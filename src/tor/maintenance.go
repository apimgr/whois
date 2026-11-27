package tor

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/sha3"
)

const (
	secretKeyName = "hs_ed25519_secret_key"
	publicKeyName = "hs_ed25519_public_key"
	hostnameName  = "hostname"
)

type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type VanityStatus struct {
	State          string   `json:"state"`
	Prefix         string   `json:"prefix,omitempty"`
	Workers        int      `json:"workers,omitempty"`
	Attempts       uint64   `json:"attempts,omitempty"`
	Rate           float64  `json:"rate,omitempty"`
	ElapsedSeconds int64    `json:"elapsed_seconds,omitempty"`
	Candidates     []string `json:"candidates"`
}

type vanitySearch struct {
	cancel     contextCancel
	prefix     string
	workers    int
	started    time.Time
	attempts   atomic.Uint64
	mu         sync.Mutex
	candidates map[string]bool
	wg         sync.WaitGroup
}

type contextCancel func()

// Maintenance owns the local vanity search and candidate key files.
type Maintenance struct {
	DataDir string
	mu      sync.Mutex
	search  *vanitySearch
}

func (m *Maintenance) VanityStatus() VanityStatus {
	m.mu.Lock()
	search := m.search
	m.mu.Unlock()
	candidates := m.Candidates()
	if search == nil {
		if len(candidates) > 0 {
			return VanityStatus{State: "found", Candidates: candidates}
		}
		return VanityStatus{State: "idle", Candidates: []string{}}
	}
	search.mu.Lock()
	found := make([]string, 0, len(search.candidates))
	for address := range search.candidates {
		found = append(found, address)
	}
	search.mu.Unlock()
	elapsed := time.Since(search.started)
	var rate float64
	if elapsed > 0 {
		rate = float64(search.attempts.Load()) / elapsed.Seconds()
	}
	state := "running"
	if len(found) > 0 {
		state = "found"
	}
	return VanityStatus{State: state, Prefix: search.prefix, Workers: search.workers, Attempts: search.attempts.Load(), Rate: rate, ElapsedSeconds: int64(elapsed.Seconds()), Candidates: found}
}

func (m *Maintenance) Candidates() []string {
	root := filepath.Join(m.DataDir, "tor", "vanity")
	entries, err := os.ReadDir(root)
	if err != nil {
		return []string{}
	}
	addresses := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() && validOnion(entry.Name()) {
			if _, err := loadCandidate(filepath.Join(root, entry.Name())); err == nil {
				addresses = append(addresses, entry.Name())
			}
		}
	}
	sort.Strings(addresses)
	return addresses
}

// SelectCandidate accepts a unique address prefix, or an omitted address when only one exists.
func (m *Maintenance) SelectCandidate(prefix string) (string, error) {
	candidates := m.Candidates()
	if len(candidates) == 0 {
		return "", fmt.Errorf("no vanity candidates are available")
	}
	if prefix == "" {
		if len(candidates) == 1 {
			return filepath.Join(m.DataDir, "tor", "vanity", candidates[0]), nil
		}
		return "", fmt.Errorf("multiple vanity candidates are available: %s", strings.Join(candidates, ", "))
	}
	matches := make([]string, 0, 1)
	for _, address := range candidates {
		if strings.HasPrefix(address, prefix) {
			matches = append(matches, address)
		}
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no vanity candidate matches %q", prefix)
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("ambiguous vanity candidate prefix %q: %s", prefix, strings.Join(matches, ", "))
	}
	return filepath.Join(m.DataDir, "tor", "vanity", matches[0]), nil
}

func (m *Maintenance) StartVanity(prefix string, workers int) error {
	if len(prefix) < 1 || len(prefix) > 6 {
		return fmt.Errorf("prefix must contain 1 to 6 base32 characters")
	}
	for _, r := range prefix {
		if (r < 'a' || r > 'z') && (r < '2' || r > '7') {
			return fmt.Errorf("prefix must use lowercase base32 characters a-z and 2-7")
		}
	}
	maxWorkers := runtime.NumCPU()
	if workers == 0 {
		workers = maxWorkers - 1
		if workers < 1 {
			workers = 1
		}
	}
	if workers < 1 || workers > maxWorkers {
		return fmt.Errorf("workers must be between 1 and %d", maxWorkers)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.search != nil {
		return fmt.Errorf("vanity search already running for prefix %s", m.search.prefix)
	}
	ctx, cancel := newCancelContext()
	search := &vanitySearch{cancel: cancel, prefix: prefix, workers: workers, started: time.Now(), candidates: map[string]bool{}}
	m.search = search
	for i := 0; i < workers; i++ {
		search.wg.Add(1)
		go func() { defer search.wg.Done(); m.vanityWorker(ctx, search) }()
	}
	return nil
}

func newCancelContext() (<-chan struct{}, contextCancel) {
	done := make(chan struct{})
	var once sync.Once
	return done, func() { once.Do(func() { close(done) }) }
}

func (m *Maintenance) vanityWorker(done <-chan struct{}, search *vanitySearch) {
	for {
		select {
		case <-done:
			return
		default:
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return
		}
		search.attempts.Add(1)
		address := onionAddress(public)
		if !strings.HasPrefix(strings.TrimSuffix(address, ".onion"), search.prefix) {
			continue
		}
		if err := writeCandidate(filepath.Join(m.DataDir, "tor", "vanity"), address, private, public); err != nil {
			continue
		}
		search.mu.Lock()
		search.candidates[address] = true
		search.mu.Unlock()
	}
}

func (m *Maintenance) StopVanity() (bool, []string) {
	m.mu.Lock()
	search := m.search
	m.mu.Unlock()
	if search == nil {
		return false, m.Candidates()
	}
	search.cancel()
	search.wg.Wait()
	m.mu.Lock()
	if m.search == search {
		m.search = nil
	}
	m.mu.Unlock()
	return true, m.Candidates()
}

func writeCandidate(root, address string, private ed25519.PrivateKey, public ed25519.PublicKey) error {
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	_ = os.Chmod(root, 0700)
	tmp, err := os.MkdirTemp(root, ".candidate-")
	if err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0700)
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tmp)
		}
	}()
	if err := writeTorKey(filepath.Join(tmp, secretKeyName), "== ed25519v1-secret: type0 ==\x00", private); err != nil {
		return err
	}
	if err := writeTorKey(filepath.Join(tmp, publicKeyName), "== ed25519v1-public: type0 ==\x00", public); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmp, hostnameName), []byte(address+"\n"), 0600); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(tmp, hostnameName), 0600); err != nil {
		return err
	}
	dest := filepath.Join(root, address)
	if err := os.Rename(tmp, dest); err != nil {
		if _, statErr := os.Stat(dest); statErr == nil {
			return nil
		}
		return err
	}
	cleanup = false
	return nil
}

func writeTorKey(path, header string, key []byte) error {
	if err := os.WriteFile(path, append([]byte(header), key...), 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

func onionAddress(public ed25519.PublicKey) string {
	//nolint:govet // Preserve the audited SHA3 implementation from x/crypto.
	checksumHash := sha3.New256()
	_, _ = checksumHash.Write([]byte(".onion checksum"))
	_, _ = checksumHash.Write(public)
	_, _ = checksumHash.Write([]byte{0x03})
	checksum := checksumHash.Sum(nil)
	addressBytes := append(append(append([]byte{}, public...), checksum[:2]...), 0x03)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(addressBytes)) + ".onion"
}

func loadCandidate(dir string) (string, error) {
	secret, err := readTorKey(filepath.Join(dir, secretKeyName), "== ed25519v1-secret: type0 ==\x00", ed25519.PrivateKeySize)
	if err != nil {
		return "", err
	}
	public, err := readTorKey(filepath.Join(dir, publicKeyName), "== ed25519v1-public: type0 ==\x00", ed25519.PublicKeySize)
	if err != nil {
		return "", err
	}
	derived := ed25519.PrivateKey(secret).Public().(ed25519.PublicKey)
	if !equalBytes(derived, public) {
		return "", fmt.Errorf("public key does not match secret key")
	}
	address := onionAddress(public)
	file, err := os.ReadFile(filepath.Join(dir, hostnameName))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(file)) != address {
		return "", fmt.Errorf("hostname does not match keys")
	}
	return address, nil
}

func readTorKey(path, header string, length int) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	prefix := []byte(header)
	if len(data) != len(prefix)+length || string(data[:len(prefix)]) != header {
		return nil, fmt.Errorf("malformed Tor key file %s", path)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return data[len(prefix):], nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func ValidateKeyDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute")
	}
	return loadCandidate(path)
}

// SwapKeyDirectory atomically replaces the live key directory while Tor is stopped.
func SwapKeyDirectory(source, siteDir string) error {
	_, commit, err := SwapKeyDirectoryTransactional(source, siteDir)
	if err != nil {
		return err
	}
	return commit()
}

// SwapKeyDirectoryTransactional installs a validated key set and returns
// rollback and commit callbacks so callers can verify Tor's published hostname.
func SwapKeyDirectoryTransactional(source, siteDir string) (rollback func() error, commit func() error, err error) {
	address, err := loadCandidate(source)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(siteDir), 0700); err != nil {
		return nil, nil, err
	}
	stage, err := os.MkdirTemp(filepath.Dir(siteDir), ".tor-site-")
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	_ = os.Chmod(stage, 0700)
	for _, name := range []string{secretKeyName, publicKeyName, hostnameName} {
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(filepath.Join(stage, name), data, 0600); err != nil {
			return nil, nil, err
		}
		if err := os.Chmod(filepath.Join(stage, name), 0600); err != nil {
			return nil, nil, err
		}
	}
	if err := os.Chmod(stage, 0700); err != nil {
		return nil, nil, err
	}
	_ = address
	backup := siteDir + ".previous"
	if err := os.RemoveAll(backup); err != nil {
		return nil, nil, err
	}
	hadSite := false
	if _, err := os.Stat(siteDir); err == nil {
		if err := os.Rename(siteDir, backup); err != nil {
			return nil, nil, err
		}
		hadSite = true
	}
	if err := os.Rename(stage, siteDir); err != nil {
		if hadSite {
			_ = os.Rename(backup, siteDir)
		}
		return nil, nil, err
	}
	rollback = func() error {
		if err := os.RemoveAll(siteDir); err != nil {
			return err
		}
		if hadSite {
			return os.Rename(backup, siteDir)
		}
		return nil
	}
	commit = func() error {
		if hadSite {
			return os.RemoveAll(backup)
		}
		return nil
	}
	return rollback, commit, nil
}

func ValidateConfig(cfg TorConfig) []FieldError {
	var failures []FieldError
	checkRange := func(field string, value, min, max int) {
		if value < min || value > max {
			failures = append(failures, FieldError{Field: field, Message: fmt.Sprintf("must be between %d and %d", min, max)})
		}
	}
	checkRange("max_circuits", cfg.MaxCircuits, 1, 128)
	checkRange("startup_timeout", cfg.StartupTimeout, 10, 300)
	checkRange("circuit_timeout", cfg.CircuitTimeout, 10, 300)
	checkRange("bootstrap_timeout", cfg.BootstrapTimeout, 30, 600)
	checkRange("max_streams_per_circuit", cfg.MaxStreamsPerCircuit, 10, 500)
	checkRange("num_intro_points", cfg.NumIntroPoints, 3, 10)
	checkRange("virtual_port", cfg.VirtualPort, 1, 65535)
	bandwidthPattern := regexp.MustCompile(`^[0-9]+ (B|KB|MB|GB)$`)
	for field, value := range map[string]string{"bandwidth_rate": cfg.BandwidthRate, "bandwidth_burst": cfg.BandwidthBurst} {
		if !bandwidthPattern.MatchString(value) {
			failures = append(failures, FieldError{Field: field, Message: "must be a Tor bandwidth value such as 1 MB"})
		}
	}
	if cfg.MaxMonthlyBandwidth != "" && cfg.MaxMonthlyBandwidth != "unlimited" && !bandwidthPattern.MatchString(cfg.MaxMonthlyBandwidth) {
		failures = append(failures, FieldError{Field: "max_monthly_bandwidth", Message: "must be a Tor bandwidth value such as 100 GB or unlimited"})
	}
	return failures
}

func CircuitIDFromIPv6(ip []byte) (uint32, bool) {
	if len(ip) != netIPv6Len {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip[12:16]), true
}

const netIPv6Len = 16
