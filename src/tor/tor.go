package tor

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/cretz/bine/control"
	"github.com/cretz/bine/tor"
	bined25519 "github.com/cretz/bine/torutil/ed25519"
)

// TorConfig holds Tor-related configuration from server config.
type TorConfig struct {
	// Binary path (empty = auto-detect)
	Binary string `yaml:"binary" json:"binary"`

	// Outbound network settings
	UseNetwork bool `yaml:"use_network" json:"use_network"`

	// Performance settings
	MaxCircuits      int `yaml:"max_circuits" json:"max_circuits"`
	CircuitTimeout   int `yaml:"circuit_timeout" json:"circuit_timeout"`
	BootstrapTimeout int `yaml:"bootstrap_timeout" json:"bootstrap_timeout"`

	// Security settings
	SafeLogging               bool `yaml:"safe_logging" json:"safe_logging"`
	MaxStreamsPerCircuit      int  `yaml:"max_streams_per_circuit" json:"max_streams_per_circuit"`
	CloseCircuitOnStreamLimit bool `yaml:"close_circuit_on_stream_limit" json:"close_circuit_on_stream_limit"`

	// Bandwidth settings
	BandwidthRate       string `yaml:"bandwidth_rate" json:"bandwidth_rate"`
	BandwidthBurst      string `yaml:"bandwidth_burst" json:"bandwidth_burst"`
	MaxMonthlyBandwidth string `yaml:"max_monthly_bandwidth" json:"max_monthly_bandwidth"`

	// Hidden service settings
	NumIntroPoints int `yaml:"num_intro_points" json:"num_intro_points"`
	VirtualPort    int `yaml:"virtual_port" json:"virtual_port"`
}

// DefaultTorConfig returns the default Tor configuration.
func DefaultTorConfig() TorConfig {
	return TorConfig{
		Binary:                    "",
		UseNetwork:                false,
		MaxCircuits:               32,
		CircuitTimeout:            60,
		BootstrapTimeout:          180,
		SafeLogging:               true,
		MaxStreamsPerCircuit:      100,
		CloseCircuitOnStreamLimit: true,
		BandwidthRate:             "1 MB",
		BandwidthBurst:            "2 MB",
		MaxMonthlyBandwidth:       "100 GB",
		NumIntroPoints:            3,
		VirtualPort:               80,
	}
}

// TorService manages the Tor hidden service and outbound connections.
// The server binary fully owns and controls the Tor process lifecycle.
type TorService struct {
	t          *tor.Tor
	serviceID  string
	serverPort int
	dialer     *tor.Dialer
}

// OnionAddress returns the full .onion address.
func (s *TorService) OnionAddress() string {
	return s.serviceID + ".onion"
}

// OutboundEnabled returns true if Tor outbound connections are available.
func (s *TorService) OutboundEnabled() bool {
	return s.dialer != nil
}

// GetHTTPClient returns an HTTP client, optionally routed through Tor.
func (s *TorService) GetHTTPClient(useTor bool) *http.Client {
	if !useTor || s.dialer == nil {
		return &http.Client{Timeout: 30 * time.Second}
	}
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			DialContext: s.dialer.DialContext,
		},
	}
}

// Health checks whether the Tor process is alive and, when outbound connections
// are available, verifies the SOCKS dialer is still functional.
// Returns nil when healthy, a non-nil error otherwise.
func (s *TorService) Health(ctx context.Context) error {
	if s.t == nil {
		return fmt.Errorf("tor: process not initialized")
	}
	if s.dialer == nil {
		// Hidden-service-only mode: process is up but no outbound dialer.
		return nil
	}
	// Attempt a lightweight test connection through the SOCKS proxy to verify
	// Tor circuit availability.
	conn, err := s.dialer.DialContext(ctx, "tcp", "check.torproject.org:443")
	if err != nil {
		return fmt.Errorf("tor: outbound circuit check failed: %w", err)
	}
	conn.Close()
	return nil
}

// Close shuts down the dedicated Tor process.
func (s *TorService) Close() error {
	if s.t != nil {
		return s.t.Close()
	}
	return nil
}

// FindBinary locates the Tor binary using the configured path, then PATH,
// then well-known OS-specific locations. Returns "" if not found.
func FindBinary(cfgBinary string) string {
	if cfgBinary != "" {
		if _, err := os.Stat(cfgBinary); err == nil {
			return cfgBinary
		}
	}

	// Check PATH
	if path, err := exec.LookPath("tor"); err == nil {
		return path
	}

	// Well-known locations by OS
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		candidates = []string{
			`C:\Program Files\Tor\tor.exe`,
			`C:\Program Files (x86)\Tor\tor.exe`,
		}
	case "darwin":
		candidates = []string{
			"/usr/local/bin/tor",
			"/opt/homebrew/bin/tor",
		}
	default:
		// Linux / BSD
		candidates = []string{
			"/usr/bin/tor",
			"/usr/local/bin/tor",
		}
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Start starts a dedicated Tor process owned by the server binary.
// serverPort is the server's existing HTTP port that the hidden service forwards to.
// configDir and dataDir are the server's config and data directories.
// Returns nil, nil if the Tor binary cannot be found (Tor is optional).
func Start(ctx context.Context, serverPort int, cfg *TorConfig, configDir, dataDir string) (*TorService, error) {
	binary := FindBinary(cfg.Binary)
	if binary == "" {
		log.Printf("[Tor] binary not found, hidden service disabled")
		return nil, nil
	}

	if err := ensureTorDirs(configDir, dataDir); err != nil {
		return nil, fmt.Errorf("tor: create directories: %w", err)
	}

	torrcPath := filepath.Join(configDir, "tor", "torrc")
	torDataDir := filepath.Join(dataDir, "tor")
	keyPath := filepath.Join(dataDir, "tor", "site", "hs_ed25519_secret_key")

	torrcContent := getTorConfig(cfg)
	if _, err := ensureTorrc(torrcPath, []byte(torrcContent)); err != nil {
		return nil, fmt.Errorf("tor: write torrc: %w", err)
	}

	conf := &tor.StartConf{
		TorrcFile:       torrcPath,
		DataDir:         torDataDir,
		ExePath:         binary,
		NoAutoSocksPort: true,
	}

	log.Printf("[Tor] starting hidden service...")
	t, err := tor.Start(ctx, conf)
	if err != nil {
		return nil, fmt.Errorf("tor: start process: %w", err)
	}

	bootstrapTimeout := time.Duration(cfg.BootstrapTimeout) * time.Second
	bootstrapCtx, cancel := context.WithTimeout(ctx, bootstrapTimeout)
	defer cancel()

	// Announce slow bootstrap after 30 seconds
	slowTimer := time.AfterFunc(30*time.Second, func() {
		log.Printf("[Tor] connecting...")
	})
	defer slowTimer.Stop()

	if err := t.EnableNetwork(bootstrapCtx, true); err != nil {
		t.Close()
		return nil, fmt.Errorf("tor: bootstrap failed: %w", err)
	}
	slowTimer.Stop()

	// Load or generate ED25519 key for persistent .onion address
	var keyArg control.Key
	if keyData, err := os.ReadFile(keyPath); err == nil && len(keyData) > 0 {
		kp := bined25519.PrivateKey(keyData).KeyPair()
		keyArg = &control.ED25519Key{KeyPair: kp}
	} else {
		keyArg = control.GenKey(control.KeyAlgoED25519V3)
	}

	req := &control.AddOnionRequest{
		Key: keyArg,
		Ports: []*control.KeyVal{
			control.NewKeyVal(fmt.Sprintf("%d", cfg.VirtualPort), fmt.Sprintf("127.0.0.1:%d", serverPort)),
		},
		MaxStreams: cfg.MaxStreamsPerCircuit,
	}

	resp, err := t.Control.AddOnion(req)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("tor: ADD_ONION failed: %w", err)
	}

	// Persist newly generated key for stable .onion address
	if _, isGen := keyArg.(control.GenKey); isGen && resp.Key != nil {
		if err := saveOnionKey(keyPath, resp.Key); err != nil {
			log.Printf("[Tor] warning: could not save onion key: %v", err)
		}
	}

	svc := &TorService{
		t:          t,
		serviceID:  resp.ServiceID,
		serverPort: serverPort,
	}

	// Initialize outbound dialer if outbound Tor connections are enabled
	if cfg.UseNetwork {
		dialer, err := t.Dialer(ctx, nil)
		if err != nil {
			log.Printf("[Tor] warning: failed to create outbound dialer: %v", err)
		} else {
			svc.dialer = dialer
			log.Printf("[Tor] outbound connections enabled")
		}
	}

	log.Printf("[Tor] %s.onion:%d → 127.0.0.1:%d", resp.ServiceID, cfg.VirtualPort, serverPort)
	return svc, nil
}

// ensureTorDirs creates all required Tor directories with 0700 permissions.
func ensureTorDirs(configDir, dataDir string) error {
	dirs := []string{
		filepath.Join(configDir, "tor"),
		filepath.Join(dataDir, "tor"),
		filepath.Join(dataDir, "tor", "site"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	return nil
}

// ensureTorrc writes the torrc only if it does not already exist.
// Returns true if the file was newly created.
func ensureTorrc(path string, content []byte) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		return false, err
	}
	return true, nil
}

// saveOnionKey persists the ED25519 private key for a stable .onion address.
func saveOnionKey(path string, key control.Key) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(key.Blob()), 0600)
}

// getTorConfig generates torrc content from the TorConfig.
// The hidden service itself is created via control.AddOnion(), NOT via torrc.
func getTorConfig(cfg *TorConfig) string {
	// SocksPort: enabled for outbound, disabled for hidden-service-only mode
	var socksConfig string
	if cfg.UseNetwork {
		socksConfig = "SocksPort auto"
	} else {
		socksConfig = "SocksPort 0"
	}

	// SafeLogging scrubs sensitive info from Tor logs
	safeLogging := "1"
	if !cfg.SafeLogging {
		safeLogging = "0"
	}

	// Monthly bandwidth accounting (when not "unlimited")
	var accountingConfig string
	if cfg.MaxMonthlyBandwidth != "" && cfg.MaxMonthlyBandwidth != "unlimited" {
		accountingConfig = fmt.Sprintf("\n# Monthly bandwidth limit\nAccountingStart month 1 00:00\nAccountingMax %s", cfg.MaxMonthlyBandwidth)
	}

	return fmt.Sprintf(`# ============================================================
# Tor Configuration - Generated by caswhois
# This file is persistent - manual edits are preserved.
# ============================================================

# SOCKS port (0 = disabled, auto = runtime port for outbound)
%s

# Control connection - localhost auto-port on all OSes
ControlPort 127.0.0.1:auto

# Security: scrub sensitive info from Tor logs
SafeLogging %s

# Circuit settings
MaxCircuitDirtiness 600

# Bandwidth limits (per second, from config)
BandwidthRate %s
BandwidthBurst %s
%s
# Not a relay or exit node
ExitRelay 0
ExitPolicy reject *:*
ORPort 0
DirPort 0

# Faster startup
FetchDirInfoEarly 1
FetchDirInfoExtraEarly 1

# Reduce memory usage
DisableDebuggerAttachment 1
`, socksConfig, safeLogging, cfg.BandwidthRate, cfg.BandwidthBurst, accountingConfig)
}
