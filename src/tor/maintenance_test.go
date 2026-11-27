package tor

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaintenanceVanityLifecycle(t *testing.T) {
	maintenance := &Maintenance{DataDir: t.TempDir()}
	if err := maintenance.StartVanity("A", 1); err == nil {
		t.Fatal("uppercase prefix should be rejected")
	}
	// Use the longest accepted prefix so this lifecycle test cannot race with
	// successful candidate generation and persistence.
	prefix := "aaaaaa"
	if err := maintenance.StartVanity(prefix, 0); err != nil {
		t.Fatalf("start vanity search: %v", err)
	}
	if err := maintenance.StartVanity("b", 1); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second search error = %v, want already running", err)
	}
	status := maintenance.VanityStatus()
	if (status.State != "running" && status.State != "found") || status.Prefix != prefix || status.Workers < 1 || status.Candidates == nil {
		t.Fatalf("running status = %+v", status)
	}
	stopped, _ := maintenance.StopVanity()
	if !stopped {
		t.Fatal("StopVanity reported no active search")
	}
	stopped, candidates := maintenance.StopVanity()
	if stopped || candidates == nil {
		t.Fatalf("second StopVanity = (%v, %v), want false and candidate list", stopped, candidates)
	}
	if status := maintenance.VanityStatus(); status.State != "idle" {
		t.Fatalf("idle status = %+v", status)
	}
}

func TestVanityCandidateValidationAndSelection(t *testing.T) {
	root := t.TempDir()
	maintenance := &Maintenance{DataDir: root}
	address, err := makeCandidate(t, filepath.Join(root, "tor", "vanity"))
	if err != nil {
		t.Fatal(err)
	}
	if got := maintenance.Candidates(); len(got) != 1 || got[0] != address {
		t.Fatalf("Candidates() = %v, want [%s]", got, address)
	}
	selected, err := maintenance.SelectCandidate(address[:8])
	if err != nil || selected != filepath.Join(root, "tor", "vanity", address) {
		t.Fatalf("SelectCandidate(prefix) = %q, %v", selected, err)
	}
	selected, err = maintenance.SelectCandidate("")
	if err != nil || selected != filepath.Join(root, "tor", "vanity", address) {
		t.Fatalf("SelectCandidate(empty) = %q, %v", selected, err)
	}
	if _, err := ValidateKeyDirectory(selected); err != nil {
		t.Fatalf("ValidateKeyDirectory: %v", err)
	}
	secretInfo, err := os.Stat(filepath.Join(selected, secretKeyName))
	if err != nil {
		t.Fatal(err)
	}
	if secretInfo.Mode().Perm() != 0600 {
		t.Errorf("secret key mode = %04o, want 0600", secretInfo.Mode().Perm())
	}
	if _, err := ValidateKeyDirectory(filepath.Join(root, "relative")); err == nil {
		t.Fatal("relative key path should be rejected")
	}
	if _, err := maintenance.SelectCandidate("not-a-candidate"); err == nil {
		t.Fatal("unknown candidate prefix should be rejected")
	}
}

func TestSwapKeyDirectoryRollbackAndCommit(t *testing.T) {
	root := t.TempDir()
	vanityRoot := filepath.Join(root, "vanity")
	source, err := makeCandidate(t, vanityRoot)
	if err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(vanityRoot, source)
	siteDir := filepath.Join(root, "site")
	if err := os.MkdirAll(siteDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(siteDir, "old-key"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	rollback, _, err := SwapKeyDirectoryTransactional(sourceDir, siteDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(siteDir, secretKeyName)); err != nil {
		t.Fatalf("installed key missing: %v", err)
	}
	if err := rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(siteDir, "old-key")); err != nil || string(data) != "old" {
		t.Fatalf("old site was not restored: data=%q err=%v", data, err)
	}
	_, commit, err := SwapKeyDirectoryTransactional(sourceDir, siteDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func TestValidateTorConfigAndCandidateFiles(t *testing.T) {
	cfg := DefaultTorConfig()
	cfg.MaxCircuits = 0
	cfg.StartupTimeout = 1
	cfg.BandwidthRate = "invalid"
	if failures := ValidateConfig(cfg); len(failures) < 3 {
		t.Fatalf("ValidateConfig failures = %+v, want range and bandwidth errors", failures)
	}
	root := t.TempDir()
	if _, err := makeCandidate(t, root); err != nil {
		t.Fatal(err)
	}
	badDir := filepath.Join(root, "bad")
	if err := os.Mkdir(badDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCandidate(badDir); err == nil {
		t.Fatal("candidate missing keys should be rejected")
	}
	if err := writeTorKey(filepath.Join(badDir, secretKeyName), "header", make([]byte, ed25519.PrivateKeySize)); err != nil {
		t.Fatal(err)
	}
	if _, err := readTorKey(filepath.Join(badDir, secretKeyName), "expected", ed25519.PrivateKeySize); err == nil {
		t.Fatal("unexpected key header should be rejected")
	}
}

func makeCandidate(t *testing.T, root string) (string, error) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	address := onionAddress(public)
	if err := writeCandidate(root, address, private, public); err != nil {
		return "", err
	}
	return address, nil
}
