package ssl

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-acme/lego/v4/lego"
)

// TestSaveLetsEncryptCert_MkdirAllFails verifies that saveLetsEncryptCert returns
// an error when the parent directory cannot be created (a file blocks the path).
func TestSaveLetsEncryptCert_MkdirAllFails(t *testing.T) {
	dir := t.TempDir()
	fqdn := "blocked.example.com"

	// Block directory creation by placing a regular file where the letsencrypt
	// directory hierarchy needs to go.
	blockPath := filepath.Join(dir, "ssl")
	if err := os.WriteFile(blockPath, []byte("I am a file, not a dir"), 0600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	cm := NewCertManager(dir, fqdn)
	err := cm.saveLetsEncryptCert([]byte("cert"), []byte("key"))
	if err == nil {
		t.Fatal("expected error when MkdirAll fails, got nil")
	}
}

// TestSaveLetsEncryptCert_WriteCertFails verifies that an error is returned when
// the certificate file cannot be written (directory is read-only after creation).
func TestSaveLetsEncryptCert_WriteCertFails(t *testing.T) {
	dir := t.TempDir()
	fqdn := "readonly.example.com"

	// Pre-create the letsencrypt directory and make it read-only so WriteFile fails.
	leDir := filepath.Join(dir, "ssl", "letsencrypt", fqdn)
	if err := os.MkdirAll(leDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(leDir, 0555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(leDir, 0755) })

	cm := NewCertManager(dir, fqdn)
	err := cm.saveLetsEncryptCert([]byte("cert"), []byte("key"))
	if err == nil {
		t.Fatal("expected error when cert WriteFile fails, got nil")
	}
}

// TestGenerateSelfSignedCertificate_MkdirAllFails verifies that
// GenerateSelfSignedCertificate returns an error when the output directory
// cannot be created.
func TestGenerateSelfSignedCertificate_MkdirAllFails(t *testing.T) {
	dir := t.TempDir()
	fqdn := "blocked-selfsigned.example.com"

	// Block directory creation: put a regular file where "ssl" would be.
	blockPath := filepath.Join(dir, "ssl")
	if err := os.WriteFile(blockPath, []byte("blocker"), 0600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	cm := NewCertManager(dir, fqdn)
	err := cm.GenerateSelfSignedCertificate()
	if err == nil {
		t.Fatal("expected error when MkdirAll fails, got nil")
	}
}

// TestGenerateSelfSignedCertificate_WriteCertFails verifies that an error is
// returned when the certificate file cannot be written.
func TestGenerateSelfSignedCertificate_WriteCertFails(t *testing.T) {
	dir := t.TempDir()
	fqdn := "readonly-selfsigned.example.com"

	// Pre-create the local cert directory and make it read-only.
	localDir := filepath.Join(dir, "ssl", "local", fqdn)
	if err := os.MkdirAll(localDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(localDir, 0555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(localDir, 0755) })

	cm := NewCertManager(dir, fqdn)
	err := cm.GenerateSelfSignedCertificate()
	if err == nil {
		t.Fatal("expected error when cert WriteFile fails, got nil")
	}
}

// TestRenewCertificate_NilClient covers the nil-acmeClient branch, which
// delegates to RequestNewCertificate. Since RequestNewCertificate makes network
// calls, we verify that the error originates from that path (non-nil error is
// expected in a test environment with no ACME server).
func TestRenewCertificate_NilClient(t *testing.T) {
	cm := NewCertManager(t.TempDir(), "renew-nil.example.com")
	// acmeClient is nil by default, so RenewCertificate should call RequestNewCertificate
	// which fails because no ACME server is reachable. Any error is acceptable.
	err := cm.RenewCertificate()
	if err == nil {
		t.Fatal("expected error when ACME server is unreachable, got nil")
	}
}

// TestRenewCertificate_WithClientMissingCertFiles covers the non-nil acmeClient
// path where getCertPEM fails because the certificate files do not exist.
func TestRenewCertificate_WithClientMissingCertFiles(t *testing.T) {
	dir := t.TempDir()
	fqdn := "renew-nocert.example.com"

	cm := NewCertManager(dir, fqdn)
	// Inject a non-nil (but invalid) acmeClient so the nil-client branch is skipped.
	// lego.NewConfig requires a user; use a minimal ACMEUser with a nil key.
	// The client will not be used to make network calls because getCertPEM will
	// fail before we reach client.Certificate.Renew.
	u := &ACMEUser{Email: "test@example.com"}
	cfg := lego.NewConfig(u)
	cfg.CADirURL = lego.LEDirectoryStaging
	client, err := lego.NewClient(cfg)
	if err != nil {
		t.Skipf("cannot create lego client in test env: %v", err)
	}
	cm.acmeClient = client

	// Certificate files are absent — getCertPEM must fail.
	err = cm.RenewCertificate()
	if err == nil {
		t.Fatal("expected error when certificate files are missing, got nil")
	}
}
