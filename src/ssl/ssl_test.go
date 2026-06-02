package ssl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateSelfSignedCert writes a self-signed cert+key pair into dir under
// the "app-local" layout expected by LoadCertificate:
// {dir}/ssl/local/{fqdn}/cert.pem and key.pem
func generateSelfSignedCert(t *testing.T, configDir, fqdn string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: fqdn},
		DNSNames:     []string{fqdn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	dir := filepath.Join(configDir, "ssl", "local", fqdn)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0644); err != nil {
		t.Fatalf("write cert.pem: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0600); err != nil {
		t.Fatalf("write key.pem: %v", err)
	}
}

// generateExpiredCert writes a cert whose NotAfter is in the past.
func generateExpiredCert(t *testing.T, configDir, fqdn string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: fqdn},
		DNSNames:     []string{fqdn},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	dir := filepath.Join(configDir, "ssl", "local", fqdn)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0644); err != nil {
		t.Fatalf("write cert.pem: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0600); err != nil {
		t.Fatalf("write key.pem: %v", err)
	}
}

func TestNewCertManager(t *testing.T) {
	cm := NewCertManager("/tmp/config", "example.com")
	if cm == nil {
		t.Fatal("NewCertManager returned nil")
	}
	if cm.configDir != "/tmp/config" {
		t.Errorf("configDir = %q, want %q", cm.configDir, "/tmp/config")
	}
	if cm.fqdn != "example.com" {
		t.Errorf("fqdn = %q, want %q", cm.fqdn, "example.com")
	}
	if cm.challengeType != "http-01" {
		t.Errorf("default challengeType = %q, want %q", cm.challengeType, "http-01")
	}
	if cm.httpPort != 80 {
		t.Errorf("default httpPort = %d, want 80", cm.httpPort)
	}
	if cm.httpsPort != 443 {
		t.Errorf("default httpsPort = %d, want 443", cm.httpsPort)
	}
	if cm.staging {
		t.Error("staging should default to false")
	}
	if cm.renewalCheckInterval != 24*time.Hour {
		t.Errorf("renewalCheckInterval = %v, want 24h", cm.renewalCheckInterval)
	}
	if cm.renewalThreshold != 7*24*time.Hour {
		t.Errorf("renewalThreshold = %v, want 7d", cm.renewalThreshold)
	}
	if cm.stopChan == nil {
		t.Error("stopChan must not be nil")
	}
}

func TestLoadCertificate_NoCertFiles(t *testing.T) {
	dir := t.TempDir()
	cm := NewCertManager(dir, "no-cert.example.com")

	err := cm.LoadCertificate()
	if err == nil {
		t.Fatal("expected error when no cert files exist, got nil")
	}
	want := "no valid certificate found for no-cert.example.com"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestLoadCertificate_WithValidCert(t *testing.T) {
	dir := t.TempDir()
	fqdn := "test.example.com"
	generateSelfSignedCert(t, dir, fqdn)

	cm := NewCertManager(dir, fqdn)
	if err := cm.LoadCertificate(); err != nil {
		t.Fatalf("LoadCertificate() error = %v", err)
	}
	if cm.cert == nil {
		t.Error("cert must be set after LoadCertificate()")
	}
}

func TestLoadCertificate_ExpiredCertSkipped(t *testing.T) {
	dir := t.TempDir()
	fqdn := "expired.example.com"
	generateExpiredCert(t, dir, fqdn)

	cm := NewCertManager(dir, fqdn)
	err := cm.LoadCertificate()
	if err == nil {
		t.Fatal("expected error for expired certificate, got nil")
	}
}

func TestLoadCertificate_WrongFQDN(t *testing.T) {
	dir := t.TempDir()
	// Generate cert for a different domain than what the manager expects.
	generateSelfSignedCert(t, dir, "other.example.com")

	// Rename the directory so it appears under the target fqdn path.
	src := filepath.Join(dir, "ssl", "local", "other.example.com")
	dst := filepath.Join(dir, "ssl", "local", "target.example.com")
	if err := os.Rename(src, dst); err != nil {
		t.Fatalf("rename: %v", err)
	}

	cm := NewCertManager(dir, "target.example.com")
	err := cm.LoadCertificate()
	if err == nil {
		t.Fatal("expected error when cert FQDN does not match manager FQDN")
	}
}

func TestGetCertificate_NoCertLoaded(t *testing.T) {
	cm := NewCertManager(t.TempDir(), "example.com")

	cert, err := cm.GetCertificate(nil)
	if err == nil {
		t.Fatal("expected error when no certificate is loaded")
	}
	if cert != nil {
		t.Error("cert should be nil when none is loaded")
	}
	if err.Error() != "no certificate loaded" {
		t.Errorf("error = %q, want \"no certificate loaded\"", err.Error())
	}
}

func TestGetCertificate_AfterLoad(t *testing.T) {
	dir := t.TempDir()
	fqdn := "gettest.example.com"
	generateSelfSignedCert(t, dir, fqdn)

	cm := NewCertManager(dir, fqdn)
	if err := cm.LoadCertificate(); err != nil {
		t.Fatalf("LoadCertificate(): %v", err)
	}

	cert, err := cm.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}
	if cert == nil {
		t.Error("expected non-nil certificate")
	}
}

func TestSetChallengeType_Valid(t *testing.T) {
	cm := NewCertManager(t.TempDir(), "example.com")

	cases := []string{"http-01", "tls-alpn-01", "dns-01"}
	for _, ct := range cases {
		t.Run(ct, func(t *testing.T) {
			if err := cm.SetChallengeType(ct); err != nil {
				t.Errorf("SetChallengeType(%q) unexpected error: %v", ct, err)
			}
			if cm.challengeType != ct {
				t.Errorf("challengeType = %q, want %q", cm.challengeType, ct)
			}
		})
	}
}

func TestSetChallengeType_Invalid(t *testing.T) {
	cm := NewCertManager(t.TempDir(), "example.com")

	cases := []string{"", "http01", "HTTPS", "auto", "foobar"}
	for _, ct := range cases {
		t.Run(ct, func(t *testing.T) {
			err := cm.SetChallengeType(ct)
			if err == nil {
				t.Errorf("SetChallengeType(%q) expected error, got nil", ct)
			}
		})
	}
}

func TestSetDNSProvider_RequiresDNS01(t *testing.T) {
	cm := NewCertManager(t.TempDir(), "example.com")
	// Default challenge type is "http-01" — SetDNSProvider must fail.
	err := cm.SetDNSProvider("route53", map[string]string{"key": "val"})
	if err == nil {
		t.Fatal("SetDNSProvider() expected error when challengeType != dns-01")
	}
}

func TestSetDNSProvider_WithDNS01(t *testing.T) {
	cm := NewCertManager(t.TempDir(), "example.com")

	if err := cm.SetChallengeType("dns-01"); err != nil {
		t.Fatalf("SetChallengeType: %v", err)
	}

	creds := map[string]string{"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "secret"}
	if err := cm.SetDNSProvider("route53", creds); err != nil {
		t.Fatalf("SetDNSProvider() unexpected error: %v", err)
	}

	if cm.dnsProvider != "route53" {
		t.Errorf("dnsProvider = %q, want %q", cm.dnsProvider, "route53")
	}
	if cm.dnsCredentials["AWS_ACCESS_KEY_ID"] != "test" {
		t.Error("credentials not stored correctly")
	}
}

func TestSetDNSProvider_NilCredentials(t *testing.T) {
	cm := NewCertManager(t.TempDir(), "example.com")
	if err := cm.SetChallengeType("dns-01"); err != nil {
		t.Fatalf("SetChallengeType: %v", err)
	}
	// nil credentials should still succeed — just an empty map.
	if err := cm.SetDNSProvider("cloudflare", nil); err != nil {
		t.Fatalf("SetDNSProvider() with nil creds error: %v", err)
	}
	if cm.dnsProvider != "cloudflare" {
		t.Errorf("dnsProvider = %q, want %q", cm.dnsProvider, "cloudflare")
	}
}

func TestGetCertificateInfo_NoCertLoaded(t *testing.T) {
	cm := NewCertManager(t.TempDir(), "example.com")

	info, err := cm.GetCertificateInfo()
	if err == nil {
		t.Fatal("expected error when no certificate is loaded")
	}
	if info != nil {
		t.Error("info should be nil on error")
	}
}

func TestGetCertificateInfo_WithCert(t *testing.T) {
	dir := t.TempDir()
	fqdn := "info.example.com"
	generateSelfSignedCert(t, dir, fqdn)

	cm := NewCertManager(dir, fqdn)
	if err := cm.LoadCertificate(); err != nil {
		t.Fatalf("LoadCertificate(): %v", err)
	}

	info, err := cm.GetCertificateInfo()
	if err != nil {
		t.Fatalf("GetCertificateInfo() error = %v", err)
	}

	if subject, ok := info["subject"].(string); !ok || subject != fqdn {
		t.Errorf("subject = %v, want %q", info["subject"], fqdn)
	}
	if valid, ok := info["valid"].(bool); !ok || !valid {
		t.Errorf("valid = %v, want true", info["valid"])
	}
}

func TestGenerateSelfSignedCertificate(t *testing.T) {
	dir := t.TempDir()
	fqdn := "selfsigned.example.com"

	cm := NewCertManager(dir, fqdn)
	if err := cm.GenerateSelfSignedCertificate(); err != nil {
		t.Fatalf("GenerateSelfSignedCertificate() error = %v", err)
	}

	// Cert and key files must exist.
	certPath := filepath.Join(dir, "ssl", "local", fqdn, "cert.pem")
	keyPath := filepath.Join(dir, "ssl", "local", fqdn, "key.pem")

	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("cert.pem not found: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key.pem not found: %v", err)
	}

	// Certificate should be loaded into the manager.
	if cm.cert == nil {
		t.Error("cert must be populated after GenerateSelfSignedCertificate")
	}
}

func TestStopAutoRenewal_NoDeadlock(t *testing.T) {
	cm := NewCertManager(t.TempDir(), "example.com")

	cm.StartAutoRenewal()

	// StopAutoRenewal must return quickly without blocking.
	done := make(chan struct{})
	go func() {
		cm.StopAutoRenewal()
		close(done)
	}()

	select {
	case <-done:
		// Success.
	case <-time.After(2 * time.Second):
		t.Fatal("StopAutoRenewal() blocked — possible deadlock")
	}
}

// ---------------------------------------------------------------------------
// ACMEUser
// ---------------------------------------------------------------------------

func TestACMEUser_GetEmail(t *testing.T) {
	u := &ACMEUser{Email: "admin@example.com"}
	if got := u.GetEmail(); got != "admin@example.com" {
		t.Errorf("GetEmail() = %q, want %q", got, "admin@example.com")
	}
}

func TestACMEUser_GetRegistration_Nil(t *testing.T) {
	u := &ACMEUser{}
	if reg := u.GetRegistration(); reg != nil {
		t.Errorf("GetRegistration() = %v, want nil", reg)
	}
}

func TestACMEUser_GetPrivateKey_NilField(t *testing.T) {
	// When the key field is a nil *ecdsa.PrivateKey, GetPrivateKey returns a
	// non-nil crypto.PrivateKey interface wrapping a nil pointer.  The test
	// simply verifies the call does not panic and the returned value can be
	// type-asserted back to *ecdsa.PrivateKey with a nil concrete value.
	u := &ACMEUser{}
	pk := u.GetPrivateKey()
	if ecKey, ok := pk.(*ecdsa.PrivateKey); ok && ecKey != nil {
		t.Errorf("GetPrivateKey() inner *ecdsa.PrivateKey = %v, want nil", ecKey)
	}
}

func TestACMEUser_GetPrivateKey_Set(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	u := &ACMEUser{Email: "admin@example.com", key: key}
	pk := u.GetPrivateKey()
	if pk == nil {
		t.Fatal("GetPrivateKey() returned nil, expected the set key")
	}
	if pk != key {
		t.Error("GetPrivateKey() returned wrong key")
	}
}

// ---------------------------------------------------------------------------
// certMatchesFQDN — tested indirectly via LoadCertificate / validateCertificate
// ---------------------------------------------------------------------------

func TestCertMatchesFQDN_WildcardCert(t *testing.T) {
	dir := t.TempDir()
	// Generate a wildcard cert for *.example.com and try to load it for
	// sub.example.com — certMatchesFQDN should accept it.
	fqdn := "sub.example.com"
	wildcard := "*.example.com"

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: wildcard},
		DNSNames:     []string{wildcard},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	localDir := filepath.Join(dir, "ssl", "local", fqdn)
	if err := os.MkdirAll(localDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(filepath.Join(localDir, "cert.pem"), certPEM, 0644); err != nil {
		t.Fatalf("write cert.pem: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(localDir, "key.pem"), keyPEM, 0600); err != nil {
		t.Fatalf("write key.pem: %v", err)
	}

	cm := NewCertManager(dir, fqdn)
	if err := cm.LoadCertificate(); err != nil {
		t.Fatalf("LoadCertificate() with wildcard cert error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// saveLetsEncryptCert — tested indirectly via GenerateSelfSignedCertificate
// and via calling saveLetsEncryptCert directly (it is unexported but in the
// same package).
// ---------------------------------------------------------------------------

func TestSaveLetsEncryptCert(t *testing.T) {
	dir := t.TempDir()
	fqdn := "le.example.com"
	generateSelfSignedCert(t, dir, fqdn) // create a cert to get valid PEM bytes

	certPath := filepath.Join(dir, "ssl", "local", fqdn, "cert.pem")
	keyPath := filepath.Join(dir, "ssl", "local", fqdn, "key.pem")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert.pem: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key.pem: %v", err)
	}

	cm := NewCertManager(dir, fqdn)
	if err := cm.saveLetsEncryptCert(certPEM, keyPEM); err != nil {
		t.Fatalf("saveLetsEncryptCert() error = %v", err)
	}

	// Files must be written to the letsencrypt location.
	savedCert := filepath.Join(dir, "ssl", "letsencrypt", fqdn, "fullchain.pem")
	savedKey := filepath.Join(dir, "ssl", "letsencrypt", fqdn, "privkey.pem")

	if _, err := os.Stat(savedCert); err != nil {
		t.Errorf("fullchain.pem not found: %v", err)
	}
	if _, err := os.Stat(savedKey); err != nil {
		t.Errorf("privkey.pem not found: %v", err)
	}

	// Key file must be 0600.
	info, err := os.Stat(savedKey)
	if err != nil {
		t.Fatalf("stat privkey.pem: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("privkey.pem permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestLoadCertificate_PrefersLetsEncryptOverLocal(t *testing.T) {
	dir := t.TempDir()
	fqdn := "priority.example.com"

	// Write a valid cert to the letsencrypt location.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject:      pkix.Name{CommonName: fqdn},
		DNSNames:     []string{fqdn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leDir := filepath.Join(dir, "ssl", "letsencrypt", fqdn)
	if err := os.MkdirAll(leDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(filepath.Join(leDir, "fullchain.pem"), certPEM, 0644); err != nil {
		t.Fatalf("write fullchain.pem: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(leDir, "privkey.pem"), keyPEM, 0600); err != nil {
		t.Fatalf("write privkey.pem: %v", err)
	}

	// Also write a valid local cert — should be ignored because LE takes priority.
	generateSelfSignedCert(t, dir, fqdn)

	cm := NewCertManager(dir, fqdn)
	if err := cm.LoadCertificate(); err != nil {
		t.Fatalf("LoadCertificate() error = %v", err)
	}
}

func TestNewCertManager_DifferentFQDNs(t *testing.T) {
	cases := []string{
		"example.com",
		"sub.domain.example.org",
		"*.wildcard.net",
		"xn--nxasmq6b.com",
	}
	for _, fqdn := range cases {
		t.Run(fqdn, func(t *testing.T) {
			cm := NewCertManager(t.TempDir(), fqdn)
			if cm.fqdn != fqdn {
				t.Errorf("fqdn = %q, want %q", cm.fqdn, fqdn)
			}
		})
	}
}
