// Package ssl provides SSL/TLS certificate management with built-in Let's Encrypt support
// Implements AI.md PART 15: SSL/TLS & LET'S ENCRYPT
package ssl

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"golang.org/x/crypto/argon2"
)

// CertManager handles SSL/TLS certificate management
type CertManager struct {
	configDir string
	fqdn      string
	email     string // Required for ACME registration
	cert      *tls.Certificate
	certMu    sync.RWMutex
	
	// Let's Encrypt configuration
	challengeType string // "http-01", "tls-alpn-01", "dns-01"
	dnsProvider   string // Only for DNS-01
	dnsCredentials map[string]string // Encrypted credentials for DNS provider
	
	// ACME client
	acmeClient *lego.Client
	
	// Auto-renewal
	renewalCheckInterval time.Duration
	renewalThreshold     time.Duration // Renew 7 days before expiry
	stopChan             chan struct{}
}

// ACMEUser implements the ACME registration.User interface
type ACMEUser struct {
	Email        string
	Registration *registration.Resource
	key          *ecdsa.PrivateKey
}

func (u *ACMEUser) GetEmail() string {
	return u.Email
}

func (u *ACMEUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *ACMEUser) GetPrivateKey() interface{} {
	return u.key
}

// CertificatePaths holds paths to certificate files
type CertificatePaths struct {
	CertPath string
	KeyPath  string
	Source   string // "system", "app-letsencrypt", "app-local"
}

// NewCertManager creates a new SSL certificate manager
func NewCertManager(configDir, fqdn string) *CertManager {
	return &CertManager{
		configDir:            configDir,
		fqdn:                 fqdn,
		challengeType:        "http-01", // Default challenge type
		renewalCheckInterval: 24 * time.Hour,
		renewalThreshold:     7 * 24 * time.Hour, // 7 days
		stopChan:             make(chan struct{}),
	}
}

// LoadCertificate attempts to load an existing certificate following PART 15 lookup order
// Priority:
//   1. /etc/letsencrypt/live/domain/ (literal "domain" directory)
//   2. /etc/letsencrypt/live/{fqdn}/
//   3. {config_dir}/ssl/letsencrypt/{fqdn}/
//   4. {config_dir}/ssl/local/{fqdn}/
func (cm *CertManager) LoadCertificate() error {
	cm.certMu.Lock()
	defer cm.certMu.Unlock()

	// Try each location in priority order
	locations := []CertificatePaths{
		{
			CertPath: "/etc/letsencrypt/live/domain/fullchain.pem",
			KeyPath:  "/etc/letsencrypt/live/domain/privkey.pem",
			Source:   "system",
		},
		{
			CertPath: filepath.Join("/etc/letsencrypt/live", cm.fqdn, "fullchain.pem"),
			KeyPath:  filepath.Join("/etc/letsencrypt/live", cm.fqdn, "privkey.pem"),
			Source:   "system",
		},
		{
			CertPath: filepath.Join(cm.configDir, "ssl", "letsencrypt", cm.fqdn, "fullchain.pem"),
			KeyPath:  filepath.Join(cm.configDir, "ssl", "letsencrypt", cm.fqdn, "privkey.pem"),
			Source:   "app-letsencrypt",
		},
		{
			CertPath: filepath.Join(cm.configDir, "ssl", "local", cm.fqdn, "cert.pem"),
			KeyPath:  filepath.Join(cm.configDir, "ssl", "local", cm.fqdn, "key.pem"),
			Source:   "app-local",
		},
	}

	for _, loc := range locations {
		cert, err := cm.loadCertFromPath(loc)
		if err == nil {
			cm.cert = cert
			return nil
		}
	}

	return fmt.Errorf("no valid certificate found for %s", cm.fqdn)
}

// loadCertFromPath loads and validates a certificate from the given paths
func (cm *CertManager) loadCertFromPath(paths CertificatePaths) (*tls.Certificate, error) {
	// Check if files exist
	if _, err := os.Stat(paths.CertPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("cert file not found: %s", paths.CertPath)
	}
	if _, err := os.Stat(paths.KeyPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("key file not found: %s", paths.KeyPath)
	}

	// Load certificate
	cert, err := tls.LoadX509KeyPair(paths.CertPath, paths.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	// Validate certificate
	if err := cm.validateCertificate(&cert); err != nil {
		return nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	return &cert, nil
}

// validateCertificate validates that the certificate matches the FQDN and is not expired
func (cm *CertManager) validateCertificate(cert *tls.Certificate) error {
	if cert == nil || len(cert.Certificate) == 0 {
		return fmt.Errorf("empty certificate")
	}

	// Parse certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check expiry
	now := time.Now()
	if now.Before(x509Cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid (valid from %s)", x509Cert.NotBefore)
	}
	if now.After(x509Cert.NotAfter) {
		return fmt.Errorf("certificate expired on %s", x509Cert.NotAfter)
	}

	// Check CN or SAN matches FQDN
	if !cm.certMatchesFQDN(x509Cert) {
		return fmt.Errorf("certificate does not match FQDN %s", cm.fqdn)
	}

	return nil
}

// certMatchesFQDN checks if the certificate matches the configured FQDN
func (cm *CertManager) certMatchesFQDN(cert *x509.Certificate) bool {
	// Check Common Name
	if strings.EqualFold(cert.Subject.CommonName, cm.fqdn) {
		return true
	}

	// Check Subject Alternative Names
	for _, san := range cert.DNSNames {
		if strings.EqualFold(san, cm.fqdn) {
			return true
		}
		// Check wildcard match
		if strings.HasPrefix(san, "*.") {
			wildcard := san[2:]
			if strings.HasSuffix(cm.fqdn, wildcard) {
				return true
			}
		}
	}

	return false
}

// GetCertificate returns the current certificate for use with tls.Config
func (cm *CertManager) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.certMu.RLock()
	defer cm.certMu.RUnlock()

	if cm.cert == nil {
		return nil, fmt.Errorf("no certificate loaded")
	}

	return cm.cert, nil
}

// StartAutoRenewal starts the automatic renewal process for app-managed certificates
// Only renews certificates in {config_dir}/ssl/letsencrypt/{fqdn}/
// Does NOT renew system certificates (/etc/letsencrypt/) or local certificates
func (cm *CertManager) StartAutoRenewal() {
	go cm.renewalLoop()
}

// StopAutoRenewal stops the automatic renewal process
func (cm *CertManager) StopAutoRenewal() {
	close(cm.stopChan)
}

// renewalLoop runs the certificate renewal check loop
func (cm *CertManager) renewalLoop() {
	ticker := time.NewTicker(cm.renewalCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cm.checkAndRenew()
		case <-cm.stopChan:
			return
		}
	}
}

// checkAndRenew checks if certificate needs renewal and renews if necessary
func (cm *CertManager) checkAndRenew() {
	cm.certMu.RLock()
	cert := cm.cert
	cm.certMu.RUnlock()

	if cert == nil {
		return
	}

	// Only auto-renew app-managed Let's Encrypt certificates
	appCertPath := filepath.Join(cm.configDir, "ssl", "letsencrypt", cm.fqdn, "fullchain.pem")
	if _, err := os.Stat(appCertPath); os.IsNotExist(err) {
		// Not an app-managed certificate, skip renewal
		return
	}

	// Parse certificate to check expiry
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}

	// Check if renewal is needed (7 days before expiry)
	timeUntilExpiry := time.Until(x509Cert.NotAfter)
	if timeUntilExpiry <= cm.renewalThreshold {
		if err := cm.RenewCertificate(); err != nil {
			// TODO: Log error (don't panic in background goroutine)
			return
		}
	}
}

// RenewCertificate requests a new certificate from Let's Encrypt
func (cm *CertManager) RenewCertificate() error {
	// TODO: Implement Let's Encrypt renewal using lego library
	// This is a stub for now - full implementation requires:
	// 1. Determine challenge type (HTTP-01, TLS-ALPN-01, DNS-01)
	// 2. Use go-acme/lego library to handle ACME protocol
	// 3. Complete challenge (HTTP, TLS, or DNS based on configuration)
	// 4. Save new certificate to {config_dir}/ssl/letsencrypt/{fqdn}/
	// 5. Reload certificate atomically (update cm.cert)
	return fmt.Errorf("certificate renewal not yet implemented")
}

// RequestNewCertificate requests a new certificate from Let's Encrypt
// This is called when no existing certificate is found
func (cm *CertManager) RequestNewCertificate() error {
	// TODO: Implement Let's Encrypt certificate request using lego library
	// Same implementation as RenewCertificate but for initial request
	return fmt.Errorf("certificate request not yet implemented")
}

// SetChallengeType sets the Let's Encrypt challenge type
func (cm *CertManager) SetChallengeType(challengeType string) error {
	validTypes := map[string]bool{
		"http-01":     true,
		"tls-alpn-01": true,
		"dns-01":      true,
	}

	if !validTypes[challengeType] {
		return fmt.Errorf("invalid challenge type: %s", challengeType)
	}

	cm.challengeType = challengeType
	return nil
}

// SetDNSProvider sets the DNS provider for DNS-01 challenge
func (cm *CertManager) SetDNSProvider(provider string, credentials map[string]string) error {
	if cm.challengeType != "dns-01" {
		return fmt.Errorf("DNS provider can only be set when using dns-01 challenge")
	}

	// TODO: Validate provider and credentials
	// TODO: Encrypt credentials before storing
	cm.dnsProvider = provider
	cm.dnsCredentials = credentials

	return nil
}

// GetCertificateInfo returns information about the current certificate
func (cm *CertManager) GetCertificateInfo() (map[string]interface{}, error) {
	cm.certMu.RLock()
	defer cm.certMu.RUnlock()

	if cm.cert == nil {
		return nil, fmt.Errorf("no certificate loaded")
	}

	x509Cert, err := x509.ParseCertificate(cm.cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	info := map[string]interface{}{
		"subject":     x509Cert.Subject.CommonName,
		"issuer":      x509Cert.Issuer.CommonName,
		"not_before":  x509Cert.NotBefore,
		"not_after":   x509Cert.NotAfter,
		"dns_names":   x509Cert.DNSNames,
		"is_ca":       x509Cert.IsCA,
		"valid":       time.Now().Before(x509Cert.NotAfter) && time.Now().After(x509Cert.NotBefore),
	}

	return info, nil
}

// GenerateSelfSignedCertificate generates a self-signed certificate for development
// Saves to {config_dir}/ssl/local/{fqdn}/
func (cm *CertManager) GenerateSelfSignedCertificate() error {
	// TODO: Implement self-signed certificate generation
	// Used for development, Tor .onion, I2P .i2p addresses
	// Let's Encrypt doesn't support these, so self-signed is required
	return fmt.Errorf("self-signed certificate generation not yet implemented")
}

// getCertPEM reads the certificate PEM data
func getCertPEM(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Validate PEM format
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", path)
	}

	return data, nil
}

// getKeyPEM reads the private key PEM data
func getKeyPEM(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Validate PEM format
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", path)
	}

	return data, nil
}
