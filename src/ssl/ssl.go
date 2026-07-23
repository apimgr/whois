// Package ssl provides SSL/TLS certificate management with built-in Let's Encrypt support
// Implements AI.md PART 15: SSL/TLS & LET'S ENCRYPT
package ssl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	legodns "github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
)

// CertManager handles SSL/TLS certificate management.
type CertManager struct {
	configDir string
	fqdn      string
	// email is required by ACME providers for account registration.
	email  string
	cert   *tls.Certificate
	certMu sync.RWMutex

	// Let's Encrypt configuration.
	// challengeType is one of "http-01", "tls-alpn-01", "dns-01".
	challengeType string
	// dnsProvider is set only when challengeType is "dns-01".
	dnsProvider string
	// dnsCredentials holds provider-specific credentials for DNS-01 challenges.
	dnsCredentials map[string]string
	// httpPort is the HTTP-01 challenge listener port (default 80).
	httpPort int
	// httpsPort is the TLS-ALPN-01 challenge listener port (default 443).
	httpsPort int
	// staging selects the Let's Encrypt staging environment when true.
	staging bool

	// ACME client.
	acmeClient *lego.Client

	// Auto-renewal.
	renewalCheckInterval time.Duration
	// renewalThreshold is how long before expiry a renewal is attempted.
	renewalThreshold time.Duration
	stopChan         chan struct{}
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

func (u *ACMEUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// CertificatePaths holds paths to certificate files
type CertificatePaths struct {
	CertPath string
	KeyPath  string
	// Source is one of: "system", "app-letsencrypt", "app-local"
	Source string
}

// NewCertManager creates a new SSL certificate manager
func NewCertManager(configDir, fqdn string) *CertManager {
	return &CertManager{
		configDir:            configDir,
		fqdn:                 fqdn,
		challengeType:        "http-01",
		httpPort:             80,
		httpsPort:            443,
		staging:              false,
		renewalCheckInterval: 24 * time.Hour,
		renewalThreshold:     7 * 24 * time.Hour,
		stopChan:             make(chan struct{}),
	}
}

// LoadCertificate attempts to load an existing certificate following PART 15 lookup order
// Priority:
//  1. /etc/letsencrypt/live/domain/ (literal "domain" directory)
//  2. /etc/letsencrypt/live/{fqdn}/
//  3. {config_dir}/ssl/letsencrypt/{fqdn}/
//  4. {config_dir}/ssl/local/{fqdn}/
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

	// Check if renewal is needed (7 days before expiry by default)
	timeUntilExpiry := time.Until(x509Cert.NotAfter)
	if timeUntilExpiry <= cm.renewalThreshold {
		_ = cm.RenewCertificate()
	}
}

// RequestNewCertificate requests a new certificate from Let's Encrypt using the configured challenge type
func (cm *CertManager) RequestNewCertificate() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ACME account key: %w", err)
	}

	user := &ACMEUser{
		Email: cm.email,
		key:   privateKey,
	}

	config := lego.NewConfig(user)
	if cm.staging {
		config.CADirURL = lego.LEDirectoryStaging
	} else {
		config.CADirURL = lego.LEDirectoryProduction
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %w", err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("failed to register ACME account: %w", err)
	}
	user.Registration = reg

	switch cm.challengeType {
	case "http-01":
		provider := http01.NewProviderServer("", strconv.Itoa(cm.httpPort))
		if err := client.Challenge.SetHTTP01Provider(provider); err != nil {
			return fmt.Errorf("failed to set HTTP-01 provider: %w", err)
		}
	case "tls-alpn-01":
		provider := tlsalpn01.NewProviderServer("", strconv.Itoa(cm.httpsPort))
		if err := client.Challenge.SetTLSALPN01Provider(provider); err != nil {
			return fmt.Errorf("failed to set TLS-ALPN-01 provider: %w", err)
		}
	case "dns-01":
		if cm.dnsProvider == "" {
			return fmt.Errorf("DNS-01 requires a configured provider; set server.tls.dns_provider in server.yml")
		}
		// Use lego's provider factory — credentials come from environment variables
		// named per the lego convention (e.g. CF_API_TOKEN for cloudflare).
		// See https://go-acme.github.io/lego/dns/ for the full provider list.
		dnsProvider, dnsErr := legodns.NewDNSChallengeProviderByName(cm.dnsProvider)
		if dnsErr != nil {
			return fmt.Errorf("DNS-01 provider %q: %w", cm.dnsProvider, dnsErr)
		}
		if err := client.Challenge.SetDNS01Provider(dnsProvider); err != nil {
			return fmt.Errorf("failed to set DNS-01 provider %q: %w", cm.dnsProvider, err)
		}
	default:
		return fmt.Errorf("unsupported challenge type: %s", cm.challengeType)
	}

	request := certificate.ObtainRequest{
		Domains: []string{cm.fqdn},
		Bundle:  true,
	}
	resource, err := client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %w", err)
	}

	if err := cm.saveLetsEncryptCert(resource.Certificate, resource.PrivateKey); err != nil {
		return err
	}

	cm.acmeClient = client
	return cm.LoadCertificate()
}

// RenewCertificate renews the existing Let's Encrypt certificate, requesting a new one if none exists
func (cm *CertManager) RenewCertificate() error {
	if cm.acmeClient == nil {
		return cm.RequestNewCertificate()
	}

	certPath := filepath.Join(cm.configDir, "ssl", "letsencrypt", cm.fqdn, "fullchain.pem")
	keyPath := filepath.Join(cm.configDir, "ssl", "letsencrypt", cm.fqdn, "privkey.pem")

	certPEM, err := getCertPEM(certPath)
	if err != nil {
		return fmt.Errorf("failed to read existing certificate for renewal: %w", err)
	}
	keyPEM, err := getKeyPEM(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read existing private key for renewal: %w", err)
	}

	existing := certificate.Resource{
		Domain:      cm.fqdn,
		Certificate: certPEM,
		PrivateKey:  keyPEM,
	}

	resource, err := cm.acmeClient.Certificate.RenewWithOptions(existing, &certificate.RenewOptions{Bundle: true})
	if err != nil {
		return fmt.Errorf("failed to renew certificate: %w", err)
	}

	if err := cm.saveLetsEncryptCert(resource.Certificate, resource.PrivateKey); err != nil {
		return err
	}

	return cm.LoadCertificate()
}

// saveLetsEncryptCert writes certificate and private key PEM files to the app-managed LE directory
func (cm *CertManager) saveLetsEncryptCert(certPEM, keyPEM []byte) error {
	dir := filepath.Join(cm.configDir, "ssl", "letsencrypt", cm.fqdn)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	certPath := filepath.Join(dir, "fullchain.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	keyPath := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
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
		"subject":    x509Cert.Subject.CommonName,
		"issuer":     x509Cert.Issuer.CommonName,
		"not_before": x509Cert.NotBefore,
		"not_after":  x509Cert.NotAfter,
		"dns_names":  x509Cert.DNSNames,
		"is_ca":      x509Cert.IsCA,
		"valid":      time.Now().Before(x509Cert.NotAfter) && time.Now().After(x509Cert.NotBefore),
	}

	return info, nil
}

// GenerateSelfSignedCertificate generates a self-signed certificate for development use
// and for domains that Let's Encrypt cannot validate (Tor .onion, I2P .i2p).
// Saves to {config_dir}/ssl/local/{fqdn}/
func (cm *CertManager) GenerateSelfSignedCertificate() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: cm.fqdn,
		},
		DNSNames:              []string{cm.fqdn},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	dir := filepath.Join(cm.configDir, "ssl", "local", cm.fqdn)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return cm.LoadCertificate()
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
