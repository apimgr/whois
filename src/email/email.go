// Package email provides email notification support with SMTP auto-detection
// Implements AI.md PART 18: EMAIL & NOTIFICATIONS
package email

import (
	"bytes"
	"crypto/tls"
	"embed"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*.txt
var defaultTemplates embed.FS

// EmailManager handles email sending and template management
type EmailManager struct {
	configDir string
	enabled   bool
	mu        sync.RWMutex

	// SMTP configuration
	smtpHost     string
	smtpPort     int
	smtpUsername string
	smtpPassword string
	smtpTLS      string // "auto", "starttls", "tls", "none"

	// Sender configuration
	fromName  string
	fromEmail string

	// Auto-detected settings
	autoDetected bool
}

// EmailTemplate represents a parsed email template
type EmailTemplate struct {
	Subject string
	Body    string
}

// EmailData holds data for template rendering
type EmailData map[string]string

// NewEmailManager creates a new email manager
func NewEmailManager(configDir string) *EmailManager {
	return &EmailManager{
		configDir: configDir,
		enabled:   false,
		smtpPort:  587,
		smtpTLS:   "auto",
	}
}

// Configure sets SMTP configuration from config or environment variables
// Environment variables override config file settings
func (em *EmailManager) Configure(host string, port int, username, password, tlsMode, fromName, fromEmail string) {
	em.mu.Lock()
	defer em.mu.Unlock()

	// Check environment variable overrides
	if envHost := os.Getenv("SMTP_HOST"); envHost != "" {
		host = envHost
	}
	if envPort := os.Getenv("SMTP_PORT"); envPort != "" {
		if p, err := parseInt(envPort); err == nil {
			port = p
		}
	}
	if envUser := os.Getenv("SMTP_USERNAME"); envUser != "" {
		username = envUser
	}
	if envPass := os.Getenv("SMTP_PASSWORD"); envPass != "" {
		password = envPass
	}
	if envTLS := os.Getenv("SMTP_TLS"); envTLS != "" {
		tlsMode = envTLS
	}
	if envFromName := os.Getenv("SMTP_FROM_NAME"); envFromName != "" {
		fromName = envFromName
	}
	if envFromEmail := os.Getenv("SMTP_FROM_EMAIL"); envFromEmail != "" {
		fromEmail = envFromEmail
	}

	em.smtpHost = host
	em.smtpPort = port
	em.smtpUsername = username
	em.smtpPassword = password
	em.smtpTLS = tlsMode
	em.fromName = fromName
	em.fromEmail = fromEmail
}

// AutoDetectSMTP attempts to auto-detect a local SMTP server
// Priority: 127.0.0.1, 172.17.0.1 (Docker), gateway IP, fqdn, global IPv4, mail.fqdn, smtp.fqdn
// Ports tried: 25, 465, 587
func (em *EmailManager) AutoDetectSMTP(fqdn string, globalIPv4 string) bool {
	em.mu.Lock()
	defer em.mu.Unlock()

	// Build list of hosts to try
	hosts := []string{
		"127.0.0.1",
		"172.17.0.1", // Docker bridge gateway
	}

	// Add gateway IP
	if gateway := getDefaultGateway(); gateway != "" {
		hosts = append(hosts, gateway)
	}

	// Add FQDN variants
	if fqdn != "" && fqdn != "localhost" {
		hosts = append(hosts, fqdn)
	}
	if globalIPv4 != "" {
		hosts = append(hosts, globalIPv4)
	}
	if fqdn != "" && fqdn != "localhost" {
		hosts = append(hosts, "mail."+fqdn)
		hosts = append(hosts, "smtp."+fqdn)
	}

	// Ports to try (in order of preference)
	ports := []int{587, 25, 465}

	// Try each host:port combination
	for _, host := range hosts {
		for _, port := range ports {
			if em.testSMTPConnection(host, port, true) {
				em.smtpHost = host
				em.smtpPort = port
				em.autoDetected = true
				em.enabled = true
				return true
			}
		}
	}

	return false
}

// TestConnection tests the configured SMTP connection
func (em *EmailManager) TestConnection() error {
	em.mu.RLock()
	host := em.smtpHost
	port := em.smtpPort
	em.mu.RUnlock()

	if host == "" {
		return fmt.Errorf("SMTP host not configured")
	}

	if !em.testSMTPConnection(host, port, false) {
		return fmt.Errorf("failed to connect to SMTP server %s:%d", host, port)
	}

	return nil
}

// testSMTPConnection tests if an SMTP server is reachable and responsive
func (em *EmailManager) testSMTPConnection(host string, port int, quick bool) bool {
	timeout := 5 * time.Second
	if quick {
		timeout = 2 * time.Second
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	// Try to connect
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Set read/write deadline
	conn.SetDeadline(time.Now().Add(timeout))

	// Try SMTP handshake (EHLO)
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return false
	}
	defer client.Close()

	// Send EHLO
	if err := client.Hello("localhost"); err != nil {
		return false
	}

	return true
}

// IsEnabled returns whether email functionality is enabled
func (em *EmailManager) IsEnabled() bool {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return em.enabled
}

// Enable enables email functionality (after successful SMTP test)
func (em *EmailManager) Enable() {
	em.mu.Lock()
	defer em.mu.Unlock()
	em.enabled = true
}

// Disable disables email functionality
func (em *EmailManager) Disable() {
	em.mu.Lock()
	defer em.mu.Unlock()
	em.enabled = false
}

// GetSMTPInfo returns current SMTP configuration (for display/debugging)
func (em *EmailManager) GetSMTPInfo() map[string]interface{} {
	em.mu.RLock()
	defer em.mu.RUnlock()

	return map[string]interface{}{
		"enabled":       em.enabled,
		"host":          em.smtpHost,
		"port":          em.smtpPort,
		"username":      em.smtpUsername,
		"tls_mode":      em.smtpTLS,
		"from_name":     em.fromName,
		"from_email":    em.fromEmail,
		"auto_detected": em.autoDetected,
	}
}

// SendEmail sends an email using the specified template and data
// If SMTP is not configured or disabled, this is a no-op (no error, no logging)
func (em *EmailManager) SendEmail(to, templateName string, data EmailData) error {
	em.mu.RLock()
	enabled := em.enabled
	em.mu.RUnlock()

	if !enabled {
		// Email disabled - silently skip (AI.md PART 18: never log "would have sent")
		return nil
	}

	// Load template
	template, err := em.loadTemplate(templateName)
	if err != nil {
		return fmt.Errorf("failed to load template %s: %w", templateName, err)
	}

	// Render template
	subject := em.renderTemplate(template.Subject, data)
	body := em.renderTemplate(template.Body, data)

	// Send email
	return em.sendSMTP(to, subject, body)
}

// loadTemplate loads a template by name
// Priority: custom template in {config_dir}/template/email/, embedded default
func (em *EmailManager) loadTemplate(name string) (*EmailTemplate, error) {
	// Try custom template first
	customPath := filepath.Join(em.configDir, "template", "email", name+".txt")
	if content, err := os.ReadFile(customPath); err == nil {
		return em.parseTemplate(string(content))
	}

	// Fall back to embedded default
	defaultPath := "templates/" + name + ".txt"
	content, err := defaultTemplates.ReadFile(defaultPath)
	if err != nil {
		return nil, fmt.Errorf("template not found: %s", name)
	}

	return em.parseTemplate(string(content))
}

// parseTemplate parses template content into subject and body
// Format:
//   Subject: ...
//   ---
//   Body...
func (em *EmailManager) parseTemplate(content string) (*EmailTemplate, error) {
	parts := strings.SplitN(content, "\n---\n", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid template format (missing --- separator)")
	}

	// Extract subject
	subjectLine := strings.TrimSpace(parts[0])
	subject := strings.TrimPrefix(subjectLine, "Subject:")
	subject = strings.TrimSpace(subject)

	if subject == "" {
		return nil, fmt.Errorf("invalid template format (missing subject)")
	}

	body := strings.TrimSpace(parts[1])

	return &EmailTemplate{
		Subject: subject,
		Body:    body,
	}, nil
}

// renderTemplate renders a template string with provided data
func (em *EmailManager) renderTemplate(template string, data EmailData) string {
	result := template

	// Replace variables
	for key, value := range data {
		placeholder := "{" + key + "}"
		result = strings.ReplaceAll(result, placeholder, value)
	}

	return result
}

// sendSMTP sends an email via SMTP
func (em *EmailManager) sendSMTP(to, subject, body string) error {
	em.mu.RLock()
	host := em.smtpHost
	port := em.smtpPort
	username := em.smtpUsername
	password := em.smtpPassword
	tlsMode := em.smtpTLS
	fromName := em.fromName
	fromEmail := em.fromEmail
	em.mu.RUnlock()

	if host == "" {
		return fmt.Errorf("SMTP host not configured")
	}

	// Format sender
	from := fromEmail
	if fromName != "" {
		from = fmt.Sprintf("%s <%s>", fromName, fromEmail)
	}

	// Build message
	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	// Determine TLS strategy
	addr := fmt.Sprintf("%s:%d", host, port)

	// Try connection based on TLS mode
	switch tlsMode {
	case "tls":
		return em.sendWithTLS(addr, username, password, fromEmail, to, msg.Bytes())
	case "starttls":
		return em.sendWithSTARTTLS(addr, host, username, password, fromEmail, to, msg.Bytes())
	case "none":
		return em.sendPlain(addr, username, password, fromEmail, to, msg.Bytes())
	case "auto":
		// Try TLS first (port 465), then STARTTLS (587), then plain (25)
		if port == 465 {
			return em.sendWithTLS(addr, username, password, fromEmail, to, msg.Bytes())
		}
		if port == 587 || port == 25 {
			return em.sendWithSTARTTLS(addr, host, username, password, fromEmail, to, msg.Bytes())
		}
		return em.sendPlain(addr, username, password, fromEmail, to, msg.Bytes())
	default:
		return fmt.Errorf("unknown TLS mode: %s", tlsMode)
	}
}

// sendWithTLS sends email using implicit TLS (typically port 465)
func (em *EmailManager) sendWithTLS(addr, username, password, from, to string, msg []byte) error {
	tlsConfig := &tls.Config{
		ServerName: strings.Split(addr, ":")[0],
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS dial failed: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, tlsConfig.ServerName)
	if err != nil {
		return fmt.Errorf("SMTP client creation failed: %w", err)
	}
	defer client.Close()

	return em.sendWithClient(client, username, password, from, to, msg)
}

// sendWithSTARTTLS sends email using STARTTLS (typically ports 587 or 25)
func (em *EmailManager) sendWithSTARTTLS(addr, host, username, password, from, to string, msg []byte) error {
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("SMTP dial failed: %w", err)
	}
	defer client.Close()

	// Try STARTTLS
	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{
			ServerName: host,
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS failed: %w", err)
		}
	}

	return em.sendWithClient(client, username, password, from, to, msg)
}

// sendPlain sends email without TLS (typically port 25, local/trusted network)
func (em *EmailManager) sendPlain(addr, username, password, from, to string, msg []byte) error {
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("SMTP dial failed: %w", err)
	}
	defer client.Close()

	return em.sendWithClient(client, username, password, from, to, msg)
}

// sendWithClient sends email using an established SMTP client
func (em *EmailManager) sendWithClient(client *smtp.Client, username, password, from, to string, msg []byte) error {
	// Authenticate if credentials provided
	if username != "" && password != "" {
		auth := smtp.PlainAuth("", username, password, strings.Split(client.Text, " ")[0])
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth failed: %w", err)
		}
	}

	// Set sender
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	// Set recipient
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO failed: %w", err)
	}

	// Send message body
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}
	defer w.Close()

	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("message write failed: %w", err)
	}

	return nil
}

// GetDefaultFromEmail returns the default from email address
func GetDefaultFromEmail(fqdn string) string {
	if fqdn == "" || fqdn == "localhost" {
		return "no-reply@localhost"
	}
	return "no-reply@" + fqdn
}

// getDefaultGateway returns the default gateway IP address
func getDefaultGateway() string {
	// TODO: Implement platform-specific gateway detection
	// This is a placeholder - proper implementation requires parsing route tables
	return ""
}

// parseInt parses a string to int
func parseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}
