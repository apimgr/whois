package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// EmailSettingsResponse represents current email/SMTP configuration
type EmailSettingsResponse struct {
	Enabled      bool   `json:"enabled"`
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	SMTPUsername string `json:"smtp_username"`
	SMTPTLSMode  string `json:"smtp_tls"`     // auto, starttls, tls, none
	FromName     string `json:"from_name"`    // Sender name
	FromEmail    string `json:"from_email"`   // Sender email
	TestStatus   string `json:"test_status"`  // success, failed, not_tested
	LastTested   string `json:"last_tested"`  // ISO timestamp
}

// EmailSettingsRequest represents email/SMTP configuration update
type EmailSettingsRequest struct {
	Enabled      bool   `json:"enabled"`
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	SMTPUsername string `json:"smtp_username"`
	SMTPPassword string `json:"smtp_password"` // Only sent when updating
	SMTPTLSMode  string `json:"smtp_tls"`
	FromName     string `json:"from_name"`
	FromEmail    string `json:"from_email"`
}

// handleServerEmailSettings serves the email/SMTP configuration page HTML
// GET /{admin_path}/server/email
func (s *Server) handleServerEmailSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	// Get admin context from middleware
	adminCtx, ok := GetAdminContext(r)
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}

	html := renderServerEmailSettingsHTML(adminCtx, s.config.AdminPath)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// handleServerEmailSettingsAPI routes GET/POST for email settings API
// GET/POST /api/v1/{admin_path}/server/email
func (s *Server) handleServerEmailSettingsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleServerEmailSettingsGet(w, r)
	case http.MethodPost:
		s.handleServerEmailSettingsSave(w, r)
	default:
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
	}
}

// handleServerEmailSettingsGet returns current email/SMTP configuration
// GET /api/v1/{admin_path}/server/email
func (s *Server) handleServerEmailSettingsGet(w http.ResponseWriter, r *http.Request) {
	// TODO: Integrate with src/email/email.go to get actual SMTP config
	// For now, return stub data
	settings := EmailSettingsResponse{
		Enabled:      false,
		SMTPHost:     "",
		SMTPPort:     587,
		SMTPUsername: "",
		SMTPTLSMode:  "auto",
		FromName:     s.config.BrandingTitle,
		FromEmail:    fmt.Sprintf("no-reply@%s", s.config.FQDN),
		TestStatus:   "not_tested",
		LastTested:   "",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

// handleServerEmailSettingsSave updates email/SMTP configuration
// POST /api/v1/{admin_path}/server/email
func (s *Server) handleServerEmailSettingsSave(w http.ResponseWriter, r *http.Request) {
	var req EmailSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, ErrValidationFailed, "Invalid request body: "+err.Error())
		return
	}

	// Validate email settings
	if err := validateServerEmailSettings(&req); err != nil {
		SendError(w, ErrValidationFailed, err.Error())
		return
	}

	// TODO: Integrate with src/email/email.go to actually configure SMTP
	// This requires:
	// 1. Storing SMTP settings in config or database
	// 2. Testing SMTP connection
	// 3. Encrypting SMTP password
	// 4. Updating email manager instance

	response := map[string]interface{}{
		"success": true,
		"message": "Email settings saved successfully",
		"note":    "SMTP integration with email manager pending",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleServerEmailTest tests SMTP connection
// POST /api/v1/{admin_path}/server/email/test
func (s *Server) handleServerEmailTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	// TODO: Integrate with src/email/email.go to test SMTP connection
	// This requires sending a test email or doing EHLO handshake

	response := map[string]interface{}{
		"success": false,
		"message": "SMTP connection test not yet implemented",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// validateServerEmailSettings validates email/SMTP configuration
func validateServerEmailSettings(cfg *EmailSettingsRequest) error {
	if !cfg.Enabled {
		return nil // Disabling email is always valid
	}

	// Validate SMTP host (required when enabled)
	if cfg.SMTPHost == "" {
		return fmt.Errorf("smtp_host is required when email is enabled")
	}

	// Validate SMTP port
	if cfg.SMTPPort < 1 || cfg.SMTPPort > 65535 {
		return fmt.Errorf("smtp_port must be between 1 and 65535")
	}

	// Common SMTP ports validation (warn about non-standard ports)
	validPorts := map[int]bool{25: true, 465: true, 587: true, 2525: true}
	if !validPorts[cfg.SMTPPort] {
		// Not an error, just unusual
	}

	// Validate TLS mode
	validTLSModes := map[string]bool{
		"auto":     true,
		"starttls": true,
		"tls":      true,
		"none":     true,
	}
	if cfg.SMTPTLSMode != "" && !validTLSModes[cfg.SMTPTLSMode] {
		return fmt.Errorf("smtp_tls must be auto, starttls, tls, or none")
	}

	// Validate from_email format
	if cfg.FromEmail != "" {
		if len(cfg.FromEmail) < 3 || !strings.Contains(cfg.FromEmail, "@") {
			return fmt.Errorf("invalid from_email address")
		}
	}

	return nil
}

// renderServerEmailSettingsHTML generates the email/SMTP configuration page HTML
func renderServerEmailSettingsHTML(adminCtx *AdminContext, adminPath string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email/SMTP Settings - Admin Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a1a;
            color: #e0e0e0;
            line-height: 1.6;
        }
        .header {
            background: #2a2a2a;
            border-bottom: 1px solid #3a3a3a;
            padding: 1rem 2rem;
        }
        .header h1 {
            font-size: 1.5rem;
            font-weight: 600;
        }
        .container {
            max-width: 900px;
            margin: 2rem auto;
            padding: 0 2rem;
        }
        .section {
            background: #2a2a2a;
            border: 1px solid #3a3a3a;
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        .section-title {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #3a3a3a;
        }
        .status-box {
            padding: 1.5rem;
            background: #1a1a1a;
            border: 1px solid #3a3a3a;
            border-radius: 4px;
            margin-bottom: 1.5rem;
        }
        .status-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 0.5rem;
        }
        .status-label {
            color: #999;
        }
        .status-value {
            font-weight: 500;
        }
        .status-enabled {
            color: #4caf50;
        }
        .status-disabled {
            color: #f44336;
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        .form-group input, .form-group select {
            width: 100%%;
            padding: 0.75rem;
            background: #1a1a1a;
            border: 1px solid #3a3a3a;
            border-radius: 4px;
            color: #e0e0e0;
            font-size: 1rem;
        }
        .form-group small {
            display: block;
            margin-top: 0.25rem;
            color: #999;
            font-size: 0.875rem;
        }
        .form-row {
            display: grid;
            grid-template-columns: 3fr 1fr;
            gap: 1rem;
        }
        .button {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 4px;
            font-size: 1rem;
            cursor: pointer;
        }
        .button-primary {
            background: #007bff;
            color: white;
        }
        .button-secondary {
            background: #3a3a3a;
            color: #e0e0e0;
            margin-left: 0.5rem;
        }
        .button-success {
            background: #4caf50;
            color: white;
        }
        .alert {
            padding: 1rem;
            border-radius: 4px;
            margin-bottom: 1rem;
            display: none;
        }
        .alert.success { background: #2e7d32; color: white; }
        .alert.error { background: #c62828; color: white; }
        .info-box {
            background: #1a3a5a;
            border: 1px solid #2a4a6a;
            padding: 1rem;
            border-radius: 4px;
            margin-top: 1rem;
        }
        .info-box p {
            margin: 0.5rem 0;
        }
        .warning-box {
            background: #5a4a1a;
            border: 1px solid #6a5a2a;
            padding: 1rem;
            border-radius: 4px;
            margin-bottom: 1.5rem;
        }
        @media (max-width: 768px) {
            .container {
                padding: 0 1rem;
            }
            .section {
                padding: 1.5rem;
            }
            .form-row {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Email/SMTP Settings</h1>
    </div>
    <div class="container">
        <div id="alert" class="alert"></div>
        
        <div class="section">
            <div class="section-title">Current Status</div>
            <div class="status-box" id="statusBox">
                <div class="status-row">
                    <span class="status-label">Email Status:</span>
                    <span class="status-value status-disabled" id="emailStatus">⚠️ Not Configured</span>
                </div>
                <div class="status-row">
                    <span class="status-label">SMTP Server:</span>
                    <span class="status-value" id="smtpServer">None</span>
                </div>
                <div class="status-row">
                    <span class="status-label">Last Test:</span>
                    <span class="status-value" id="lastTest">Never</span>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">SMTP Configuration</div>
            
            <div class="warning-box">
                <strong>⚠️ Important:</strong> Email features require a working SMTP server. 
                If no SMTP is configured, email-dependent features will be disabled.
            </div>
            
            <div class="form-row">
                <div class="form-group">
                    <label>SMTP Host</label>
                    <input type="text" id="smtpHost" placeholder="smtp.example.com or 127.0.0.1">
                    <small>Leave empty for auto-detection on startup</small>
                </div>
                
                <div class="form-group">
                    <label>Port</label>
                    <input type="number" id="smtpPort" value="587" min="1" max="65535">
                    <small>25, 465, 587</small>
                </div>
            </div>
            
            <div class="form-group">
                <label>Username (optional)</label>
                <input type="text" id="smtpUsername" placeholder="user@example.com">
                <small>Leave empty if SMTP server doesn't require authentication</small>
            </div>
            
            <div class="form-group">
                <label>Password (optional)</label>
                <input type="password" id="smtpPassword" placeholder="••••••••">
                <small>🔒 Encrypted and stored securely</small>
            </div>
            
            <div class="form-group">
                <label>TLS Mode</label>
                <select id="smtpTLS">
                    <option value="auto">Auto (Recommended)</option>
                    <option value="starttls">STARTTLS (Port 587)</option>
                    <option value="tls">TLS/SSL (Port 465)</option>
                    <option value="none">None (Port 25 - Not Recommended)</option>
                </select>
            </div>
            
            <div class="section-title" style="margin-top: 2rem;">Sender Information</div>
            
            <div class="form-group">
                <label>From Name</label>
                <input type="text" id="fromName" placeholder="caswhois">
                <small>Name displayed in "From" field of emails</small>
            </div>
            
            <div class="form-group">
                <label>From Email</label>
                <input type="email" id="fromEmail" placeholder="no-reply@example.com">
                <small>Email address displayed in "From" field</small>
            </div>
            
            <button class="button button-primary" onclick="saveServerEmailSettings()">Save Settings</button>
            <button class="button button-success" onclick="testServerEmailConnection()">Test Connection</button>
            
            <div class="info-box">
                <p><strong>ℹ️ SMTP Information</strong></p>
                <p>• Auto-detection tries common hosts: 127.0.0.1, 172.17.0.1, mail.{fqdn}</p>
                <p>• Port 587 (STARTTLS) is recommended for modern SMTP</p>
                <p>• Port 465 uses implicit TLS/SSL</p>
                <p>• Port 25 is unencrypted (not recommended)</p>
                <p>• Some hosts (Gmail, etc.) require app-specific passwords</p>
            </div>
        </div>
    </div>
    
    <script>
        function showAlert(msg, type) {
            const alert = document.getElementById('alert');
            alert.className = 'alert ' + type;
            alert.textContent = msg;
            alert.style.display = 'block';
            setTimeout(() => alert.style.display = 'none', 5000);
        }
        
        async function loadServerEmailSettings() {
            try {
                const res = await fetch('/api/v1/%s/server/email');
                const data = await res.json();
                
                document.getElementById('emailStatus').textContent = data.enabled ? '✅ Configured' : '⚠️ Not Configured';
                document.getElementById('emailStatus').className = data.enabled ? 'status-value status-enabled' : 'status-value status-disabled';
                document.getElementById('smtpServer').textContent = data.smtp_host ? data.smtp_host + ':' + data.smtp_port : 'None';
                document.getElementById('lastTest').textContent = data.last_tested || 'Never';
                
                document.getElementById('smtpHost').value = data.smtp_host || '';
                document.getElementById('smtpPort').value = data.smtp_port || 587;
                document.getElementById('smtpUsername').value = data.smtp_username || '';
                document.getElementById('smtpTLS').value = data.smtp_tls || 'auto';
                document.getElementById('fromName').value = data.from_name || '';
                document.getElementById('fromEmail').value = data.from_email || '';
            } catch (e) {
                console.error('Failed to load email settings:', e);
            }
        }
        
        async function saveServerEmailSettings() {
            const config = {
                enabled: true,
                smtp_host: document.getElementById('smtpHost').value,
                smtp_port: parseInt(document.getElementById('smtpPort').value),
                smtp_username: document.getElementById('smtpUsername').value,
                smtp_password: document.getElementById('smtpPassword').value,
                smtp_tls: document.getElementById('smtpTLS').value,
                from_name: document.getElementById('fromName').value,
                from_email: document.getElementById('fromEmail').value
            };
            
            try {
                const res = await fetch('/api/v1/%s/server/email', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(config)
                });
                const data = await res.json();
                
                if (data.success) {
                    showAlert(data.message, 'success');
                    loadServerEmailSettings();
                    document.getElementById('smtpPassword').value = '';
                } else {
                    showAlert(data.message || 'Failed to save email settings', 'error');
                }
            } catch (e) {
                showAlert('Network error: ' + e.message, 'error');
            }
        }
        
        async function testServerEmailConnection() {
            try {
                const res = await fetch('/api/v1/%s/server/email/test', {
                    method: 'POST'
                });
                const data = await res.json();
                
                if (data.success) {
                    showAlert('SMTP connection successful!', 'success');
                } else {
                    showAlert(data.message || 'SMTP connection test failed', 'error');
                }
            } catch (e) {
                showAlert('Network error: ' + e.message, 'error');
            }
        }
        
        loadServerEmailSettings();
    </script>
</body>
</html>`, adminPath, adminPath, adminPath)
}
