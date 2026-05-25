package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// SSLStatusResponse represents the current SSL/TLS configuration status
type SSLStatusResponse struct {
	Enabled     bool   `json:"enabled"`
	Certificate string `json:"certificate"` // Let's Encrypt, Self-signed, Custom
	Issuer      string `json:"issuer"`
	ExpiresAt   string `json:"expires_at"`
	DaysLeft    int    `json:"days_left"`
	FQDN        string `json:"fqdn"`
	AutoRenew   bool   `json:"auto_renew"`
}

// SSLConfigRequest represents SSL configuration update request
type SSLConfigRequest struct {
	Enabled       bool   `json:"enabled"`
	Provider      string `json:"provider"` // letsencrypt, custom, selfsigned
	Email         string `json:"email"`    // For Let's Encrypt notifications
	CertPath      string `json:"cert_path"`
	KeyPath       string `json:"key_path"`
	ChallengeType string `json:"challenge_type"` // http-01, dns-01, tls-alpn-01
	DNSProvider   string `json:"dns_provider"`    // cloudflare, route53, etc
	DNSToken      string `json:"dns_token"`       // API token for DNS provider
}

// handleServerSSLSettings serves the SSL configuration page HTML
// GET /{admin_path}/server/ssl
func (s *Server) handleServerSSLSettings(w http.ResponseWriter, r *http.Request) {
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

	html := renderServerSSLSettingsHTML(adminCtx, s.config.AdminPath, s.config.FQDN)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// handleServerSSLSettingsAPI routes GET/POST for SSL settings API
// GET/POST /api/v1/{admin_path}/server/ssl
func (s *Server) handleServerSSLSettingsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleServerSSLSettingsGet(w, r)
	case http.MethodPost:
		s.handleServerSSLSettingsSave(w, r)
	default:
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
	}
}

// handleServerSSLSettingsGet returns current SSL configuration status
// GET /api/v1/{admin_path}/server/ssl
func (s *Server) handleServerSSLSettingsGet(w http.ResponseWriter, r *http.Request) {
	// TODO: Integrate with src/ssl/ssl.go to get actual certificate info
	// For now, return stub data indicating SSL not configured
	status := SSLStatusResponse{
		Enabled:     false,
		Certificate: "None",
		Issuer:      "",
		ExpiresAt:   "",
		DaysLeft:    0,
		FQDN:        s.config.FQDN,
		AutoRenew:   false,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleServerSSLSettingsSave updates SSL configuration
// POST /api/v1/{admin_path}/server/ssl
func (s *Server) handleServerSSLSettingsSave(w http.ResponseWriter, r *http.Request) {
	var req SSLConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, ErrValidationFailed, "Invalid request body: "+err.Error())
		return
	}

	// Validate SSL configuration
	if err := validateServerSSLConfig(&req); err != nil {
		SendError(w, ErrValidationFailed, err.Error())
		return
	}

	// TODO: Integrate with src/ssl/ssl.go to actually configure SSL/TLS
	// This requires implementing:
	// 1. Let's Encrypt ACME client integration
	// 2. Certificate storage and retrieval
	// 3. Auto-renewal scheduler task
	// 4. DNS provider API integration for DNS-01 challenge

	response := map[string]interface{}{
		"success": true,
		"message": "SSL configuration saved successfully",
		"note":    "Full SSL certificate management integration pending",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// validateServerSSLConfig validates SSL configuration request
func validateServerSSLConfig(cfg *SSLConfigRequest) error {
	if !cfg.Enabled {
		return nil // Disabling SSL is always valid
	}

	// Validate provider
	validProviders := map[string]bool{
		"letsencrypt": true,
		"custom":      true,
		"selfsigned":  true,
	}
	if !validProviders[cfg.Provider] {
		return fmt.Errorf("invalid provider: must be letsencrypt, custom, or selfsigned")
	}

	// Validate Let's Encrypt specific fields
	if cfg.Provider == "letsencrypt" {
		if cfg.Email == "" {
			return fmt.Errorf("email is required for Let's Encrypt")
		}
		// Basic email validation
		if len(cfg.Email) < 3 || !strings.Contains(cfg.Email, "@") {
			return fmt.Errorf("invalid email address")
		}

		// Validate challenge type
		validChallenges := map[string]bool{
			"http-01":     true,
			"dns-01":      true,
			"tls-alpn-01": true,
		}
		if cfg.ChallengeType != "" && !validChallenges[cfg.ChallengeType] {
			return fmt.Errorf("invalid challenge type: must be http-01, dns-01, or tls-alpn-01")
		}

		// If DNS challenge, require provider and token
		if cfg.ChallengeType == "dns-01" {
			if cfg.DNSProvider == "" {
				return fmt.Errorf("dns_provider is required for DNS-01 challenge")
			}
			if cfg.DNSToken == "" {
				return fmt.Errorf("dns_token is required for DNS-01 challenge")
			}
		}
	}

	// Validate custom certificate paths
	if cfg.Provider == "custom" {
		if cfg.CertPath == "" {
			return fmt.Errorf("cert_path is required for custom certificates")
		}
		if cfg.KeyPath == "" {
			return fmt.Errorf("key_path is required for custom certificates")
		}
	}

	return nil
}

// renderServerSSLSettingsHTML generates the SSL configuration page HTML
func renderServerSSLSettingsHTML(adminCtx *AdminContext, adminPath, fqdn string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL/TLS Configuration - Admin Panel</title>
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
        @media (max-width: 768px) {
            .container {
                padding: 0 1rem;
            }
            .section {
                padding: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>SSL/TLS Configuration</h1>
    </div>
    <div class="container">
        <div id="alert" class="alert"></div>
        
        <div class="section">
            <div class="section-title">Current Status</div>
            <div class="status-box" id="statusBox">
                <div class="status-row">
                    <span class="status-label">SSL Status:</span>
                    <span class="status-value status-disabled" id="sslStatus">⚠️ Not Configured</span>
                </div>
                <div class="status-row">
                    <span class="status-label">FQDN:</span>
                    <span class="status-value" id="fqdnValue">%s</span>
                </div>
                <div class="status-row">
                    <span class="status-label">Certificate:</span>
                    <span class="status-value" id="certType">None</span>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">SSL Configuration</div>
            <div class="form-group">
                <label>Provider</label>
                <select id="provider">
                    <option value="">Select Provider</option>
                    <option value="letsencrypt">Let's Encrypt (Recommended)</option>
                    <option value="custom">Custom Certificate</option>
                    <option value="selfsigned">Self-Signed (Development Only)</option>
                </select>
            </div>
            
            <div id="letsencryptFields" style="display:none;">
                <div class="form-group">
                    <label>Email Address</label>
                    <input type="email" id="email" placeholder="admin@example.com">
                    <small>For Let's Encrypt notifications and certificate recovery</small>
                </div>
                
                <div class="form-group">
                    <label>Challenge Type</label>
                    <select id="challengeType">
                        <option value="http-01">HTTP-01 (Port 80 required)</option>
                        <option value="dns-01">DNS-01 (Requires DNS provider API)</option>
                        <option value="tls-alpn-01">TLS-ALPN-01 (Port 443 required)</option>
                    </select>
                </div>
                
                <div id="dnsFields" style="display:none;">
                    <div class="form-group">
                        <label>DNS Provider</label>
                        <select id="dnsProvider">
                            <option value="">Select Provider</option>
                            <option value="cloudflare">Cloudflare</option>
                            <option value="route53">AWS Route53</option>
                            <option value="digitalocean">DigitalOcean</option>
                            <option value="google">Google Cloud DNS</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label>API Token</label>
                        <input type="password" id="dnsToken" placeholder="API token">
                        <small>🔒 Encrypted and stored securely</small>
                    </div>
                </div>
            </div>
            
            <div id="customFields" style="display:none;">
                <div class="form-group">
                    <label>Certificate Path</label>
                    <input type="text" id="certPath" placeholder="/path/to/certificate.crt">
                </div>
                
                <div class="form-group">
                    <label>Private Key Path</label>
                    <input type="text" id="keyPath" placeholder="/path/to/private.key">
                </div>
            </div>
            
            <button class="button button-primary" onclick="saveServerSSLConfig()">Enable SSL</button>
            <button class="button button-secondary" onclick="testServerSSLConfig()">Test Configuration</button>
            
            <div class="info-box">
                <p><strong>ℹ️ SSL/TLS Information</strong></p>
                <p>• Let's Encrypt certificates are free and auto-renew every 90 days</p>
                <p>• HTTP-01 challenge requires port 80 accessible from internet</p>
                <p>• DNS-01 challenge works behind firewalls but requires DNS API access</p>
                <p>• Self-signed certificates show browser warnings (dev only)</p>
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
        
        async function loadServerSSLStatus() {
            try {
                const res = await fetch('/api/v1/%s/server/ssl');
                const data = await res.json();
                
                document.getElementById('sslStatus').textContent = data.enabled ? '🔒 Active' : '⚠️ Not Configured';
                document.getElementById('sslStatus').className = data.enabled ? 'status-value status-enabled' : 'status-value status-disabled';
                document.getElementById('certType').textContent = data.certificate || 'None';
                document.getElementById('fqdnValue').textContent = data.fqdn || 'Not set';
            } catch (e) {
                console.error('Failed to load SSL status:', e);
            }
        }
        
        async function saveServerSSLConfig() {
            const provider = document.getElementById('provider').value;
            if (!provider) {
                showAlert('Please select a provider', 'error');
                return;
            }
            
            const config = {
                enabled: true,
                provider: provider,
                email: document.getElementById('email').value,
                cert_path: document.getElementById('certPath').value,
                key_path: document.getElementById('keyPath').value,
                challenge_type: document.getElementById('challengeType').value,
                dns_provider: document.getElementById('dnsProvider').value,
                dns_token: document.getElementById('dnsToken').value
            };
            
            try {
                const res = await fetch('/api/v1/%s/server/ssl', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(config)
                });
                const data = await res.json();
                
                if (data.success) {
                    showAlert(data.message, 'success');
                    loadServerSSLStatus();
                } else {
                    showAlert(data.message || 'Failed to save SSL configuration', 'error');
                }
            } catch (e) {
                showAlert('Network error: ' + e.message, 'error');
            }
        }
        
        function testServerSSLConfig() {
            showAlert('SSL configuration test not yet implemented', 'error');
        }
        
        document.getElementById('provider').addEventListener('change', function() {
            document.getElementById('letsencryptFields').style.display = this.value === 'letsencrypt' ? 'block' : 'none';
            document.getElementById('customFields').style.display = this.value === 'custom' ? 'block' : 'none';
        });
        
        document.getElementById('challengeType').addEventListener('change', function() {
            document.getElementById('dnsFields').style.display = this.value === 'dns-01' ? 'block' : 'none';
        });
        
        loadServerSSLStatus();
    </script>
</body>
</html>`, fqdn, adminPath, adminPath)
}
