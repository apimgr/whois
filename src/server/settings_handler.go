package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/casapps/caswhois/src/config"
)

// ServerSettings represents configurable server settings
// See AI.md PART 17 for complete field definitions
type ServerSettings struct {
	// General section
	Port    int    `json:"port"`
	Mode    string `json:"mode"`     // production or development
	FQDN    string `json:"fqdn"`     // auto-detected or manual
	Address string `json:"address"`  // listen address

	// Process section
	Daemonize bool `json:"daemonize"`
	PIDFile   bool `json:"pidfile"`

	// Branding section
	Title       string `json:"title"`
	Tagline     string `json:"tagline"`
	Description string `json:"description"`
	Theme       string `json:"theme"` // auto, light, dark
	AccentColor string `json:"accent_color"`

	// Security section
	AdminPath        string `json:"admin_path"`
	RateLimitEnabled bool   `json:"rate_limit_enabled"`
	RateLimitReqs    int    `json:"rate_limit_requests"`
	RateLimitWindow  string `json:"rate_limit_window"`
}

// handleServerSettings serves the server settings page
// GET /{admin_path}/server/settings
func (s *Server) handleServerSettings(w http.ResponseWriter, r *http.Request) {
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

	html := renderServerSettingsHTML(adminCtx, s.config)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// handleServerSettingsAPI handles GET/POST for server settings API
// GET /api/v1/{admin_path}/server/settings
// POST /api/v1/{admin_path}/server/settings
func (s *Server) handleServerSettingsAPI(w http.ResponseWriter, r *http.Request) {
	// Get admin context from middleware
	_, ok := GetAdminContext(r)
	if !ok {
		SendError(w, ErrUnauthorized, "Unauthorized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleServerSettingsGet(w, r)
	case http.MethodPost:
		s.handleServerSettingsSave(w, r)
	default:
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
	}
}

// handleServerSettingsGet returns current server settings as JSON
func (s *Server) handleServerSettingsGet(w http.ResponseWriter, r *http.Request) {
	// Build settings from current config
	settings := ServerSettings{
		Port:             s.config.Port,
		Mode:             s.config.Mode,
		FQDN:             s.config.FQDN,
		Address:          s.config.Address,
		Daemonize:        s.config.Daemonize,
		PIDFile:          s.config.PIDFile,
		Title:            s.config.BrandingTitle,
		Tagline:          s.config.BrandingTagline,
		Description:      s.config.BrandingDescription,
		Theme:            s.config.BrandingTheme,
		AccentColor:      s.config.BrandingAccentColor,
		AdminPath:        s.config.AdminPath,
		RateLimitEnabled: s.config.RateLimitEnabled,
		RateLimitReqs:    s.config.RateLimitRequests,
		RateLimitWindow:  s.config.RateLimitWindow,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

// handleServerSettingsSave saves server settings
// POST /api/v1/{admin_path}/server/settings
func (s *Server) handleServerSettingsSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	// Get admin context from middleware
	_, ok := GetAdminContext(r)
	if !ok {
		SendError(w, ErrUnauthorized, "Unauthorized")
		return
	}

	// Parse request body
	var settings ServerSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		SendError(w, ErrValidationFailed, "Invalid request body: "+err.Error())
		return
	}

	// Validate settings
	if err := validateServerSettings(&settings); err != nil {
		SendError(w, ErrValidationFailed, err.Error())
		return
	}

	// Determine which settings require restart
	restartRequired := []string{}
	if settings.Port != s.config.Port {
		restartRequired = append(restartRequired, "port")
	}
	if settings.Mode != s.config.Mode {
		restartRequired = append(restartRequired, "mode")
	}
	if settings.Address != s.config.Address {
		restartRequired = append(restartRequired, "address")
	}
	if settings.Daemonize != s.config.Daemonize {
		restartRequired = append(restartRequired, "daemonize")
	}
	if settings.PIDFile != s.config.PIDFile {
		restartRequired = append(restartRequired, "pidfile")
	}

	// Update in-memory config
	s.config.Port = settings.Port
	s.config.Address = settings.Address
	s.config.Mode = settings.Mode
	s.config.FQDN = settings.FQDN
	s.config.Daemonize = settings.Daemonize
	s.config.PIDFile = settings.PIDFile
	s.config.BrandingTitle = settings.Title
	s.config.BrandingTagline = settings.Tagline
	s.config.BrandingDescription = settings.Description
	s.config.BrandingTheme = settings.Theme
	s.config.BrandingAccentColor = settings.AccentColor
	s.config.RateLimitEnabled = settings.RateLimitEnabled
	s.config.RateLimitRequests = settings.RateLimitReqs
	s.config.RateLimitWindow = settings.RateLimitWindow

	// Persist to server.yml (AI.md PART 6: YAML comments ABOVE, never inline)
	if err := s.config.Save(s.config.ConfigDir); err != nil {
		SendError(w, ErrServerError, "Failed to save configuration: "+err.Error())
		return
	}

	response := map[string]interface{}{
		"success":          true,
		"message":          "Settings saved successfully",
		"restart_required": len(restartRequired) > 0,
		"restart_settings": restartRequired,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// validateServerSettings validates server settings
func validateServerSettings(s *ServerSettings) error {
	// Validate port
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	// Validate mode
	if s.Mode != "production" && s.Mode != "development" {
		return fmt.Errorf("mode must be 'production' or 'development'")
	}

	// Validate FQDN (if provided)
	if s.FQDN != "" {
		if len(s.FQDN) > 255 {
			return fmt.Errorf("FQDN too long (max 255 characters)")
		}
		// Basic FQDN validation
		if strings.Contains(s.FQDN, " ") || strings.Contains(s.FQDN, "..") {
			return fmt.Errorf("invalid FQDN format")
		}
	}

	// Validate address
	if s.Address == "" {
		return fmt.Errorf("address cannot be empty")
	}

	// Validate theme
	validThemes := map[string]bool{"auto": true, "light": true, "dark": true}
	if !validThemes[s.Theme] {
		return fmt.Errorf("theme must be 'auto', 'light', or 'dark'")
	}

	// Validate accent color (hex color)
	if s.AccentColor != "" {
		if !strings.HasPrefix(s.AccentColor, "#") || len(s.AccentColor) != 7 {
			return fmt.Errorf("accent_color must be a hex color (#RRGGBB)")
		}
	}

	// Validate admin path
	if s.AdminPath == "" {
		return fmt.Errorf("admin_path cannot be empty")
	}
	if strings.Contains(s.AdminPath, "/") || strings.Contains(s.AdminPath, " ") {
		return fmt.Errorf("admin_path must not contain slashes or spaces")
	}

	// Validate rate limit
	if s.RateLimitEnabled {
		if s.RateLimitReqs < 1 {
			return fmt.Errorf("rate_limit_requests must be at least 1")
		}
		// Validate window format (e.g., "1m", "60s")
		if s.RateLimitWindow == "" {
			return fmt.Errorf("rate_limit_window cannot be empty when rate limiting enabled")
		}
	}

	return nil
}

// renderServerSettingsHTML generates the server settings page HTML
func renderServerSettingsHTML(adminCtx *AdminContext, cfg *config.ServerConfig) string {
	// Extract current values with defaults
	port := strconv.Itoa(cfg.Port)
	mode := cfg.Mode
	if mode == "" {
		mode = "production"
	}
	fqdn := cfg.FQDN
	if fqdn == "" {
		fqdn = "(auto-detected)"
	}
	address := cfg.Address
	if address == "" {
		address = "[::]"
	}

	title := cfg.BrandingTitle
	if title == "" {
		title = "caswhois"
	}
	tagline := cfg.BrandingTagline
	description := cfg.BrandingDescription
	theme := cfg.BrandingTheme
	if theme == "" {
		theme = "auto"
	}
	accentColor := cfg.BrandingAccentColor
	if accentColor == "" {
		accentColor = "#007bff"
	}

	adminPath := cfg.AdminPath
	if adminPath == "" {
		adminPath = "admin"
	}

	rateLimitEnabled := "checked"
	if !cfg.RateLimitEnabled {
		rateLimitEnabled = ""
	}
	rateLimitReqs := strconv.Itoa(cfg.RateLimitRequests)
	if rateLimitReqs == "0" {
		rateLimitReqs = "120"
	}
	rateLimitWindow := cfg.RateLimitWindow
	if rateLimitWindow == "" {
		rateLimitWindow = "1m"
	}

	daemonizeOn := ""
	daemonizeOff := "checked"
	if cfg.Daemonize {
		daemonizeOn = "checked"
		daemonizeOff = ""
	}

	pidfileOn := "checked"
	pidfileOff := ""
	if !cfg.PIDFile {
		pidfileOn = ""
		pidfileOff = "checked"
	}

	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Settings - ` + title + `</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #1a1a1a;
            color: #e0e0e0;
            line-height: 1.6;
        }
        
        .header {
            background: #2a2a2a;
            border-bottom: 1px solid #3a3a3a;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            font-size: 1.5rem;
            font-weight: 600;
        }
        
        .header .actions {
            display: flex;
            gap: 1rem;
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
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        
        .form-group input[type="text"],
        .form-group input[type="number"],
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 0.75rem;
            background: #1a1a1a;
            border: 1px solid #3a3a3a;
            border-radius: 4px;
            color: #e0e0e0;
            font-size: 1rem;
        }
        
        .form-group textarea {
            resize: vertical;
            min-height: 100px;
        }
        
        .form-group input[type="text"]:focus,
        .form-group input[type="number"]:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: ` + accentColor + `;
        }
        
        .form-hint {
            font-size: 0.875rem;
            color: #888;
            margin-top: 0.25rem;
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }
        
        .restart-warning {
            color: #ff9800;
        }
        
        .toggle-group {
            display: flex;
            gap: 1rem;
        }
        
        .toggle-option {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .toggle-option input[type="radio"] {
            width: 1.25rem;
            height: 1.25rem;
        }
        
        .button {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 4px;
            font-size: 1rem;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .button-primary {
            background: ` + accentColor + `;
            color: white;
        }
        
        .button-primary:hover {
            opacity: 0.9;
        }
        
        .button-secondary {
            background: #3a3a3a;
            color: #e0e0e0;
        }
        
        .button-secondary:hover {
            background: #4a4a4a;
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: 1.25rem;
            height: 1.25rem;
        }
        
        .alert {
            padding: 1rem;
            border-radius: 4px;
            margin-bottom: 1rem;
            display: none;
        }
        
        .alert.success {
            background: #2e7d32;
            border: 1px solid #4caf50;
            color: white;
        }
        
        .alert.error {
            background: #c62828;
            border: 1px solid #f44336;
            color: white;
        }
        
        .alert.warning {
            background: #f57c00;
            border: 1px solid #ff9800;
            color: white;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Server Settings</h1>
        <div class="actions">
            <button class="button button-secondary" onclick="window.location.href='/` + adminPath + `'">Cancel</button>
            <button class="button button-primary" onclick="saveSettings()">Save All</button>
        </div>
    </div>
    
    <div class="container">
        <div id="alert" class="alert"></div>
        
        <div class="section">
            <div class="section-title">General</div>
            
            <div class="form-group">
                <label for="port">Port</label>
                <input type="number" id="port" name="port" value="` + port + `" min="1" max="65535">
                <div class="form-hint">
                    <span>ⓘ The port the server listens on</span>
                    <span class="restart-warning">⚠️ Requires restart</span>
                </div>
            </div>
            
            <div class="form-group">
                <label for="mode">Mode</label>
                <select id="mode" name="mode">
                    <option value="production" ` + func() string { if mode == "production" { return "selected" }; return "" }() + `>Production</option>
                    <option value="development" ` + func() string { if mode == "development" { return "selected" }; return "" }() + `>Development</option>
                </select>
                <div class="form-hint">
                    <span>ⓘ Production enforces strict host validation</span>
                    <span class="restart-warning">⚠️ Requires restart</span>
                </div>
            </div>
            
            <div class="form-group">
                <label for="fqdn">FQDN</label>
                <input type="text" id="fqdn" name="fqdn" value="` + fqdn + `" placeholder="api.example.com">
                <div class="form-hint">ⓘ Fully qualified domain name (leave empty for auto-detection)</div>
            </div>
            
            <div class="form-group">
                <label for="address">Listen Address</label>
                <input type="text" id="address" name="address" value="` + address + `">
                <div class="form-hint">
                    <span>ⓘ Network address to bind to (:: for all IPv6, 0.0.0.0 for all IPv4)</span>
                    <span class="restart-warning">⚠️ Requires restart</span>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">Process</div>
            
            <div class="form-group">
                <label>Daemonize</label>
                <div class="toggle-group">
                    <div class="toggle-option">
                        <input type="radio" id="daemonize-on" name="daemonize" value="true" ` + daemonizeOn + `>
                        <label for="daemonize-on">● On</label>
                    </div>
                    <div class="toggle-option">
                        <input type="radio" id="daemonize-off" name="daemonize" value="false" ` + daemonizeOff + `>
                        <label for="daemonize-off">○ Off</label>
                    </div>
                </div>
                <div class="form-hint">
                    <span>ⓘ Detach from terminal on start (for manual start only)</span>
                    <span class="restart-warning">⚠️ Requires restart. Don't use with systemd/docker.</span>
                </div>
            </div>
            
            <div class="form-group">
                <label>PID File</label>
                <div class="toggle-group">
                    <div class="toggle-option">
                        <input type="radio" id="pidfile-on" name="pidfile" value="true" ` + pidfileOn + `>
                        <label for="pidfile-on">● On</label>
                    </div>
                    <div class="toggle-option">
                        <input type="radio" id="pidfile-off" name="pidfile" value="false" ` + pidfileOff + `>
                        <label for="pidfile-off">○ Off</label>
                    </div>
                </div>
                <div class="form-hint">
                    <span>ⓘ Create PID file for process management</span>
                    <span class="restart-warning">⚠️ Requires restart</span>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">Branding</div>
            
            <div class="form-group">
                <label for="title">Application Title</label>
                <input type="text" id="title" name="title" value="` + title + `">
                <div class="form-hint">ⓘ Display name for your application</div>
            </div>
            
            <div class="form-group">
                <label for="tagline">Tagline</label>
                <input type="text" id="tagline" name="tagline" value="` + tagline + `" placeholder="A powerful WHOIS lookup service">
                <div class="form-hint">ⓘ Short slogan (optional)</div>
            </div>
            
            <div class="form-group">
                <label for="description">Description</label>
                <textarea id="description" name="description" placeholder="Detailed description for SEO and about pages">` + description + `</textarea>
                <div class="form-hint">ⓘ Longer description for SEO and about pages</div>
            </div>
            
            <div class="form-group">
                <label for="theme">Theme</label>
                <select id="theme" name="theme">
                    <option value="auto" ` + func() string { if theme == "auto" { return "selected" }; return "" }() + `>Auto (System)</option>
                    <option value="light" ` + func() string { if theme == "light" { return "selected" }; return "" }() + `>Light</option>
                    <option value="dark" ` + func() string { if theme == "dark" { return "selected" }; return "" }() + `>Dark</option>
                </select>
                <div class="form-hint">ⓘ Default theme for the application</div>
            </div>
            
            <div class="form-group">
                <label for="accent_color">Accent Color</label>
                <input type="text" id="accent_color" name="accent_color" value="` + accentColor + `" placeholder="#007bff">
                <div class="form-hint">ⓘ Primary accent color (hex format: #RRGGBB)</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">Security</div>
            
            <div class="form-group">
                <label for="admin_path">Admin Panel Path</label>
                <input type="text" id="admin_path" name="admin_path" value="` + adminPath + `">
                <div class="form-hint">
                    <span>ⓘ Custom path for admin panel (no slashes)</span>
                    <span class="restart-warning">⚠️ Requires reload</span>
                </div>
            </div>
            
            <div class="form-group">
                <label class="checkbox-group">
                    <input type="checkbox" id="rate_limit_enabled" name="rate_limit_enabled" ` + rateLimitEnabled + `>
                    Enable Rate Limiting
                </label>
                <div class="form-hint">ⓘ Limit requests per IP address</div>
            </div>
            
            <div class="form-group">
                <label for="rate_limit_requests">Rate Limit - Requests</label>
                <input type="number" id="rate_limit_requests" name="rate_limit_requests" value="` + rateLimitReqs + `" min="1">
                <div class="form-hint">ⓘ Maximum requests per window</div>
            </div>
            
            <div class="form-group">
                <label for="rate_limit_window">Rate Limit - Window</label>
                <input type="text" id="rate_limit_window" name="rate_limit_window" value="` + rateLimitWindow + `" placeholder="1m">
                <div class="form-hint">ⓘ Time window (e.g., 1m, 60s, 1h)</div>
            </div>
        </div>
        
        <div class="section">
            <div style="display: flex; justify-content: flex-end; gap: 1rem;">
                <button class="button button-secondary" onclick="window.location.href='/` + adminPath + `'">Cancel</button>
                <button class="button button-primary" onclick="saveSettings()">Save Settings</button>
            </div>
        </div>
    </div>
    
    <script>
        function showAlert(message, type) {
            const alert = document.getElementById('alert');
            alert.className = 'alert ' + type;
            alert.textContent = message;
            alert.style.display = 'block';
            
            if (type === 'success') {
                setTimeout(() => {
                    alert.style.display = 'none';
                }, 5000);
            }
            
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
        
        function saveSettings() {
            const settings = {
                port: parseInt(document.getElementById('port').value),
                mode: document.getElementById('mode').value,
                fqdn: document.getElementById('fqdn').value,
                address: document.getElementById('address').value,
                daemonize: document.querySelector('input[name="daemonize"]:checked').value === 'true',
                pidfile: document.querySelector('input[name="pidfile"]:checked').value === 'true',
                title: document.getElementById('title').value,
                tagline: document.getElementById('tagline').value,
                description: document.getElementById('description').value,
                theme: document.getElementById('theme').value,
                accent_color: document.getElementById('accent_color').value,
                admin_path: document.getElementById('admin_path').value,
                rate_limit_enabled: document.getElementById('rate_limit_enabled').checked,
                rate_limit_requests: parseInt(document.getElementById('rate_limit_requests').value),
                rate_limit_window: document.getElementById('rate_limit_window').value
            };
            
            fetch('/api/v1/` + adminPath + `/server/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(settings)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    let message = data.message;
                    if (data.restart_required) {
                        message += ' ⚠️  Server restart required for: ' + data.restart_settings.join(', ');
                        showAlert(message, 'warning');
                    } else {
                        showAlert(message, 'success');
                    }
                } else {
                    showAlert('Error: ' + (data.message || 'Unknown error'), 'error');
                }
            })
            .catch(error => {
                showAlert('Error saving settings: ' + error.message, 'error');
            });
        }
    </script>
</body>
</html>`
}
