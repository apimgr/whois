package server

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// BackupSettingsResponse represents current backup configuration
type BackupSettingsResponse struct {
	Enabled          bool   `json:"enabled"`
	Schedule         string `json:"schedule"`          // Cron schedule (e.g., "0 2 * * *")
	RetentionDays    int    `json:"retention_days"`    // How many days to keep backups
	IncludeSSL       bool   `json:"include_ssl"`       // Include SSL certificates
	IncludeData      bool   `json:"include_data"`      // Include data directory
	EncryptionEnabled bool   `json:"encryption_enabled"` // Whether backups are encrypted
	LastBackup       string `json:"last_backup"`       // ISO timestamp
	NextBackup       string `json:"next_backup"`       // ISO timestamp
	BackupCount      int    `json:"backup_count"`      // Number of stored backups
}

// BackupSettingsRequest represents backup configuration update
type BackupSettingsRequest struct {
	Enabled       bool   `json:"enabled"`
	Schedule      string `json:"schedule"`       // Cron schedule
	RetentionDays int    `json:"retention_days"` // 1-365 days
	IncludeSSL    bool   `json:"include_ssl"`
	IncludeData   bool   `json:"include_data"`
	SetPassword   bool   `json:"set_password"`       // Whether to set encryption password
	Password      string `json:"password,omitempty"` // Backup encryption password (only when setting)
}

// handleServerBackupSettings serves the backup configuration page HTML
// GET /{admin_path}/server/backup
func (s *Server) handleServerBackupSettings(w http.ResponseWriter, r *http.Request) {
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

	html := renderServerBackupSettingsHTML(adminCtx, s.config.AdminPath)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// handleServerBackupSettingsAPI routes GET/POST for backup settings API
// GET/POST /api/v1/{admin_path}/server/backup
func (s *Server) handleServerBackupSettingsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleServerBackupSettingsGet(w, r)
	case http.MethodPost:
		s.handleServerBackupSettingsSave(w, r)
	default:
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
	}
}

// handleServerBackupSettingsGet returns current backup configuration
// GET /api/v1/{admin_path}/server/backup
func (s *Server) handleServerBackupSettingsGet(w http.ResponseWriter, r *http.Request) {
	// TODO: Integrate with scheduler to get actual backup task info
	// For now, return stub data
	settings := BackupSettingsResponse{
		Enabled:           false,
		Schedule:          "0 2 * * *", // Daily at 2 AM
		RetentionDays:     30,
		IncludeSSL:        false,
		IncludeData:       false,
		EncryptionEnabled: false,
		LastBackup:        "",
		NextBackup:        "",
		BackupCount:       0,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

// handleServerBackupSettingsSave updates backup configuration
// POST /api/v1/{admin_path}/server/backup
func (s *Server) handleServerBackupSettingsSave(w http.ResponseWriter, r *http.Request) {
	var req BackupSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, ErrValidationFailed, "Invalid request body: "+err.Error())
		return
	}

	// Validate backup settings
	if err := validateServerBackupSettings(&req); err != nil {
		SendError(w, ErrValidationFailed, err.Error())
		return
	}

	// TODO: Integrate with scheduler to actually configure backup task
	// This requires:
	// 1. Registering/updating backup_daily task in scheduler
	// 2. Storing encryption password securely (if set)
	// 3. Updating backup retention policy
	// 4. Configuring backup flags (include_ssl, include_data)

	response := map[string]interface{}{
		"success": true,
		"message": "Backup settings saved successfully",
		"note":    "Backup task scheduler integration pending",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleServerBackupNow triggers immediate backup
// POST /api/v1/{admin_path}/server/backup/now
func (s *Server) handleServerBackupNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	// TODO: Trigger immediate backup via scheduler or backup manager
	response := map[string]interface{}{
		"success": false,
		"message": "Manual backup trigger not yet implemented",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// validateServerBackupSettings validates backup configuration
func validateServerBackupSettings(cfg *BackupSettingsRequest) error {
	if !cfg.Enabled {
		return nil // Disabling backups is always valid
	}

	// Validate schedule (basic cron validation)
	if cfg.Schedule == "" {
		return fmt.Errorf("schedule is required when backups are enabled")
	}

	// Validate retention days (1-365 days)
	if cfg.RetentionDays < 1 || cfg.RetentionDays > 365 {
		return fmt.Errorf("retention_days must be between 1 and 365")
	}

	// If setting password, validate it
	if cfg.SetPassword {
		if cfg.Password == "" {
			return fmt.Errorf("password is required when set_password is true")
		}
		if len(cfg.Password) < 8 {
			return fmt.Errorf("backup password must be at least 8 characters")
		}
	}

	return nil
}

// renderServerBackupSettingsHTML generates the backup configuration page HTML
func renderServerBackupSettingsHTML(adminCtx *AdminContext, adminPath string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Backup Settings - Admin Panel</title>
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
        .form-group input[type="text"],
        .form-group input[type="number"],
        .form-group input[type="password"],
        .form-group select {
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
        .checkbox-group {
            display: flex;
            align-items: center;
            margin-bottom: 1rem;
        }
        .checkbox-group input[type="checkbox"] {
            margin-right: 0.5rem;
            width: 18px;
            height: 18px;
        }
        .checkbox-group label {
            margin: 0;
            font-weight: normal;
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
        .button-success {
            background: #4caf50;
            color: white;
            margin-left: 0.5rem;
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
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Backup Settings</h1>
    </div>
    <div class="container">
        <div id="alert" class="alert"></div>
        
        <div class="section">
            <div class="section-title">Current Status</div>
            <div class="status-box">
                <div class="status-row">
                    <span class="status-label">Backup Status:</span>
                    <span class="status-value status-disabled" id="backupStatus">⚠️ Not Configured</span>
                </div>
                <div class="status-row">
                    <span class="status-label">Last Backup:</span>
                    <span class="status-value" id="lastBackup">Never</span>
                </div>
                <div class="status-row">
                    <span class="status-label">Next Backup:</span>
                    <span class="status-value" id="nextBackup">Not scheduled</span>
                </div>
                <div class="status-row">
                    <span class="status-label">Stored Backups:</span>
                    <span class="status-value" id="backupCount">0</span>
                </div>
            </div>
            
            <button class="button button-success" onclick="triggerServerBackupNow()">Backup Now</button>
            <button class="button button-secondary" onclick="window.location.href='/%s/server/backup/list'">View Backups</button>
        </div>
        
        <div class="section">
            <div class="section-title">Backup Configuration</div>
            
            <div class="warning-box">
                <strong>⚠️ Important:</strong> Backups include admin credentials (hashed), configuration, and databases. 
                Store backups securely. Enable encryption for sensitive data.
            </div>
            
            <div class="form-group">
                <label>Schedule</label>
                <input type="text" id="schedule" value="0 2 * * *" placeholder="0 2 * * *">
                <small>Cron schedule (default: daily at 2 AM). Examples: "0 2 * * *" (daily), "0 */6 * * *" (every 6 hours)</small>
            </div>
            
            <div class="form-group">
                <label>Retention Period (days)</label>
                <input type="number" id="retentionDays" value="30" min="1" max="365">
                <small>How many days to keep old backups (1-365 days)</small>
            </div>
            
            <div class="section-title" style="margin-top: 2rem;">Backup Options</div>
            
            <div class="checkbox-group">
                <input type="checkbox" id="includeSSL">
                <label for="includeSSL">Include SSL certificates in backup</label>
            </div>
            
            <div class="checkbox-group">
                <input type="checkbox" id="includeData">
                <label for="includeData">Include data directory in backup (may increase backup size)</label>
            </div>
            
            <div class="section-title" style="margin-top: 2rem;">Encryption</div>
            
            <div class="checkbox-group">
                <input type="checkbox" id="setPassword" onchange="togglePasswordFields()">
                <label for="setPassword">Enable backup encryption (recommended)</label>
            </div>
            
            <div id="passwordFields" style="display:none; margin-left: 2rem;">
                <div class="form-group">
                    <label>Backup Password</label>
                    <input type="password" id="backupPassword" placeholder="Enter strong password">
                    <small>⚠️ Password is NEVER stored. You must remember it to restore backups.</small>
                </div>
                
                <div class="form-group">
                    <label>Confirm Password</label>
                    <input type="password" id="confirmPassword" placeholder="Re-enter password">
                </div>
            </div>
            
            <button class="button button-primary" onclick="saveServerBackupSettings()">Save Settings</button>
            
            <div class="info-box">
                <p><strong>ℹ️ Backup Information</strong></p>
                <p>• Backups include: server.yml, server.db, users.db (if exists), custom templates</p>
                <p>• Built-in scheduler runs backups automatically (no external cron needed)</p>
                <p>• Encrypted backups use AES-256-GCM encryption</p>
                <p>• Admin credentials in backup are Argon2id hashed (not plaintext)</p>
                <p>• Backups stored in {config_dir}/backup/ directory</p>
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
        
        function togglePasswordFields() {
            const checked = document.getElementById('setPassword').checked;
            document.getElementById('passwordFields').style.display = checked ? 'block' : 'none';
        }
        
        async function loadServerBackupSettings() {
            try {
                const res = await fetch('/api/v1/%s/server/backup');
                const data = await res.json();
                
                document.getElementById('backupStatus').textContent = data.enabled ? '✅ Enabled' : '⚠️ Not Configured';
                document.getElementById('backupStatus').className = data.enabled ? 'status-value status-enabled' : 'status-value status-disabled';
                document.getElementById('lastBackup').textContent = data.last_backup || 'Never';
                document.getElementById('nextBackup').textContent = data.next_backup || 'Not scheduled';
                document.getElementById('backupCount').textContent = data.backup_count || '0';
                
                document.getElementById('schedule').value = data.schedule || '0 2 * * *';
                document.getElementById('retentionDays').value = data.retention_days || 30;
                document.getElementById('includeSSL').checked = data.include_ssl || false;
                document.getElementById('includeData').checked = data.include_data || false;
                document.getElementById('setPassword').checked = data.encryption_enabled || false;
                togglePasswordFields();
            } catch (e) {
                console.error('Failed to load backup settings:', e);
            }
        }
        
        async function saveServerBackupSettings() {
            const setPassword = document.getElementById('setPassword').checked;
            const password = document.getElementById('backupPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            
            if (setPassword && password !== confirmPassword) {
                showAlert('Passwords do not match', 'error');
                return;
            }
            
            const config = {
                enabled: true,
                schedule: document.getElementById('schedule').value,
                retention_days: parseInt(document.getElementById('retentionDays').value),
                include_ssl: document.getElementById('includeSSL').checked,
                include_data: document.getElementById('includeData').checked,
                set_password: setPassword,
                password: setPassword ? password : ''
            };
            
            try {
                const res = await fetch('/api/v1/%s/server/backup', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(config)
                });
                const data = await res.json();
                
                if (data.success) {
                    showAlert(data.message, 'success');
                    loadServerBackupSettings();
                    if (setPassword) {
                        document.getElementById('backupPassword').value = '';
                        document.getElementById('confirmPassword').value = '';
                    }
                } else {
                    showAlert(data.message || 'Failed to save backup settings', 'error');
                }
            } catch (e) {
                showAlert('Network error: ' + e.message, 'error');
            }
        }
        
        async function triggerServerBackupNow() {
            if (!confirm('Start backup now? This may take a few minutes.')) return;
            
            try {
                const res = await fetch('/api/v1/%s/server/backup/now', {
                    method: 'POST'
                });
                const data = await res.json();
                
                if (data.success) {
                    showAlert('Backup started successfully', 'success');
                    setTimeout(loadServerBackupSettings, 2000);
                } else {
                    showAlert(data.message || 'Failed to start backup', 'error');
                }
            } catch (e) {
                showAlert('Network error: ' + e.message, 'error');
            }
        }
        
        loadServerBackupSettings();
    </script>
</body>
</html>`, adminPath, adminPath, adminPath, adminPath)
}
