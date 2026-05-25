package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/casapps/caswhois/src/admin"
)

// ProfileInfo represents admin profile information
type ProfileInfo struct {
	ID        int64  `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	IsSuper   bool   `json:"is_super"`
	CreatedAt string `json:"created_at"`
}

// ProfileUpdateRequest represents a profile update request
type ProfileUpdateRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// PasswordChangeRequest represents a password change request
type PasswordChangeRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// handleAdminProfile serves the admin profile page
// GET /{admin_path}/profile
func (s *Server) handleAdminProfile(w http.ResponseWriter, r *http.Request) {
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

	html := renderAdminProfileHTML(adminCtx, s.config.AdminPath)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// handleAdminProfileAPI handles GET for admin profile API
// GET /api/v1/{admin_path}/profile
func (s *Server) handleAdminProfileAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	// Get admin context from middleware
	adminCtx, ok := GetAdminContext(r)
	if !ok {
		SendError(w, ErrUnauthorized, "Unauthorized")
		return
	}

	// Build profile info
	profile := ProfileInfo{
		ID:        adminCtx.Admin.ID,
		Email:     adminCtx.Admin.Email,
		Name:      adminCtx.Admin.Name,
		IsSuper:   adminCtx.Admin.IsSuper,
		CreatedAt: adminCtx.Admin.CreatedAt.Format("2006-01-02"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

// handleAdminProfileUpdate handles PATCH for updating profile
// PATCH /api/v1/{admin_path}/profile
func (s *Server) handleAdminProfileUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch && r.Method != http.MethodPost {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	// Get admin context from middleware
	adminCtx, ok := GetAdminContext(r)
	if !ok {
		SendError(w, ErrUnauthorized, "Unauthorized")
		return
	}

	// Parse request body
	var req ProfileUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, ErrValidationFailed, "Invalid request body: "+err.Error())
		return
	}

	// Update profile
	err := admin.UpdateAdminProfile(r.Context(), s.database, adminCtx.Admin.ID, req.Name, req.Email)
	if err != nil {
		SendError(w, ErrValidationFailed, err.Error())
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "Profile updated successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAdminPasswordChange handles POST for changing password
// POST /api/v1/{admin_path}/profile/password
func (s *Server) handleAdminPasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	// Get admin context from middleware
	adminCtx, ok := GetAdminContext(r)
	if !ok {
		SendError(w, ErrUnauthorized, "Unauthorized")
		return
	}

	// Parse request body
	var req PasswordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, ErrValidationFailed, "Invalid request body: "+err.Error())
		return
	}

	// Update password
	err := admin.UpdateAdminPassword(r.Context(), s.database, adminCtx.Admin.ID, req.OldPassword, req.NewPassword)
	if err != nil {
		SendError(w, ErrValidationFailed, err.Error())
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "Password changed successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAdminAPIToken handles GET for viewing API token (masked)
// GET /api/v1/{admin_path}/profile/token
func (s *Server) handleAdminAPIToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	// Get admin context from middleware
	adminCtx, ok := GetAdminContext(r)
	if !ok {
		SendError(w, ErrUnauthorized, "Unauthorized")
		return
	}

	// Get masked token
	maskedToken, err := admin.GetAdminAPIToken(r.Context(), s.database, adminCtx.Admin.ID)
	if err != nil {
		SendError(w, ErrServerError, err.Error())
		return
	}

	response := map[string]interface{}{
		"token": maskedToken,
		"note":  "Only first 8 and last 4 characters shown. Full token cannot be retrieved.",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAdminAPITokenRegenerate handles POST for regenerating API token
// POST /api/v1/{admin_path}/profile/token
func (s *Server) handleAdminAPITokenRegenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	// Get admin context from middleware
	adminCtx, ok := GetAdminContext(r)
	if !ok {
		SendError(w, ErrUnauthorized, "Unauthorized")
		return
	}

	// Regenerate token
	newToken, err := admin.RegenerateAdminAPIToken(r.Context(), s.database, adminCtx.Admin.ID)
	if err != nil {
		SendError(w, ErrServerError, err.Error())
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "API token regenerated successfully",
		"token":   newToken,
		"warning": "Save this token now. It will only be shown once and cannot be retrieved again.",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// renderAdminProfileHTML generates the admin profile page HTML
func renderAdminProfileHTML(adminCtx *AdminContext, adminPath string) string {
	// Basic profile page - can be expanded later
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile - Admin Panel</title>
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
        .form-group {
            margin-bottom: 1.5rem;
        }
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        .form-group input {
            width: 100%%;
            padding: 0.75rem;
            background: #1a1a1a;
            border: 1px solid #3a3a3a;
            border-radius: 4px;
            color: #e0e0e0;
            font-size: 1rem;
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
        }
        .alert {
            padding: 1rem;
            border-radius: 4px;
            margin-bottom: 1rem;
            display: none;
        }
        .alert.success { background: #2e7d32; color: white; }
        .alert.error { background: #c62828; color: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Admin Profile</h1>
    </div>
    <div class="container">
        <div id="alert" class="alert"></div>
        
        <div class="section">
            <div class="section-title">Profile Information</div>
            <div class="form-group">
                <label>Email</label>
                <input type="email" id="email" value="%s">
            </div>
            <div class="form-group">
                <label>Name</label>
                <input type="text" id="name" value="%s">
            </div>
            <button class="button button-primary" onclick="updateProfile()">Update Profile</button>
        </div>
        
        <div class="section">
            <div class="section-title">Change Password</div>
            <div class="form-group">
                <label>Current Password</label>
                <input type="password" id="old_password">
            </div>
            <div class="form-group">
                <label>New Password</label>
                <input type="password" id="new_password">
            </div>
            <button class="button button-primary" onclick="changePassword()">Change Password</button>
        </div>
        
        <div class="section">
            <div class="section-title">API Token</div>
            <p>Current token: <span id="token">Loading...</span></p>
            <button class="button button-secondary" onclick="regenerateToken()">Regenerate Token</button>
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
        
        async function updateProfile() {
            const res = await fetch('/api/v1/%s/profile', {
                method: 'PATCH',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    name: document.getElementById('name').value,
                    email: document.getElementById('email').value
                })
            });
            const data = await res.json();
            showAlert(data.message || 'Profile updated', data.success ? 'success' : 'error');
        }
        
        async function changePassword() {
            const res = await fetch('/api/v1/%s/profile/password', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    old_password: document.getElementById('old_password').value,
                    new_password: document.getElementById('new_password').value
                })
            });
            const data = await res.json();
            showAlert(data.message || 'Password changed', data.success ? 'success' : 'error');
            if(data.success) {
                document.getElementById('old_password').value = '';
                document.getElementById('new_password').value = '';
            }
        }
        
        async function regenerateToken() {
            if(!confirm('Regenerate API token? Old token will be revoked.')) return;
            const res = await fetch('/api/v1/%s/profile/token', {
                method: 'POST'
            });
            const data = await res.json();
            if(data.success) {
                showAlert('Token: ' + data.token + ' (save it now!)', 'success');
                loadToken();
            } else {
                showAlert('Failed to regenerate token', 'error');
            }
        }
        
        async function loadToken() {
            const res = await fetch('/api/v1/%s/profile/token');
            const data = await res.json();
            document.getElementById('token').textContent = data.token || 'None';
        }
        
        loadToken();
    </script>
</body>
</html>`, adminCtx.Admin.Email, adminCtx.Admin.Name, adminPath, adminPath, adminPath, adminPath)
}
