package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/casapps/caswhois/src/admin"
	"github.com/casapps/caswhois/src/security"
)

// handleAdminSetupStatus returns setup status
// GET /api/v1/{admin_path}/server/setup
func (s *Server) handleAdminSetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Check if this is first run
	isFirstRun, err := admin.IsFirstRun(ctx, s.database)
	if err != nil {
		log.Printf("Error checking first run: %v", err)
		SendError(w, ErrServerError, "Failed to check setup status")
		return
	}

	// Check if admins exist
	hasAdmins, err := admin.HasAdmins(ctx, s.database)
	if err != nil {
		log.Printf("Error checking admins: %v", err)
		SendError(w, ErrServerError, "Failed to check admin status")
		return
	}

	data := map[string]interface{}{
		"is_first_run":    isFirstRun,
		"setup_required":  isFirstRun,
		"has_admins":      hasAdmins,
		"setup_complete":  hasAdmins,
	}

	SendSuccess(w, data)
}

// SetupTokenRequest for token verification
type SetupTokenRequest struct {
	Token string `json:"token"`
}

// handleAdminSetupVerify verifies the setup token
// POST /api/v1/{admin_path}/server/setup/verify
func (s *Server) handleAdminSetupVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse request
	var req SetupTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, ErrBadRequest, "Invalid request body")
		return
	}

	// Validate token format (32 hex chars)
	if len(req.Token) != 32 {
		SendError(w, ErrValidationFailed, "Invalid token format")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get stored token hash
	storedHash, err := admin.GetSetupToken(ctx, s.database)
	if err != nil {
		log.Printf("Error getting setup token: %v", err)
		SendError(w, ErrUnauthorized, "Invalid setup token")
		return
	}

	// Hash provided token and verify
	providedHash := security.HashToken(req.Token)
	if !security.VerifyToken(req.Token, storedHash) {
		SendError(w, ErrUnauthorized, "Invalid setup token")
		return
	}

	// Token is valid
	data := map[string]interface{}{
		"valid":        true,
		"token_hash":   providedHash,
		"message":      "Setup token verified successfully",
	}

	SendSuccess(w, data)
}

// CreateAdminAccountRequest for admin account creation
type CreateAdminAccountRequest struct {
	SetupToken string `json:"setup_token"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	Name       string `json:"name"`
}

// handleAdminSetupAccount creates the first admin account
// POST /api/v1/{admin_path}/server/setup/account
func (s *Server) handleAdminSetupAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse request
	var req CreateAdminAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, ErrBadRequest, "Invalid request body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Verify setup token first
	storedHash, err := admin.GetSetupToken(ctx, s.database)
	if err != nil {
		log.Printf("Error getting setup token: %v", err)
		SendError(w, ErrUnauthorized, "Invalid setup token")
		return
	}

	if !security.VerifyToken(req.SetupToken, storedHash) {
		SendError(w, ErrUnauthorized, "Invalid setup token")
		return
	}

	// Validate input
	req.Email = strings.TrimSpace(req.Email)
	req.Name = strings.TrimSpace(req.Name)

	if req.Email == "" {
		SendError(w, ErrValidationFailed, "Email is required")
		return
	}

	if !strings.Contains(req.Email, "@") {
		SendError(w, ErrValidationFailed, "Invalid email format")
		return
	}

	if req.Password == "" {
		SendError(w, ErrValidationFailed, "Password is required")
		return
	}

	if len(req.Password) < 8 {
		SendError(w, ErrValidationFailed, "Password must be at least 8 characters")
		return
	}

	if req.Name == "" {
		req.Name = "Administrator"
	}

	// Create admin account
	adminReq := admin.CreateAdminRequest{
		Email:    req.Email,
		Password: req.Password,
		Name:     req.Name,
		IsSuper:  true, // First admin is always super admin
	}

	createdAdmin, err := admin.CreateAdmin(ctx, s.database, adminReq)
	if err != nil {
		log.Printf("Error creating admin: %v", err)
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "UNIQUE") {
			SendError(w, ErrConflict, "Admin account already exists")
			return
		}
		SendError(w, ErrServerError, "Failed to create admin account")
		return
	}

	// Invalidate setup token (one-time use)
	if err := admin.InvalidateSetupToken(ctx, s.database); err != nil {
		log.Printf("Error invalidating setup token: %v", err)
		// Don't fail the request, admin was created successfully
	}

	// Generate API token for the admin
	apiToken, err := security.GenerateToken("adm")
	if err != nil {
		log.Printf("Error generating API token: %v", err)
		SendError(w, ErrServerError, "Admin created but failed to generate API token")
		return
	}

	// Store API token hash in database
	tokenHash := security.HashToken(apiToken)
	expiresAt := time.Now().Add(365 * 24 * time.Hour) // 1 year expiry

	_, err = s.database.Users.ExecContext(ctx,
		`INSERT INTO usr_api_keys (admin_id, token_hash, name, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		createdAdmin.ID, tokenHash, "Default API Token", expiresAt, time.Now())

	if err != nil {
		log.Printf("Error storing API token: %v", err)
		// Don't fail - admin account was created successfully
	}

	log.Printf("Admin account created successfully: %s (ID: %d)", createdAdmin.Email, createdAdmin.ID)

	data := map[string]interface{}{
		"success":    true,
		"admin_id":   createdAdmin.ID,
		"email":      createdAdmin.Email,
		"name":       createdAdmin.Name,
		"api_token":  apiToken,
		"message":    "Admin account created successfully",
		"note":       "Save the API token - it will not be shown again",
	}

	SendSuccess(w, data)
}

// handleAdminSetupComplete marks setup as complete
// POST /api/v1/{admin_path}/server/setup/complete
func (s *Server) handleAdminSetupComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Check if admins exist
	hasAdmins, err := admin.HasAdmins(ctx, s.database)
	if err != nil {
		log.Printf("Error checking admins: %v", err)
		SendError(w, ErrServerError, "Failed to verify setup")
		return
	}

	if !hasAdmins {
		SendError(w, ErrBadRequest, "Setup not complete - no admin accounts")
		return
	}

	// Ensure setup token is invalidated
	if err := admin.InvalidateSetupToken(ctx, s.database); err != nil {
		log.Printf("Error invalidating setup token: %v", err)
		// Continue anyway
	}

	data := map[string]interface{}{
		"success": true,
		"message": "Setup completed successfully",
	}

	SendSuccess(w, data)
}

// handleAdminSetupPage serves the setup wizard HTML page
// GET /{admin_path}/server/setup
func (s *Server) handleAdminSetupPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Check if setup is still needed
	isFirstRun, err := admin.IsFirstRun(ctx, s.database)
	if err != nil {
		log.Printf("Error checking first run: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if !isFirstRun {
		// Setup already complete, redirect to admin login
		adminPath := s.config.AdminPath
		if adminPath == "" {
			adminPath = "admin"
		}
		http.Redirect(w, r, fmt.Sprintf("/%s", adminPath), http.StatusFound)
		return
	}

	// Serve setup wizard HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	// Inline HTML for setup wizard (will move to templates later)
	html := s.renderSetupWizardHTML()
	fmt.Fprint(w, html)
}

// renderSetupWizardHTML returns the setup wizard HTML
func (s *Server) renderSetupWizardHTML() string {
	adminPath := s.config.AdminPath
	if adminPath == "" {
		adminPath = "admin"
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" class="theme-dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Setup Wizard - CASWHOIS</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
            padding: 2rem;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 2rem;
        }
        h1 {
            color: #58a6ff;
            margin-bottom: 0.5rem;
            font-size: 2rem;
        }
        .subtitle {
            color: #8b949e;
            margin-bottom: 2rem;
        }
        .step {
            display: none;
            animation: fadeIn 0.3s;
        }
        .step.active {
            display: block;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            color: #c9d1d9;
            font-weight: 500;
        }
        input[type="text"],
        input[type="email"],
        input[type="password"] {
            width: 100%%;
            padding: 0.75rem;
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            color: #c9d1d9;
            font-size: 1rem;
        }
        input:focus {
            outline: none;
            border-color: #58a6ff;
        }
        .btn {
            padding: 0.75rem 1.5rem;
            background: #238636;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            cursor: pointer;
            font-weight: 500;
        }
        .btn:hover {
            background: #2ea043;
        }
        .btn:disabled {
            background: #30363d;
            cursor: not-allowed;
        }
        .btn-secondary {
            background: #21262d;
            margin-left: 0.5rem;
        }
        .btn-secondary:hover {
            background: #30363d;
        }
        .error {
            background: #da3633;
            color: white;
            padding: 0.75rem;
            border-radius: 6px;
            margin-bottom: 1rem;
        }
        .success {
            background: #238636;
            color: white;
            padding: 0.75rem;
            border-radius: 6px;
            margin-bottom: 1rem;
        }
        .info {
            background: #1f6feb;
            color: white;
            padding: 0.75rem;
            border-radius: 6px;
            margin-bottom: 1rem;
        }
        .token-display {
            background: #0d1117;
            border: 1px solid #30363d;
            padding: 1rem;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 1.1rem;
            margin: 1rem 0;
            word-break: break-all;
        }
        .note {
            color: #8b949e;
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔧 Setup Wizard</h1>
        <p class="subtitle">Welcome to CASWHOIS - Let's get you set up</p>

        <div id="error-message" class="error" style="display: none;"></div>
        <div id="success-message" class="success" style="display: none;"></div>

        <!-- Step 1: Setup Token -->
        <div id="step-1" class="step active">
            <h2>Step 1: Verify Setup Token</h2>
            <p class="note">Enter the setup token displayed in your server console.</p>
            
            <div class="form-group">
                <label for="setup-token">Setup Token</label>
                <input type="text" id="setup-token" placeholder="32-character hex token" maxlength="32">
            </div>

            <button class="btn" onclick="verifyToken()">Verify Token</button>
        </div>

        <!-- Step 2: Create Admin Account -->
        <div id="step-2" class="step">
            <h2>Step 2: Create Admin Account</h2>
            <p class="note">This will be your primary administrator account.</p>

            <div class="form-group">
                <label for="admin-email">Email Address</label>
                <input type="email" id="admin-email" placeholder="admin@example.com" required>
            </div>

            <div class="form-group">
                <label for="admin-password">Password</label>
                <input type="password" id="admin-password" placeholder="Minimum 8 characters" required>
            </div>

            <div class="form-group">
                <label for="admin-name">Full Name</label>
                <input type="text" id="admin-name" placeholder="Administrator" value="Administrator">
            </div>

            <button class="btn" onclick="createAdmin()">Create Admin Account</button>
            <button class="btn btn-secondary" onclick="showStep(1)">Back</button>
        </div>

        <!-- Step 3: Complete -->
        <div id="step-3" class="step">
            <h2>✅ Setup Complete!</h2>
            <p class="note">Your admin account has been created successfully.</p>

            <div class="info">
                <strong>Admin Email:</strong> <span id="created-email"></span><br>
                <strong>Admin Name:</strong> <span id="created-name"></span>
            </div>

            <h3>API Token</h3>
            <p class="note">Save this token - it will not be shown again!</p>
            <div class="token-display" id="api-token-display"></div>

            <button class="btn" onclick="finishSetup()">Go to Admin Panel</button>
        </div>
    </div>

    <script>
        let setupToken = '';
        let apiToken = '';

        function showError(message) {
            const errorDiv = document.getElementById('error-message');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            setTimeout(() => {
                errorDiv.style.display = 'none';
            }, 5000);
        }

        function showSuccess(message) {
            const successDiv = document.getElementById('success-message');
            successDiv.textContent = message;
            successDiv.style.display = 'block';
            setTimeout(() => {
                successDiv.style.display = 'none';
            }, 5000);
        }

        function showStep(step) {
            document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
            document.getElementById('step-' + step).classList.add('active');
        }

        async function verifyToken() {
            const token = document.getElementById('setup-token').value.trim();
            
            if (!token || token.length !== 32) {
                showError('Please enter a valid 32-character token');
                return;
            }

            try {
                const response = await fetch('/api/v1/%s/server/setup/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token: token })
                });

                const data = await response.json();

                if (data.ok) {
                    setupToken = token;
                    showSuccess('Token verified successfully!');
                    showStep(2);
                } else {
                    showError(data.error || 'Invalid setup token');
                }
            } catch (error) {
                showError('Failed to verify token: ' + error.message);
            }
        }

        async function createAdmin() {
            const email = document.getElementById('admin-email').value.trim();
            const password = document.getElementById('admin-password').value;
            const name = document.getElementById('admin-name').value.trim();

            if (!email || !password) {
                showError('Email and password are required');
                return;
            }

            if (password.length < 8) {
                showError('Password must be at least 8 characters');
                return;
            }

            try {
                const response = await fetch('/api/v1/%s/server/setup/account', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        setup_token: setupToken,
                        email: email,
                        password: password,
                        name: name || 'Administrator'
                    })
                });

                const data = await response.json();

                if (data.ok) {
                    apiToken = data.data.api_token;
                    document.getElementById('created-email').textContent = data.data.email;
                    document.getElementById('created-name').textContent = data.data.name;
                    document.getElementById('api-token-display').textContent = apiToken;
                    showStep(3);
                } else {
                    showError(data.error || 'Failed to create admin account');
                }
            } catch (error) {
                showError('Failed to create admin: ' + error.message);
            }
        }

        async function finishSetup() {
            try {
                await fetch('/api/v1/%s/server/setup/complete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });

                window.location.href = '/%s';
            } catch (error) {
                // Redirect anyway
                window.location.href = '/%s';
            }
        }
    </script>
</body>
</html>`, adminPath, adminPath, adminPath, adminPath, adminPath, adminPath)
}
