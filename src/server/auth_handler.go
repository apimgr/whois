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
)

const (
	// Session cookie name per AI.md PART 17
	AdminSessionCookie = "admin_session"
	
	// Default session duration: 30 days per AI.md PART 17
	DefaultSessionDuration = 30 * 24 * time.Hour
)

// LoginRequest for login credentials
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Remember bool   `json:"remember"` // Extends session duration
}

// handleAuthLogin handles both GET (login form) and POST (process login)
// GET/POST /auth/login
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.handleAuthLoginPage(w, r)
		return
	}

	if r.Method == http.MethodPost {
		s.handleAuthLoginProcess(w, r)
		return
	}

	SendError(w, ErrMethodNotAllowed, "Method not allowed")
}

// handleAuthLoginPage serves the login form
func (s *Server) handleAuthLoginPage(w http.ResponseWriter, r *http.Request) {
	// Check if already logged in
	if cookie, err := r.Cookie(AdminSessionCookie); err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if _, err := admin.ValidateSession(ctx, s.database, cookie.Value); err == nil {
			// Already logged in, redirect to admin panel
			adminPath := s.config.AdminPath
			if adminPath == "" {
				adminPath = "admin"
			}
			http.Redirect(w, r, fmt.Sprintf("/%s", adminPath), http.StatusFound)
			return
		}
	}

	// Serve login form HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	html := s.renderLoginPageHTML()
	fmt.Fprint(w, html)
}

// handleAuthLoginProcess processes login credentials
func (s *Server) handleAuthLoginProcess(w http.ResponseWriter, r *http.Request) {
	// Parse request (support both JSON and form data)
	var req LoginRequest

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			SendError(w, ErrBadRequest, "Invalid request body")
			return
		}
	} else {
		// Form data
		if err := r.ParseForm(); err != nil {
			SendError(w, ErrBadRequest, "Invalid form data")
			return
		}
		req.Email = r.FormValue("email")
		req.Password = r.FormValue("password")
		req.Remember = r.FormValue("remember") == "on" || r.FormValue("remember") == "true"
	}

	// Validate input
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		SendError(w, ErrValidationFailed, "Email is required")
		return
	}

	if req.Password == "" {
		SendError(w, ErrValidationFailed, "Password is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Look up admin by email (per AI.md PART 17: check admins table first)
	adminAccount, err := admin.GetAdminByEmail(ctx, s.database, req.Email)
	if err != nil {
		log.Printf("Login attempt failed for %s: admin not found", req.Email)
		SendError(w, ErrUnauthorized, "Invalid email or password")
		return
	}

	// Verify password
	valid, err := adminAccount.VerifyPassword(req.Password)
	if err != nil {
		log.Printf("Login attempt failed for %s: password verification error: %v", req.Email, err)
		SendError(w, ErrServerError, "Authentication error")
		return
	}
	if !valid {
		log.Printf("Login attempt failed for %s: invalid password", req.Email)
		SendError(w, ErrUnauthorized, "Invalid email or password")
		return
	}

	// Check if account is active
	if !adminAccount.IsActive {
		log.Printf("Login attempt failed for %s: account disabled", req.Email)
		SendError(w, ErrForbidden, "Account is disabled")
		return
	}

	// Determine session duration
	sessionDuration := DefaultSessionDuration
	if req.Remember {
		sessionDuration = 90 * 24 * time.Hour // 90 days if "remember me"
	}

	// Get client IP and User-Agent
	ipAddress := getClientIP(r)
	userAgent := r.UserAgent()

	// Create session
	session, err := admin.CreateSession(ctx, s.database, adminAccount.ID, ipAddress, userAgent, sessionDuration)
	if err != nil {
		log.Printf("Failed to create session for %s: %v", req.Email, err)
		SendError(w, ErrServerError, "Failed to create session")
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     AdminSessionCookie,
		Value:    session.ID,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil, // Secure flag if HTTPS
	})

	// Update last login time
	_, err = s.database.Users.ExecContext(ctx,
		`UPDATE usr_admins SET last_login = ? WHERE id = ?`,
		time.Now(), adminAccount.ID)
	if err != nil {
		log.Printf("Warning: Failed to update last_login for %s: %v", req.Email, err)
		// Don't fail the login
	}

	log.Printf("Admin login successful: %s (ID: %d)", adminAccount.Email, adminAccount.ID)

	// Return success response
	adminPath := s.config.AdminPath
	if adminPath == "" {
		adminPath = "admin"
	}

	// Check if this is a JSON request or form request
	if strings.Contains(contentType, "application/json") {
		data := map[string]interface{}{
			"success":      true,
			"redirect":     fmt.Sprintf("/%s", adminPath),
			"session_id":   session.ID,
			"expires_at":   session.ExpiresAt.Format(time.RFC3339),
			"admin_email":  adminAccount.Email,
			"admin_name":   adminAccount.Name,
		}
		SendSuccess(w, data)
	} else {
		// Form submission - redirect to admin panel
		http.Redirect(w, r, fmt.Sprintf("/%s", adminPath), http.StatusFound)
	}
}

// handleAuthLogout handles logout
// GET/POST /auth/logout
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	// Get session cookie
	cookie, err := r.Cookie(AdminSessionCookie)
	if err != nil {
		// No session cookie, redirect to login
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}

	// Delete session from database
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := admin.DeleteSession(ctx, s.database, cookie.Value); err != nil {
		log.Printf("Failed to delete session: %v", err)
		// Continue anyway
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     AdminSessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Delete cookie
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	log.Printf("Admin logout: session %s", cookie.Value)

	// Check if this is a JSON request
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		data := map[string]interface{}{
			"success":  true,
			"message":  "Logged out successfully",
			"redirect": "/auth/login",
		}
		SendSuccess(w, data)
	} else {
		// Redirect to login page
		http.Redirect(w, r, "/auth/login", http.StatusFound)
	}
}

// renderLoginPageHTML returns the login page HTML
func (s *Server) renderLoginPageHTML() string {
	return `<!DOCTYPE html>
<html lang="en" class="theme-dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - CASWHOIS</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
            padding: 2rem;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        .container {
            max-width: 400px;
            width: 100%;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 2rem;
        }
        h1 {
            color: #58a6ff;
            margin-bottom: 0.5rem;
            font-size: 1.75rem;
            text-align: center;
        }
        .subtitle {
            color: #8b949e;
            margin-bottom: 2rem;
            text-align: center;
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
        input[type="email"],
        input[type="password"] {
            width: 100%;
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
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
        }
        input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
        }
        .checkbox-group label {
            margin: 0;
            font-weight: normal;
            cursor: pointer;
        }
        .btn {
            width: 100%;
            padding: 0.75rem;
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
        .error {
            background: #da3633;
            color: white;
            padding: 0.75rem;
            border-radius: 6px;
            margin-bottom: 1rem;
            display: none;
        }
        .error.show {
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Admin Login</h1>
        <p class="subtitle">Sign in to access the admin panel</p>

        <div id="error-message" class="error"></div>

        <form id="login-form" method="POST" action="/auth/login">
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" required autofocus>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>

            <div class="checkbox-group">
                <input type="checkbox" id="remember" name="remember">
                <label for="remember">Remember me (90 days)</label>
            </div>

            <button type="submit" class="btn">Sign In</button>
        </form>
    </div>

    <script>
        const form = document.getElementById('login-form');
        const errorDiv = document.getElementById('error-message');

        form.addEventListener('submit', async (e) => {
            e.preventDefault();

            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const remember = document.getElementById('remember').checked;

            try {
                const response = await fetch('/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password, remember })
                });

                const data = await response.json();

                if (data.ok) {
                    // Redirect to admin panel
                    window.location.href = data.data.redirect;
                } else {
                    // Show error
                    errorDiv.textContent = data.message || 'Login failed';
                    errorDiv.classList.add('show');
                }
            } catch (error) {
                errorDiv.textContent = 'Network error: ' + error.message;
                errorDiv.classList.add('show');
            }
        });
    </script>
</body>
</html>`
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (behind proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fallback to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx > 0 {
		ip = ip[:idx]
	}
	return ip
}
