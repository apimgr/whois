package server

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/casapps/caswhois/src/admin"
)

// adminContextKey is the context key for admin information
type adminContextKey struct{}

// AdminContext holds admin information for the current request
type AdminContext struct {
	Admin   *admin.Admin
	Session *admin.Session
}

// RequireAdminSession is middleware that requires a valid admin session
func (s *Server) RequireAdminSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get session cookie
		cookie, err := r.Cookie(AdminSessionCookie)
		if err != nil {
			// No session cookie - redirect to login
			redirectToLogin(w, r)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Validate session
		session, err := admin.ValidateSession(ctx, s.database, cookie.Value)
		if err != nil {
			// Invalid or expired session - redirect to login
			log.Printf("Invalid session: %v", err)
			redirectToLogin(w, r)
			return
		}

		// Update last activity
		if err := admin.UpdateSessionActivity(ctx, s.database, session.ID); err != nil {
			log.Printf("Failed to update session activity: %v", err)
			// Don't fail the request
		}

		// Get admin account
		adminAccount, err := admin.GetAdminByID(ctx, s.database, session.AdminID)
		if err != nil {
			log.Printf("Failed to get admin account: %v", err)
			redirectToLogin(w, r)
			return
		}

		// Check if account is still active
		if !adminAccount.IsActive {
			log.Printf("Admin account disabled: %d", adminAccount.ID)
			redirectToLogin(w, r)
			return
		}

		// Add admin context to request
		adminCtx := &AdminContext{
			Admin:   adminAccount,
			Session: session,
		}
		newCtx := context.WithValue(r.Context(), adminContextKey{}, adminCtx)

		// Call next handler with admin context
		next.ServeHTTP(w, r.WithContext(newCtx))
	}
}

// GetAdminContext retrieves the admin context from the request
func GetAdminContext(r *http.Request) (*AdminContext, bool) {
	ctx, ok := r.Context().Value(adminContextKey{}).(*AdminContext)
	return ctx, ok
}

// redirectToLogin redirects to the login page
func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	// Check if this is a JSON/API request
	if strings.Contains(r.Header.Get("Accept"), "application/json") ||
		strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		SendError(w, ErrUnauthorized, "Authentication required")
		return
	}

	// Redirect to login page
	http.Redirect(w, r, "/auth/login", http.StatusFound)
}
