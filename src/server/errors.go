package server

import (
	"encoding/json"
	"net/http"
)

// APIResponse represents the unified API response structure (AI.md PART 9)
type APIResponse struct {
	OK      bool   `json:"ok"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

// Standard error codes (per AI.md PART 9)
const (
	ErrBadRequest        = "BAD_REQUEST"
	ErrValidationFailed  = "VALIDATION_FAILED"
	ErrUnauthorized      = "UNAUTHORIZED"
	ErrTokenExpired      = "TOKEN_EXPIRED"
	ErrTokenInvalid      = "TOKEN_INVALID"
	ErrForbidden         = "FORBIDDEN"
	ErrNotFound          = "NOT_FOUND"
	ErrMethodNotAllowed  = "METHOD_NOT_ALLOWED"
	ErrConflict          = "CONFLICT"
	ErrRateLimited       = "RATE_LIMITED"
	ErrServerError       = "SERVER_ERROR"
	ErrMaintenance       = "MAINTENANCE"
)

// SendSuccess sends a successful API response
func SendSuccess(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{
		OK:   true,
		Data: data,
	})
}

// SendError sends an error API response
func SendError(w http.ResponseWriter, code string, message string) {
	status := mapErrorCodeToStatus(code)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(APIResponse{
		OK:      false,
		Error:   code,
		Message: message,
	})
}

// mapErrorCodeToStatus maps error codes to HTTP status codes (AI.md PART 9)
func mapErrorCodeToStatus(code string) int {
	switch code {
	case ErrBadRequest, ErrValidationFailed:
		return http.StatusBadRequest
	case ErrUnauthorized, ErrTokenExpired, ErrTokenInvalid:
		return http.StatusUnauthorized
	case ErrForbidden:
		return http.StatusForbidden
	case ErrNotFound:
		return http.StatusNotFound
	case ErrMethodNotAllowed:
		return http.StatusMethodNotAllowed
	case ErrConflict:
		return http.StatusConflict
	case ErrRateLimited:
		return http.StatusTooManyRequests
	case ErrMaintenance:
		return http.StatusServiceUnavailable
	case ErrServerError:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// handleNotFound is the catch-all 404 handler.
// Returns JSON for /api/* paths; HTML 404 page for all others.
func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
		SendError(w, ErrNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	htmlResponseTmpl.Execute(w, "404 — page not found")
}

// Common error messages
var (
	MsgBadRequest       = "Invalid request format"
	MsgValidationFailed = "Validation failed"
	MsgUnauthorized     = "Authentication required"
	MsgForbidden        = "Permission denied"
	MsgNotFound         = "Resource not found"
	MsgMethodNotAllowed = "Method not allowed"
	MsgConflict         = "Resource already exists"
	MsgRateLimited      = "Too many requests"
	MsgServerError      = "Internal server error"
	MsgMaintenance      = "Service unavailable"
)
