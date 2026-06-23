package server

import (
	"encoding/json"
	"net/http"
	"strings"
)

// APIResponse represents the unified API response structure (AI.md PART 14)
type APIResponse struct {
	OK bool `json:"ok"`
	// Data carries the success payload.
	Data any `json:"data,omitempty"`
	// Error is the machine-readable error code on failure.
	Error string `json:"error,omitempty"`
	// Message is the human-readable error message on failure.
	Message string `json:"message,omitempty"`
	// Details carries optional structured error context (AI.md PART 14).
	Details map[string]any `json:"details,omitempty"`
}

// Standard error codes (per AI.md PART 14)
const (
	ErrBadRequest       = "BAD_REQUEST"
	ErrValidationFailed = "VALIDATION_FAILED"
	ErrUnauthorized     = "UNAUTHORIZED"
	ErrTokenExpired     = "TOKEN_EXPIRED"
	ErrTokenInvalid     = "TOKEN_INVALID"
	ErrForbidden        = "FORBIDDEN"
	ErrNotFound         = "NOT_FOUND"
	ErrMethodNotAllowed = "METHOD_NOT_ALLOWED"
	ErrConflict         = "CONFLICT"
	ErrRateLimited      = "RATE_LIMITED"
	ErrServerError      = "SERVER_ERROR"
	ErrMaintenance      = "MAINTENANCE"
)

// writeJSON marshals v with 2-space indentation and writes it followed by exactly
// one trailing newline (AI.md PART 14 — every API response ends with one \n).
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	w.Write(body)
	w.Write([]byte("\n"))
}

// SendSuccess sends a successful API response
func SendSuccess(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, APIResponse{
		OK:   true,
		Data: data,
	})
}

// SendError sends an error API response
func SendError(w http.ResponseWriter, code string, message string) {
	status := mapErrorCodeToStatus(code)
	// Rate-limited responses must advertise a Retry-After header (AI.md PART 14).
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60")
	}
	writeJSON(w, status, APIResponse{
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

// statusToErrorCode maps an HTTP status code to its canonical error code
// (AI.md PART 14) for content-negotiated error responses.
func statusToErrorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return ErrBadRequest
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusMethodNotAllowed:
		return ErrMethodNotAllowed
	case http.StatusConflict:
		return ErrConflict
	case http.StatusTooManyRequests:
		return ErrRateLimited
	case http.StatusServiceUnavailable:
		return ErrMaintenance
	default:
		return ErrServerError
	}
}

// handleNotFound is the catch-all 404 handler.
// Returns JSON for /api/* paths; HTML 404 page for all others.
func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api") {
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
