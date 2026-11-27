package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/apimgr/whois/src/common/i18n"
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
	// ErrCSRFFailed is returned when a mutating request's CSRF token is
	// missing or does not match the csrf_token cookie (AI.md PART 16 —
	// CSRF Protection, double-submit cookie pattern).
	ErrCSRFFailed = "CSRF_FAILED"
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
	_, _ = w.Write(body)
	_, _ = w.Write([]byte("\n"))
}

// SendSuccess sends a successful API response
func SendSuccess(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, APIResponse{
		OK:   true,
		Data: data,
	})
}

// SendError sends an error API response
func SendError(w http.ResponseWriter, code string, _ string) {
	status := mapErrorCodeToStatus(code)
	lang := w.Header().Get("Content-Language")
	if lang == "" {
		lang = "en"
	}
	writeLocalizedAPIError(w, status, code, lang)
}

func writeLocalizedAPIError(w http.ResponseWriter, status int, code, lang string) {
	// Rate-limited responses must advertise a Retry-After header (AI.md PART 14).
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60")
	}
	if lang == "" {
		lang = "en"
	}
	messageKey := errorTranslationKey(code)
	if status == http.StatusBadGateway || status == http.StatusGatewayTimeout {
		messageKey = "errors.bad_gateway_message"
	}
	w.Header().Set("Content-Language", lang)
	addVaryHeader(w.Header(), "Accept-Language")
	writeJSON(w, status, APIResponse{
		OK:      false,
		Error:   code,
		Message: translateKey(lang, messageKey),
	})
}

func writeRequestAPIError(w http.ResponseWriter, r *http.Request, status int) {
	lang := requestErrorLanguage(r)
	writeLocalizedAPIError(w, status, statusToErrorCode(status), lang)
}

func errorTranslationKey(code string) string {
	switch code {
	case ErrBadRequest:
		return "errors.bad_request"
	case ErrValidationFailed:
		return "errors.validation_failed"
	case ErrUnauthorized, ErrTokenExpired, ErrTokenInvalid:
		return "errors.unauthorized"
	case ErrForbidden, ErrCSRFFailed:
		return "errors.forbidden"
	case ErrNotFound:
		return "errors.not_found"
	case ErrMethodNotAllowed:
		return "errors.method_not_allowed"
	case ErrConflict:
		return "errors.conflict"
	case ErrRateLimited:
		return "errors.rate_limited"
	case ErrMaintenance:
		return "errors.maintenance"
	default:
		return "errors.server_error"
	}
}

func writeRequestError(w http.ResponseWriter, r *http.Request, status int) {
	lang := requestErrorLanguage(r)
	w.Header().Set("Content-Language", lang)
	addVaryHeader(w.Header(), "Accept-Language")
	server := serverFromContext(r.Context())
	if (server != nil && isAPIRoute(server, r.URL.Path)) || strings.HasPrefix(r.URL.Path, "/api/") {
		writeRequestAPIError(w, r, status)
		return
	}
	key := errorTranslationKey(statusToErrorCode(status))
	http.Error(w, translateKey(lang, key), status)
}

func addVaryHeader(header http.Header, value string) {
	for _, line := range header.Values("Vary") {
		for _, existing := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(existing), value) {
				return
			}
		}
	}
	header.Add("Vary", value)
}

func requestErrorLanguage(r *http.Request) string {
	if lang, ok := r.Context().Value(langContextKey).(string); ok && i18n.IsSupported(lang) {
		return lang
	}
	if lang, ok := r.URL.Query()["lang"]; ok {
		if len(lang) > 0 && i18n.IsSupported(lang[0]) {
			return lang[0]
		}
		return "en"
	}
	if cookie, err := r.Cookie("lang"); err == nil && i18n.IsSupported(cookie.Value) {
		return cookie.Value
	}
	return i18n.ParseAcceptLanguage(r.Header.Get("Accept-Language"))
}

// mapErrorCodeToStatus maps error codes to HTTP status codes (AI.md PART 9)
func mapErrorCodeToStatus(code string) int {
	switch code {
	case ErrBadRequest, ErrValidationFailed:
		return http.StatusBadRequest
	case ErrUnauthorized, ErrTokenExpired, ErrTokenInvalid:
		return http.StatusUnauthorized
	case ErrForbidden, ErrCSRFFailed:
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
	if isAPIRoute(s, r.URL.Path) {
		SendError(w, ErrNotFound, "not found")
		return
	}
	s.renderStatusError(w, r, http.StatusNotFound)
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
