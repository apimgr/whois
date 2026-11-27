package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/apimgr/whois/src/config"
)

// csrfToken returns the current CSRF token for the request, issuing a new
// cookie when none exists (AI.md PART 16 — CSRF Protection: stateless
// double-submit cookie pattern; token regenerated when the cookie is
// absent). The cookie is SameSite=Strict and NOT HttpOnly — the
// server-rendered form embeds the same value, so client JS never needs
// to read it, but the spec requires HttpOnly=false regardless.
func (s *Server) csrfToken(w http.ResponseWriter, r *http.Request) string {
	cfg := s.config.CSRF
	cookieName := cfg.CookieName
	if cookieName == "" {
		cookieName = "csrf_token"
	}
	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" && s.validCSRFToken(r.Context(), c.Value) {
		return c.Value
	}
	length := cfg.TokenLength
	if length <= 0 {
		length = 32
	}
	if s.database == nil {
		return ""
	}
	key, err := s.database.AppSecret(r.Context(), "csrf_token_secret")
	if err != nil {
		return ""
	}
	nonce := make([]byte, length)
	if _, err := rand.Read(nonce); err != nil {
		return ""
	}
	nonceText := hex.EncodeToString(nonce)
	token := nonceText + "." + csrfTokenMAC(key, nonceText)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   csrfCookieSecure(cfg.Secure, r),
		SameSite: http.SameSiteStrictMode,
	})
	return token
}

func csrfTokenMAC(key []byte, nonce string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

func rotateCSRFSecretTx(ctx context.Context, tx *sql.Tx) error {
	var encoded string
	if err := tx.QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name='csrf_token_secret'`).Scan(&encoded); err != nil {
		return fmt.Errorf("read CSRF secret: %w", err)
	}
	previous, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(previous) != 32 {
		return fmt.Errorf("current CSRF secret is invalid")
	}
	current := make([]byte, 32)
	if _, err := rand.Read(current); err != nil {
		return fmt.Errorf("generate CSRF secret: %w", err)
	}
	now := time.Now().UTC()
	previousValue := base64.StdEncoding.EncodeToString(previous)
	currentValue := base64.StdEncoding.EncodeToString(current)
	until := now.Add(7 * 24 * time.Hour).Format(time.RFC3339)
	for name, value := range map[string]string{"csrf_token_secret_previous": previousValue, "csrf_token_secret_previous_until": until, "csrf_token_secret": currentValue} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO app_secrets(name,value,updated_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, name, value, now.Format(time.RFC3339)); err != nil {
			return fmt.Errorf("store rotated CSRF secret: %w", err)
		}
	}
	return nil
}

func (s *Server) validCSRFToken(ctx context.Context, token string) bool {
	if s.database == nil {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[1]) != sha256.Size*2 {
		return false
	}
	if _, err := hex.DecodeString(parts[0]); err != nil {
		return false
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return false
	}
	current, err := s.database.AppSecret(ctx, "csrf_token_secret")
	if err != nil {
		return false
	}
	if hmac.Equal([]byte(parts[1]), []byte(csrfTokenMAC(current, parts[0]))) {
		return true
	}
	var previous, until string
	if err := s.database.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name='csrf_token_secret_previous'`).Scan(&previous); err != nil {
		return false
	}
	if err := s.database.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name='csrf_token_secret_previous_until'`).Scan(&until); err != nil {
		return false
	}
	deadline, err := time.Parse(time.RFC3339, until)
	if err != nil || !time.Now().UTC().Before(deadline) {
		return false
	}
	previousKey, err := base64.StdEncoding.DecodeString(previous)
	if err != nil || len(previousKey) != 32 {
		return false
	}
	return hmac.Equal([]byte(parts[1]), []byte(csrfTokenMAC(previousKey, parts[0])))
}

// generateCSRFToken returns a random hex-encoded token of the given byte length.
func generateCSRFToken(length int) string {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failures are effectively unrecoverable; fall back to a
		// per-process fixed-length placeholder rather than panicking the request.
		return hex.EncodeToString([]byte("insecure-fallback-token-do-not-use"))
	}
	return hex.EncodeToString(buf)
}

// csrfCookieSecure resolves the "auto" | "true" | "false" config value into
// the cookie's Secure attribute (AI.md PART 16 — CSRF Protection configuration).
func csrfCookieSecure(mode string, r *http.Request) bool {
	switch strings.ToLower(mode) {
	case "true":
		return true
	case "false":
		return false
	default:
		return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	}
}

// csrfBearerPresent reports whether the request carries a bearer-style
// credential (Authorization: Bearer … or X-API-Token: …), which bypasses
// CSRF validation entirely (AI.md PART 16 — bearer credentials are not
// auto-attached by browsers, so cross-site forgery has no vector).
func csrfBearerPresent(r *http.Request) bool {
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return true
	}
	return r.Header.Get("X-API-Token") != ""
}

// csrfExempt reports whether the request path matches one of the operator's
// configured exempt_paths glob patterns (AI.md PART 16 — Configuration).
func csrfExempt(cfg *config.CSRFConfig, r *http.Request) bool {
	for _, pattern := range cfg.ExemptPaths {
		if ok, err := path.Match(pattern, r.URL.Path); err == nil && ok {
			return true
		}
	}
	return false
}

// csrfRequired reports whether the request must pass CSRF validation
// (AI.md PART 16 — "When CSRF Validation Runs"). Read-only methods, bearer
// auth, WebSocket upgrades, and operator-declared exempt paths never need it.
func (s *Server) csrfRequired(r *http.Request) bool {
	if !s.config.CSRF.Enabled {
		return false
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	if csrfBearerPresent(r) {
		return false
	}
	if csrfExempt(&s.config.CSRF, r) {
		return false
	}
	return true
}

// csrfValid checks the submitted token (form field or configured header)
// against the CSRF cookie using a constant-time comparison. Missing cookie,
// missing submitted value, or a mismatch are all rejected — no silent
// fallback (AI.md PART 16 — Implementation Rules).
func (s *Server) csrfValid(r *http.Request) bool {
	cfg := s.config.CSRF
	cookieName := cfg.CookieName
	if cookieName == "" {
		cookieName = "csrf_token"
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	headerName := cfg.HeaderName
	if headerName == "" {
		headerName = "X-CSRF-Token"
	}
	submitted := r.Header.Get(headerName)
	if submitted == "" {
		submitted = r.FormValue("csrf_token")
	}
	if submitted == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(submitted)) == 1 && s.validCSRFToken(r.Context(), submitted)
}

// requireCSRF wraps a state-changing handler and rejects requests that fail
// CSRF validation per the rules in csrfRequired (AI.md PART 16 — CSRF
// Protection). Failures are logged as security.csrf_failure and answered
// with the canonical 403 CSRF_FAILED error body.
func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.csrfRequired(r) && !s.csrfValid(r) {
			if s.logger != nil {
				s.logger.Warn("security.csrf_failure", "path", r.URL.Path, "remote_addr", r.RemoteAddr, "reason", "token_mismatch_or_missing")
			}
			SendError(w, ErrCSRFFailed, "CSRF token validation failed")
			return
		}
		next(w, r)
	}
}
