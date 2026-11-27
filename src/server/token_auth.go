package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/apimgr/whois/src/common/constants"
)

// getServerTokenHash returns the cached SHA-256 hash of the server token.
func (s *Server) getServerTokenHash() []byte {
	s.serverTokenHashOnce.Do(func() {
		h := sha256.Sum256([]byte(s.config.ServerToken))
		s.serverTokenHash = h
	})
	return s.serverTokenHash[:]
}

// requireToken returns an http.HandlerFunc that requires a valid server token.
// Token is expected as: Authorization: Bearer adm_...
// Comparison is done via constant-time SHA-256 to prevent timing oracles.
func (s *Server) requireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authFailureBlocked(w, r) {
			return
		}
		token := extractBearerToken(r)
		if token == "" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q`, constants.InternalName))
			SendError(w, ErrUnauthorized, "Authorization required")
			return
		}

		// Hash the incoming token
		incoming := sha256.Sum256([]byte(token))

		// Compare against server token hash (constant-time)
		expected := s.getServerTokenHash()
		if subtle.ConstantTimeCompare(incoming[:], expected) != 1 {
			if _, err := s.lookupOwnerToken(r.Context(), token); err == nil {
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
				SendError(w, ErrForbidden, "Operator token required")
				return
			}
			if s.recordAuthFailure(w, r) {
				return
			}
			// Token format valid but hash does not match — 401 with generic message
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q`, constants.InternalName))
			SendError(w, ErrUnauthorized, "Invalid token")
			return
		}

		next(w, r)
	}
}

// extractBearerToken pulls the raw token from the Authorization header.
// Returns "" if header is absent or malformed.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

// TokenHash returns the hex-encoded SHA-256 hash of a token string.
// Used for storing resource-owner tokens in the api_tokens table.
func TokenHash(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// TokenPrefix returns the first 12 characters of the raw token for log identification.
func TokenPrefix(raw string) string {
	if len(raw) <= 12 {
		return raw
	}
	return raw[:12]
}
