package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const securityIDWindowSeconds int64 = 48 * 60 * 60

func securityIDFor(secret []byte, window int64) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(strconv.FormatInt(window, 10)))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

func (s *Server) currentSecurityID(ctx context.Context, now time.Time) (string, error) {
	if s.database == nil {
		return "", fmt.Errorf("server database is unavailable")
	}
	secret, err := s.database.AppSecret(ctx, "installation_secret")
	if err != nil {
		return "", err
	}
	if len(secret) != 32 {
		return "", fmt.Errorf("installation secret must be 32 bytes")
	}
	return securityIDFor(secret, now.Unix()/securityIDWindowSeconds), nil
}

func (s *Server) validSecurityID(ctx context.Context, supplied string, now time.Time) bool {
	if len(supplied) != 16 || s.database == nil {
		return false
	}
	secret, err := s.database.AppSecret(ctx, "installation_secret")
	if err != nil || len(secret) != 32 {
		return false
	}
	window := now.Unix() / securityIDWindowSeconds
	secrets := [][]byte{secret}
	var encoded, until string
	if err := s.database.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name='installation_secret_previous'`).Scan(&encoded); err == nil {
		if s.database.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name='installation_secret_previous_until'`).Scan(&until) == nil {
			if deadline, parseErr := time.Parse(time.RFC3339, until); parseErr == nil && now.Before(deadline) {
				if previous, decodeErr := base64.StdEncoding.DecodeString(encoded); decodeErr == nil && len(previous) == 32 {
					secrets = append(secrets, previous)
				}
			}
		}
	}
	for _, candidate := range secrets {
		for _, candidateWindow := range []int64{window, window - 1} {
			if subtle.ConstantTimeCompare([]byte(supplied), []byte(securityIDFor(candidate, candidateWindow))) == 1 {
				return true
			}
		}
	}
	return false
}

func (s *Server) securityReportURL(ctx context.Context, r *http.Request, now time.Time) string {
	id, err := s.currentSecurityID(ctx, now)
	if err != nil {
		return ""
	}
	return s.BuildURL(r, "/server/contact") + "?security_id=" + id
}

func securityIDHashPrefix(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])[:8]
}

func (s *Server) logInvalidSecurityID(r *http.Request, supplied string) {
	if s.logger == nil {
		return
	}
	s.logger.WriteSecurity(fmt.Sprintf("security.security_id_invalid ip=%q user_agent=%q supplied_hash=%s",
		r.RemoteAddr, r.UserAgent(), securityIDHashPrefix(supplied)))
}

func (s *Server) logInvalidSecurityIDIfPresent(r *http.Request) {
	supplied := r.URL.Query().Get("security_id")
	if supplied == "" {
		supplied = r.FormValue("security_id")
	}
	if supplied != "" && !s.validSecurityID(r.Context(), supplied, time.Now()) {
		s.logInvalidSecurityID(r, supplied)
	}
}
