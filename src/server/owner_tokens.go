package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	caslogger "github.com/apimgr/whois/src/logger"
	"github.com/apimgr/whois/src/security"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const ownerTokenCookieName = "caswhois_owner_token_oibocvwt"

const ownerTokenAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var (
	errLinkedTokenNameConflict  = errors.New("linked token name already exists")
	errLinkedTokenLimitConflict = errors.New("maximum active linked tokens reached")
)

func isLinkedTokenNameUniqueConflict(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique constraint failed") &&
		strings.Contains(message, "api_tokens.owner_id") && strings.Contains(message, "api_tokens.name")
}

func isOwnerTokenWriteConflict(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{"sqlite_busy", "sqlite_locked", "database is locked", "transaction conflict", "serialization failure", "write conflict"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

type ownerTokenRecord struct {
	ID           string
	OwnerID      string
	Kind         string
	Name         sql.NullString
	Prefix       string
	Last4        string
	Masked       string
	Encrypted    string
	CreatedAt    int64
	ExpiresAt    sql.NullInt64
	LastUsed     sql.NullInt64
	RevokedAt    sql.NullInt64
	Status       string
	CreatedText  string
	LastUsedText string
	ExpiresText  string
}

func (s *Server) encryptionKey() ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s.config.Security.EncryptionKey)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("invalid server.security.encryption_key")
	}
	return key, nil
}

func generateOwnerToken() (string, error) {
	token := make([]byte, 32)
	for i := range token {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(ownerTokenAlphabet))))
		if err != nil {
			return "", err
		}
		token[i] = ownerTokenAlphabet[n.Int64()]
	}
	return "own_" + string(token), nil
}

func maskedOwnerToken(last4 string) string {
	return "own_" + strings.Repeat("•", 24) + last4
}

func (s *Server) issuePrimaryToken(ctx context.Context, actorIP string) (string, string, error) {
	raw, err := generateOwnerToken()
	if err != nil {
		return "", "", fmt.Errorf("generate owner token: %w", err)
	}
	key, err := s.encryptionKey()
	if err != nil {
		return "", "", err
	}
	encrypted, err := security.EncryptAESGCM(key, raw)
	if err != nil {
		return "", "", err
	}
	ownerID, err := uuid.NewV7()
	if err != nil {
		return "", "", err
	}
	tokenID, err := uuid.NewV7()
	if err != nil {
		return "", "", err
	}
	tokenHash := sha256.Sum256([]byte(raw))
	details, _ := json.Marshal(map[string]string{"source": "issue", "token_prefix": raw[:12]})
	err = s.database.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO owners (id) VALUES (?)`, ownerID.String()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO api_tokens
		(id, owner_id, kind, token_hash, token_prefix, token_last4, token_enc)
		VALUES (?, ?, 'primary', ?, ?, ?, ?)`,
			tokenID.String(), ownerID.String(), hex.EncodeToString(tokenHash[:]),
			raw[:12], raw[len(raw)-4:], encrypted); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log (category, action, actor_ip, target_type, target_id, details)
		VALUES ('token', 'token.created', ?, 'owner', ?, ?)`, actorIP, ownerID.String(), string(details)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	if s.logger != nil {
		s.logger.WriteAudit(caslogger.AuditEntry{Category: "token", Action: "token.created", ActorIP: actorIP,
			TargetType: "owner", TargetID: ownerID.String(), Details: string(details), Success: true})
	}
	return ownerID.String(), raw, nil
}

func (s *Server) lookupOwnerToken(ctx context.Context, token string) (*ownerTokenRecord, error) {
	if !strings.HasPrefix(token, "own_") || len(token) != 36 {
		return nil, sql.ErrNoRows
	}
	hash := sha256.Sum256([]byte(token))
	record := &ownerTokenRecord{}
	err := s.database.Read().QueryRowContext(ctx, `SELECT id, owner_id, kind, name, token_prefix,
		token_last4, token_enc, created_at, expires_at, last_used_at, revoked_at
		FROM api_tokens WHERE token_hash = ?`, hex.EncodeToString(hash[:])).Scan(
		&record.ID, &record.OwnerID, &record.Kind, &record.Name, &record.Prefix,
		&record.Last4, &record.Encrypted, &record.CreatedAt, &record.ExpiresAt,
		&record.LastUsed, &record.RevokedAt)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Unix()
	if record.RevokedAt.Valid || (record.ExpiresAt.Valid && record.ExpiresAt.Int64 <= now) {
		return nil, sql.ErrNoRows
	}
	if !record.LastUsed.Valid || record.LastUsed.Int64 <= now-60 {
		record.LastUsed = sql.NullInt64{Int64: s.queueTokenUse(record.ID, record.OwnerID, now), Valid: true}
	} else {
		return record, nil
	}
	return record, nil
}

func (s *Server) ownerFromRequest(r *http.Request, allowCookie bool) (*ownerTokenRecord, error) {
	token := extractBearerToken(r)
	if token == "" && allowCookie {
		if cookie, err := r.Cookie(ownerTokenCookieName); err == nil {
			token = cookie.Value
		}
	}
	if token == "" {
		return nil, sql.ErrNoRows
	}
	return s.lookupOwnerToken(r.Context(), token)
}

func setOwnerCookie(w http.ResponseWriter, r *http.Request, raw string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: ownerTokenCookieName, Value: raw, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: !isI2PRequest(r), SameSite: http.SameSiteStrictMode,
	})
}

func clearOwnerCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: ownerTokenCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: !isI2PRequest(r), SameSite: http.SameSiteStrictMode,
	})
}

func isI2PRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	isI2P, _ := r.Context().Value(i2pRequestContextKey{}).(bool)
	return isI2P
}

func ownerCookieMaxAge(cfgAge string) int {
	if cfgAge == "" || cfgAge == "1y" {
		return 365 * 24 * 60 * 60
	}
	duration, err := time.ParseDuration(cfgAge)
	if err != nil || duration <= 0 {
		return 365 * 24 * 60 * 60
	}
	return int(duration.Seconds())
}

func validOperatorBearer(s *Server, r *http.Request) bool {
	token := extractBearerToken(r)
	if token == "" {
		return false
	}
	hash := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(hash[:], s.getServerTokenHash()) == 1
}

func (s *Server) handleIssuePrimaryTokenAPI(w http.ResponseWriter, r *http.Request) {
	if validOperatorBearer(s, r) {
		SendError(w, ErrConflict, "A valid token is already present")
		return
	}
	if token := extractBearerToken(r); token != "" {
		if _, err := s.lookupOwnerToken(r.Context(), token); err == nil {
			SendError(w, ErrConflict, "A valid token is already present")
			return
		}
	}
	ownerID, raw, err := s.issuePrimaryToken(r.Context(), extractClientIP(r, s.config.TrustedProxies.Additional))
	if err != nil {
		SendError(w, ErrServerError, "Could not issue token")
		return
	}
	writeJSON(w, http.StatusCreated, APIResponse{OK: true, Data: map[string]string{"owner_id": ownerID, "owner_token": raw}})
}

func (s *Server) handleIssuePrimaryTokenPage(w http.ResponseWriter, r *http.Request) {
	if rec, err := s.ownerFromRequest(r, true); err == nil && rec != nil {
		writeRequestError(w, r, http.StatusConflict)
		return
	}
	ownerID, raw, err := s.issuePrimaryToken(r.Context(), extractClientIP(r, s.config.TrustedProxies.Additional))
	if err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
		return
	}
	setOwnerCookie(w, r, raw, ownerCookieMaxAge(s.config.Tokens.CookieMaxAge))
	_ = ownerID
	if err := s.setTokenViewCookie(w, r, "primary"); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.BuildURL(r, "/server/preferences/tokens#primary"), http.StatusSeeOther)
}

func (s *Server) handleRevealPrimaryTokenPage(w http.ResponseWriter, r *http.Request) {
	record, err := s.ownerFromRequest(r, true)
	if err != nil || record.Kind != "primary" {
		writeRequestError(w, r, http.StatusForbidden)
		return
	}
	if err := s.auditOwnerTokenEvent(r, "token.revealed", record); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
		return
	}
	if err := s.setTokenViewCookie(w, r, "primary"); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.BuildURL(r, "/server/preferences/tokens#primary"), http.StatusSeeOther)
}

func (s *Server) handleCreateLinkedTokenPage(w http.ResponseWriter, r *http.Request) {
	record, err := s.webPrimaryToken(r)
	if err != nil {
		writeRequestError(w, r, http.StatusForbidden)
		return
	}
	body, _ := json.Marshal(linkedTokenRequest{Name: r.FormValue("name"), Expires: r.FormValue("expires"), ExpiresOn: r.FormValue("expires_on")})
	request := s.ownerAPIRequest(r, record, http.MethodPost, "/tokens", body)
	response := httptest.NewRecorder()
	s.handleCreateLinkedTokenAPI(response, request)
	if response.Code != http.StatusCreated {
		writeRequestError(w, r, response.Code)
		return
	}
	var result struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Data.ID == "" {
		writeRequestError(w, r, http.StatusInternalServerError)
		return
	}
	if err := s.setTokenViewCookie(w, r, result.Data.ID); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.BuildURL(r, "/server/preferences/tokens#token-"+result.Data.ID), http.StatusSeeOther)
}

func (s *Server) handleRevealLinkedTokenPage(w http.ResponseWriter, r *http.Request) {
	primary, err := s.webPrimaryToken(r)
	if err != nil {
		writeRequestError(w, r, http.StatusForbidden)
		return
	}
	record, err := s.getOwnedLinkedToken(r.Context(), primary.OwnerID, chi.URLParam(r, "id"))
	if err != nil || record.RevokedAt.Valid {
		writeRequestError(w, r, http.StatusNotFound)
		return
	}
	if err := s.auditOwnerTokenEvent(r, "token.revealed", record); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
		return
	}
	if err := s.setTokenViewCookie(w, r, record.ID); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.BuildURL(r, "/server/preferences/tokens#token-"+record.ID), http.StatusSeeOther)
}

func (s *Server) handleRotateTokenPage(w http.ResponseWriter, r *http.Request) {
	primary, err := s.webPrimaryToken(r)
	if err != nil {
		writeRequestError(w, r, http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" || id == "primary" {
		response := httptest.NewRecorder()
		s.handleRotatePrimaryTokenAPI(response, s.ownerAPIRequest(r, primary, http.MethodPost, "/tokens/primary/rotate", nil))
		if response.Code != http.StatusOK {
			writeRequestError(w, r, response.Code)
			return
		}
		var result struct {
			Data struct {
				Token string `json:"owner_token"`
			} `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Data.Token == "" {
			writeRequestError(w, r, http.StatusInternalServerError)
			return
		}
		setOwnerCookie(w, r, result.Data.Token, ownerCookieMaxAge(s.config.Tokens.CookieMaxAge))
		if err := s.setTokenViewCookie(w, r, "primary"); err != nil {
			writeRequestError(w, r, http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, s.BuildURL(r, "/server/preferences/tokens#primary"), http.StatusSeeOther)
		return
	}
	record, err := s.getOwnedLinkedToken(r.Context(), primary.OwnerID, id)
	if err != nil || record.RevokedAt.Valid {
		writeRequestError(w, r, http.StatusNotFound)
		return
	}
	response := httptest.NewRecorder()
	s.handleRotateLinkedTokenAPI(response, s.ownerAPIRequest(r, primary, http.MethodPost, "/tokens/"+id+"/rotate", nil))
	if response.Code != http.StatusOK {
		writeRequestError(w, r, response.Code)
		return
	}
	if err := s.setTokenViewCookie(w, r, id); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.BuildURL(r, "/server/preferences/tokens#token-"+id), http.StatusSeeOther)
}

func (s *Server) handleUpdateLinkedTokenPage(w http.ResponseWriter, r *http.Request) {
	primary, err := s.webPrimaryToken(r)
	if err != nil {
		writeRequestError(w, r, http.StatusForbidden)
		return
	}
	body, _ := json.Marshal(linkedTokenRequest{Name: r.FormValue("name"), Expires: r.FormValue("expires"), ExpiresOn: r.FormValue("expires_on")})
	request := s.ownerAPIRequest(r, primary, http.MethodPatch, "/tokens/"+chi.URLParam(r, "id"), body)
	response := httptest.NewRecorder()
	s.handleUpdateLinkedTokenAPI(response, request)
	if response.Code != http.StatusOK {
		writeRequestError(w, r, response.Code)
		return
	}
	http.Redirect(w, r, s.BuildURL(r, "/server/preferences/tokens#token-"+chi.URLParam(r, "id")), http.StatusSeeOther)
}

func (s *Server) handleRevokeLinkedTokenPage(w http.ResponseWriter, r *http.Request) {
	primary, err := s.webPrimaryToken(r)
	if err != nil {
		writeRequestError(w, r, http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	response := httptest.NewRecorder()
	s.handleRevokeLinkedTokenAPI(response, s.ownerAPIRequest(r, primary, http.MethodDelete, "/tokens/"+id, nil))
	if response.Code != http.StatusOK {
		writeRequestError(w, r, response.Code)
		return
	}
	clearSiteDataOnTokenRevocation(w)
	http.Redirect(w, r, s.BuildURL(r, "/server/preferences/tokens#token-"+id), http.StatusSeeOther)
}

func (s *Server) handleRevokePrimaryTokenPage(w http.ResponseWriter, r *http.Request) {
	primary, err := s.webPrimaryToken(r)
	if err != nil || subtle.ConstantTimeCompare([]byte(r.FormValue("confirm")), []byte(primary.Last4)) != 1 {
		writeRequestError(w, r, http.StatusBadRequest)
		return
	}
	if _, _, err := s.deleteOwner(r, primary, "web"); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
		return
	}
	clearOwnerCookie(w, r)
	clearSiteDataOnTokenRevocation(w)
	http.Redirect(w, r, s.BuildURL(r, "/server/preferences/tokens"), http.StatusSeeOther)
}

func (s *Server) webPrimaryToken(r *http.Request) (*ownerTokenRecord, error) {
	cookie, err := r.Cookie(ownerTokenCookieName)
	if err != nil {
		return nil, err
	}
	record, err := s.lookupOwnerToken(r.Context(), cookie.Value)
	if err != nil || record.Kind != "primary" {
		return nil, sql.ErrNoRows
	}
	return record, nil
}

func (s *Server) refreshOwnerCookie(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := httptest.NewRecorder()
		next.ServeHTTP(recorder, r)
		if cookie, err := r.Cookie(ownerTokenCookieName); err == nil {
			hasOwnerCookie := false
			for _, responseCookie := range recorder.Result().Cookies() {
				if responseCookie.Name == ownerTokenCookieName {
					hasOwnerCookie = true
					break
				}
			}
			if record, lookupErr := s.lookupOwnerToken(r.Context(), cookie.Value); recorder.Code >= 200 && recorder.Code < 400 && !hasOwnerCookie && lookupErr == nil && record.Kind == "primary" {
				setOwnerCookie(w, r, cookie.Value, ownerCookieMaxAge(s.config.Tokens.CookieMaxAge))
			}
		}
		for key, values := range recorder.Header() {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
	})
}

func (s *Server) setTokenViewCookie(w http.ResponseWriter, r *http.Request, id string) error {
	key, err := s.database.AppSecret(context.Background(), "cookie_signing_key")
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("caswhois_token_view:" + id))
	value := id + "." + hex.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{Name: "caswhois_token_view", Value: value, Path: "/server/preferences/tokens", MaxAge: 60, HttpOnly: true, Secure: !isI2PRequest(r), SameSite: http.SameSiteStrictMode})
	return nil
}

func (s *Server) verifyTokenViewCookie(ctx context.Context, value string) (string, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 || parts[0] == "" || len(parts[1]) != sha256.Size*2 {
		return "", false
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", false
	}
	key, err := s.database.AppSecret(ctx, "cookie_signing_key")
	if err != nil {
		return "", false
	}
	if validTokenViewMAC(key, parts[0], parts[1]) {
		return parts[0], true
	}
	var previous, until string
	if err := s.database.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name='cookie_signing_key_previous'`).Scan(&previous); err != nil {
		return "", false
	}
	if err := s.database.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name='cookie_signing_key_previous_until'`).Scan(&until); err != nil {
		return "", false
	}
	deadline, err := time.Parse(time.RFC3339, until)
	if err != nil || !time.Now().UTC().Before(deadline) {
		return "", false
	}
	previousKey, err := base64.StdEncoding.DecodeString(previous)
	if err != nil || len(previousKey) != 32 || !validTokenViewMAC(previousKey, parts[0], parts[1]) {
		return "", false
	}
	return parts[0], true
}

func validTokenViewMAC(key []byte, id, supplied string) bool {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("caswhois_token_view:" + id))
	return hmac.Equal([]byte(supplied), []byte(hex.EncodeToString(mac.Sum(nil))))
}

func (s *Server) ownerAPIRequest(r *http.Request, primary *ownerTokenRecord, method, path string, body []byte) *http.Request {
	request := r.Clone(r.Context())
	request.Method = method
	request.URL.Path = s.config.APIBasePath() + "/server/preferences" + path
	request.Header = r.Header.Clone()
	request.Header.Set("Authorization", "Bearer "+primaryTokenValue(r))
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func primaryTokenValue(r *http.Request) string {
	cookie, _ := r.Cookie(ownerTokenCookieName)
	if cookie == nil {
		return ""
	}
	return cookie.Value
}

func (s *Server) handleRevealPrimaryTokenAPI(w http.ResponseWriter, r *http.Request) {
	if s.authFailureBlocked(w, r) {
		return
	}
	record, err := s.ownerFromRequest(r, false)
	if err != nil {
		if s.recordAuthFailure(w, r) {
			return
		}
		SendError(w, ErrUnauthorized, "Primary token required")
		return
	}
	if record.Kind != "primary" {
		SendError(w, ErrForbidden, "Primary token required")
		return
	}
	if err := s.auditOwnerTokenEvent(r, "token.revealed", record); err != nil {
		SendError(w, ErrServerError, "Could not record token access")
		return
	}
	key, err := s.encryptionKey()
	if err != nil {
		SendError(w, ErrServerError, "Token is unavailable")
		return
	}
	raw, err := parseStoredToken(key, record.Encrypted)
	if err != nil {
		SendError(w, ErrServerError, "Token is unavailable")
		return
	}
	SendSuccess(w, map[string]string{"id": record.ID, "kind": "primary", "owner_token": raw})
}

func (s *Server) handleListOwnerTokensAPI(w http.ResponseWriter, r *http.Request) {
	record := s.requirePrimaryTokenAPI(w, r)
	if record == nil {
		return
	}
	rows, err := s.database.Read().QueryContext(r.Context(), `SELECT id, kind, name, token_prefix, token_last4,
		created_at, last_used_at, expires_at, revoked_at FROM api_tokens WHERE owner_id = ? ORDER BY created_at`, record.OwnerID)
	if err != nil {
		SendError(w, ErrServerError, "Could not list tokens")
		return
	}
	defer func() { _ = rows.Close() }()
	tokens := make([]map[string]any, 0)
	for rows.Next() {
		var id, kind, prefix, last4 string
		var name sql.NullString
		var created int64
		var used, expires, revoked sql.NullInt64
		if err := rows.Scan(&id, &kind, &name, &prefix, &last4, &created, &used, &expires, &revoked); err != nil {
			SendError(w, ErrServerError, "Could not list tokens")
			return
		}
		status := "active"
		if revoked.Valid {
			status = "revoked"
		} else if expires.Valid && expires.Int64 <= time.Now().Unix() {
			status = "expired"
		}
		tokens = append(tokens, map[string]any{"id": id, "kind": kind, "name": name.String,
			"token_masked": maskedOwnerToken(last4), "created_at": time.Unix(created, 0).UTC().Format(time.RFC3339),
			"last_used_at": nullableTime(used), "expires_at": nullableTime(expires), "status": status})
	}
	if err := rows.Err(); err != nil {
		SendError(w, ErrServerError, "Could not list tokens")
		return
	}
	if len(tokens) == 0 {
		SendError(w, ErrUnauthorized, "Primary token required")
		return
	}
	primary := map[string]any{}
	linked := make([]map[string]any, 0)
	for _, token := range tokens {
		if token["kind"] == "primary" {
			primary = token
		} else {
			linked = append(linked, token)
		}
	}
	SendSuccess(w, map[string]any{"primary": primary, "linked": linked, "max_linked": s.config.Tokens.MaxLinked})
}

func (s *Server) requirePrimaryTokenAPI(w http.ResponseWriter, r *http.Request) *ownerTokenRecord {
	if s.authFailureBlocked(w, r) {
		return nil
	}
	record, err := s.ownerFromRequest(r, false)
	if err != nil {
		if s.recordAuthFailure(w, r) {
			return nil
		}
		SendError(w, ErrUnauthorized, "Primary token required")
		return nil
	}
	if record.Kind != "primary" {
		SendError(w, ErrForbidden, "Primary token required")
		return nil
	}
	return record
}

type linkedTokenRequest struct {
	Name      string `json:"name"`
	Expires   string `json:"expires"`
	ExpiresOn string `json:"expires_on"`
}

func decodeLinkedTokenRequest(w http.ResponseWriter, r *http.Request) (*linkedTokenRequest, error) {
	defer func() { _ = r.Body.Close() }()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	var request linkedTokenRequest
	if err := decoder.Decode(&request); err != nil {
		return nil, err
	}
	return &request, nil
}

func parseTokenExpiry(expires, expiresOn string, now time.Time) (*int64, error) {
	if expires != "" && expiresOn != "" {
		return nil, fmt.Errorf("expires and expires_on cannot both be set")
	}
	if expiresOn != "" {
		day, err := time.Parse("2006-01-02", expiresOn)
		if err != nil || day.Before(time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)) {
			return nil, fmt.Errorf("expires_on must be today or later in UTC")
		}
		end := day.AddDate(0, 0, 1).Unix()
		return &end, nil
	}
	if expires == "" || expires == "never" {
		return nil, nil
	}
	var duration time.Duration
	switch expires {
	case "7d":
		duration = 7 * 24 * time.Hour
	case "30d":
		duration = 30 * 24 * time.Hour
	case "90d":
		duration = 90 * 24 * time.Hour
	case "1y":
		duration = 365 * 24 * time.Hour
	default:
		return nil, fmt.Errorf("expires must be never, 7d, 30d, 90d, or 1y")
	}
	value := now.UTC().Add(duration).Unix()
	return &value, nil
}

func (s *Server) handleCreateLinkedTokenAPI(w http.ResponseWriter, r *http.Request) {
	primary := s.requirePrimaryTokenAPI(w, r)
	if primary == nil {
		return
	}
	request, err := decodeLinkedTokenRequest(w, r)
	if err != nil || len(strings.TrimSpace(request.Name)) == 0 || len([]rune(strings.TrimSpace(request.Name))) > 64 {
		SendError(w, ErrValidationFailed, "Name must contain 1 to 64 characters")
		return
	}
	name := strings.TrimSpace(request.Name)
	expires, err := parseTokenExpiry(request.Expires, request.ExpiresOn, time.Now())
	if err != nil {
		SendError(w, ErrValidationFailed, err.Error())
		return
	}
	limit := s.config.Tokens.MaxLinked
	if limit <= 0 {
		limit = 25
	}
	raw, err := generateOwnerToken()
	if err != nil {
		SendError(w, ErrServerError, "Could not create linked token")
		return
	}
	key, err := s.encryptionKey()
	if err != nil {
		SendError(w, ErrServerError, "Could not create linked token")
		return
	}
	encrypted, err := security.EncryptAESGCM(key, raw)
	if err != nil {
		SendError(w, ErrServerError, "Could not create linked token")
		return
	}
	id, err := uuid.NewV7()
	if err != nil {
		SendError(w, ErrServerError, "Could not create linked token")
		return
	}
	hash := sha256.Sum256([]byte(raw))
	createdAt := time.Now().Unix()
	var conflict error
	for attempt := 0; attempt < 5; attempt++ {
		conflict = nil
		err = s.database.Write(r.Context(), func(tx *sql.Tx) error {
			// Touch the owner row first to serialize this owner's quota checks
			// across concurrent transactions, including remote libSQL writers.
			result, err := tx.ExecContext(r.Context(), `UPDATE owners SET last_seen_at = last_seen_at WHERE id = ?`, primary.OwnerID)
			if err != nil {
				return err
			}
			if affected, err := result.RowsAffected(); err != nil {
				return err
			} else if affected == 0 {
				return sql.ErrNoRows
			}
			var duplicate int
			if err := tx.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM api_tokens WHERE owner_id = ? AND kind = 'linked' AND name = ?`, primary.OwnerID, name).Scan(&duplicate); err != nil {
				return err
			}
			if duplicate != 0 {
				conflict = errLinkedTokenNameConflict
				return conflict
			}
			var active int
			if err := tx.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM api_tokens WHERE owner_id = ? AND kind = 'linked' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`, primary.OwnerID, time.Now().Unix()).Scan(&active); err != nil {
				return err
			}
			if active >= limit {
				conflict = errLinkedTokenLimitConflict
				return conflict
			}
			_, err = tx.ExecContext(r.Context(), `INSERT INTO api_tokens
				(id, owner_id, kind, name, token_hash, token_prefix, token_last4, token_enc, expires_at)
				VALUES (?, ?, 'linked', ?, ?, ?, ?, ?, ?)`, id.String(), primary.OwnerID, name, hex.EncodeToString(hash[:]), raw[:12], raw[len(raw)-4:], encrypted, expires)
			return err
		})
		if err == nil || errors.Is(err, errLinkedTokenNameConflict) || errors.Is(err, errLinkedTokenLimitConflict) || !isOwnerTokenWriteConflict(err) || r.Context().Err() != nil {
			break
		}
		select {
		case <-time.After(time.Duration(25<<attempt) * time.Millisecond):
		case <-r.Context().Done():
			err = r.Context().Err()
		}
	}
	if errors.Is(err, errLinkedTokenNameConflict) || isLinkedTokenNameUniqueConflict(err) {
		SendError(w, ErrConflict, "A token with that name already exists")
		return
	}
	if errors.Is(err, errLinkedTokenLimitConflict) {
		SendError(w, ErrConflict, "Maximum active linked tokens reached")
		return
	}
	if err != nil {
		SendError(w, ErrServerError, "Could not create linked token")
		return
	}
	linked := &ownerTokenRecord{ID: id.String(), OwnerID: primary.OwnerID, Kind: "linked", Name: sql.NullString{String: name, Valid: true}, Prefix: raw[:12], Last4: raw[len(raw)-4:], Encrypted: encrypted, CreatedAt: createdAt}
	if expires != nil {
		linked.ExpiresAt = sql.NullInt64{Int64: *expires, Valid: true}
	}
	if err := s.auditOwnerTokenEvent(r, "token.created", linked); err != nil {
		SendError(w, ErrServerError, "Could not record token creation")
		return
	}
	data := ownerTokenPublicView(linked)
	data["linked_token"] = raw
	writeJSON(w, http.StatusCreated, APIResponse{OK: true, Data: data})
}

func ownerTokenPublicView(record *ownerTokenRecord) map[string]any {
	status := ownerTokenStatus(record)
	return map[string]any{"id": record.ID, "name": record.Name.String, "kind": record.Kind,
		"token_masked": maskedOwnerToken(record.Last4),
		"created_at":   time.Unix(record.CreatedAt, 0).UTC().Format(time.RFC3339),
		"last_used_at": nullableTime(record.LastUsed), "expires_at": nullableTime(record.ExpiresAt), "status": status}
}

func ownerTokenStatus(record *ownerTokenRecord) string {
	if record.RevokedAt.Valid {
		return "revoked"
	}
	if record.ExpiresAt.Valid && record.ExpiresAt.Int64 <= time.Now().Unix() {
		return "expired"
	}
	return "active"
}

func prepareOwnerTokenPageRecord(record *ownerTokenRecord) {
	if record == nil {
		return
	}
	record.Status = ownerTokenStatus(record)
	record.Masked = maskedOwnerToken(record.Last4)
	record.CreatedText = time.Unix(record.CreatedAt, 0).UTC().Format("2006-01-02 15:04:05 UTC")
	if record.LastUsed.Valid {
		record.LastUsedText = time.Unix(record.LastUsed.Int64, 0).UTC().Format("2006-01-02 15:04:05 UTC")
	}
	if record.ExpiresAt.Valid {
		record.ExpiresText = time.Unix(record.ExpiresAt.Int64, 0).UTC().Format("2006-01-02 15:04:05 UTC")
	}
}

func (s *Server) getOwnedLinkedToken(ctx context.Context, ownerID, id string) (*ownerTokenRecord, error) {
	record := &ownerTokenRecord{}
	err := s.database.Read().QueryRowContext(ctx, `SELECT id, owner_id, kind, name, token_prefix, token_last4, token_enc, created_at, expires_at, last_used_at, revoked_at FROM api_tokens WHERE id = ? AND owner_id = ? AND kind = 'linked'`, id, ownerID).Scan(
		&record.ID, &record.OwnerID, &record.Kind, &record.Name, &record.Prefix, &record.Last4, &record.Encrypted, &record.CreatedAt, &record.ExpiresAt, &record.LastUsed, &record.RevokedAt)
	return record, err
}

func (s *Server) handleRevealLinkedTokenAPI(w http.ResponseWriter, r *http.Request) {
	primary := s.requirePrimaryTokenAPI(w, r)
	if primary == nil {
		return
	}
	record, err := s.getOwnedLinkedToken(r.Context(), primary.OwnerID, chi.URLParam(r, "id"))
	if err != nil || record.RevokedAt.Valid {
		SendError(w, ErrNotFound, "Token not found")
		return
	}
	if err := s.auditOwnerTokenEvent(r, "token.revealed", record); err != nil {
		SendError(w, ErrServerError, "Could not record token access")
		return
	}
	key, err := s.encryptionKey()
	if err != nil {
		SendError(w, ErrServerError, "Token is unavailable")
		return
	}
	raw, err := parseStoredToken(key, record.Encrypted)
	if err != nil {
		SendError(w, ErrServerError, "Token is unavailable")
		return
	}
	data := ownerTokenPublicView(record)
	data["linked_token"] = raw
	SendSuccess(w, data)
}

func (s *Server) rotateOwnedToken(w http.ResponseWriter, r *http.Request, record *ownerTokenRecord) {
	raw, err := generateOwnerToken()
	if err != nil {
		SendError(w, ErrServerError, "Could not rotate token")
		return
	}
	key, err := s.encryptionKey()
	if err != nil {
		SendError(w, ErrServerError, "Could not rotate token")
		return
	}
	encrypted, err := security.EncryptAESGCM(key, raw)
	if err != nil {
		SendError(w, ErrServerError, "Could not rotate token")
		return
	}
	hash := sha256.Sum256([]byte(raw))
	err = s.database.Write(r.Context(), func(tx *sql.Tx) error {
		result, err := tx.ExecContext(r.Context(), `UPDATE api_tokens SET token_hash = ?, token_prefix = ?, token_last4 = ?, token_enc = ?, rotated_at = ? WHERE id = ? AND owner_id = ? AND revoked_at IS NULL`, hex.EncodeToString(hash[:]), raw[:12], raw[len(raw)-4:], encrypted, time.Now().Unix(), record.ID, record.OwnerID)
		if err != nil {
			return err
		}
		if rows, err := result.RowsAffected(); err != nil || rows != 1 {
			return sql.ErrNoRows
		}
		return rotateCSRFSecretTx(r.Context(), tx)
	})
	if err != nil {
		SendError(w, ErrServerError, "Could not rotate token")
		return
	}
	record.Prefix, record.Last4, record.Encrypted = raw[:12], raw[len(raw)-4:], encrypted
	if err := s.auditOwnerTokenEvent(r, "token.rotated", record); err != nil {
		SendError(w, ErrServerError, "Could not record token rotation")
		return
	}
	data := ownerTokenPublicView(record)
	if record.Kind == "primary" {
		data["owner_token"] = raw
		setOwnerCookie(w, r, raw, ownerCookieMaxAge(s.config.Tokens.CookieMaxAge))
	} else {
		data["linked_token"] = raw
	}
	SendSuccess(w, data)
}

func (s *Server) handleRotatePrimaryTokenAPI(w http.ResponseWriter, r *http.Request) {
	primary := s.requirePrimaryTokenAPI(w, r)
	if primary != nil {
		s.rotateOwnedToken(w, r, primary)
	}
}

func (s *Server) handleRotateLinkedTokenAPI(w http.ResponseWriter, r *http.Request) {
	primary := s.requirePrimaryTokenAPI(w, r)
	if primary == nil {
		return
	}
	record, err := s.getOwnedLinkedToken(r.Context(), primary.OwnerID, chi.URLParam(r, "id"))
	if err != nil || record.RevokedAt.Valid {
		SendError(w, ErrNotFound, "Token not found")
		return
	}
	s.rotateOwnedToken(w, r, record)
}

func (s *Server) handleUpdateLinkedTokenAPI(w http.ResponseWriter, r *http.Request) {
	primary := s.requirePrimaryTokenAPI(w, r)
	if primary == nil {
		return
	}
	record, err := s.getOwnedLinkedToken(r.Context(), primary.OwnerID, chi.URLParam(r, "id"))
	if err != nil || record.RevokedAt.Valid {
		SendError(w, ErrNotFound, "Token not found")
		return
	}
	request, err := decodeLinkedTokenRequest(w, r)
	if err != nil || (request.Name == "" && request.Expires == "" && request.ExpiresOn == "") {
		SendError(w, ErrValidationFailed, "Provide a name or expiry change")
		return
	}
	name := record.Name.String
	if request.Name != "" {
		name = strings.TrimSpace(request.Name)
		if len([]rune(name)) == 0 || len([]rune(name)) > 64 {
			SendError(w, ErrValidationFailed, "Name must contain 1 to 64 characters")
			return
		}
	}
	var expires any
	if request.Expires != "" || request.ExpiresOn != "" {
		parsed, err := parseTokenExpiry(request.Expires, request.ExpiresOn, time.Now())
		if err != nil {
			SendError(w, ErrValidationFailed, err.Error())
			return
		}
		if parsed != nil {
			expires = *parsed
		}
	}
	err = s.database.Write(r.Context(), func(tx *sql.Tx) error {
		if request.Name != "" {
			if _, err := tx.ExecContext(r.Context(), `UPDATE owners SET last_seen_at = last_seen_at WHERE id = ?`, primary.OwnerID); err != nil {
				return err
			}
			var duplicate int
			if err := tx.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM api_tokens WHERE owner_id = ? AND kind = 'linked' AND name = ? AND id <> ?`, primary.OwnerID, name, record.ID).Scan(&duplicate); err != nil {
				return err
			}
			if duplicate != 0 {
				return errLinkedTokenNameConflict
			}
			if _, err := tx.ExecContext(r.Context(), `UPDATE api_tokens SET name = ? WHERE id = ? AND owner_id = ?`, name, record.ID, primary.OwnerID); err != nil {
				return err
			}
		}
		if request.Expires != "" || request.ExpiresOn != "" {
			if _, err := tx.ExecContext(r.Context(), `UPDATE api_tokens SET expires_at = ? WHERE id = ? AND owner_id = ?`, expires, record.ID, primary.OwnerID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errLinkedTokenNameConflict) || isLinkedTokenNameUniqueConflict(err) {
			SendError(w, ErrConflict, "A token with that name already exists")
			return
		}
		SendError(w, ErrServerError, "Could not update token")
		return
	}
	record.Name = sql.NullString{String: name, Valid: true}
	if expires == nil {
		record.ExpiresAt = sql.NullInt64{}
	} else {
		record.ExpiresAt = sql.NullInt64{Int64: expires.(int64), Valid: true}
	}
	if err := s.auditOwnerTokenEvent(r, "token.updated", record); err != nil {
		SendError(w, ErrServerError, "Could not record token update")
		return
	}
	SendSuccess(w, ownerTokenPublicView(record))
}

func (s *Server) handleRevokeLinkedTokenAPI(w http.ResponseWriter, r *http.Request) {
	primary := s.requirePrimaryTokenAPI(w, r)
	if primary == nil {
		return
	}
	record, err := s.getOwnedLinkedToken(r.Context(), primary.OwnerID, chi.URLParam(r, "id"))
	if err != nil || record.RevokedAt.Valid {
		SendError(w, ErrNotFound, "Token not found")
		return
	}
	now := time.Now().Unix()
	if err := s.database.ExecWrite(r.Context(), `UPDATE api_tokens SET revoked_at = ?, revoked_reason = 'owner_action' WHERE id = ? AND owner_id = ?`, now, record.ID, primary.OwnerID); err != nil {
		SendError(w, ErrServerError, "Could not revoke token")
		return
	}
	record.RevokedAt = sql.NullInt64{Int64: now, Valid: true}
	if err := s.auditOwnerTokenEvent(r, "token.revoked", record); err != nil {
		SendError(w, ErrServerError, "Could not record token revocation")
		return
	}
	clearSiteDataOnTokenRevocation(w)
	SendSuccess(w, map[string]string{"id": record.ID, "status": "revoked"})
}

func (s *Server) handleRevokePrimaryTokenAPI(w http.ResponseWriter, r *http.Request) {
	primary := s.requirePrimaryTokenAPI(w, r)
	if primary == nil {
		return
	}
	var request struct {
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&request); err != nil || subtle.ConstantTimeCompare([]byte(request.Confirm), []byte(primary.Last4)) != 1 {
		SendError(w, ErrValidationFailed, "Primary token confirmation did not match")
		return
	}
	tokens, resources, err := s.deleteOwner(r, primary, "api")
	if err != nil {
		SendError(w, ErrServerError, "Could not revoke owner")
		return
	}
	clearSiteDataOnTokenRevocation(w)
	SendSuccess(w, map[string]int{"tokens": tokens, "resources": resources})
}

func clearSiteDataOnTokenRevocation(w http.ResponseWriter) {
	w.Header().Set("Clear-Site-Data", `"cache", "cookies", "storage"`)
}

func (s *Server) deleteOwner(r *http.Request, primary *ownerTokenRecord, source string) (int, int, error) {
	var tokens int
	resources := 0
	var details []byte
	actorIP := extractClientIP(r, s.config.TrustedProxies.Additional)
	err := s.database.Write(r.Context(), func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM api_tokens WHERE owner_id = ?`, primary.OwnerID).Scan(&tokens); err != nil {
			return err
		}
		var err error
		details, err = json.Marshal(map[string]any{"scope": "owner", "tokens": tokens, "resources": resources, "source": source})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(r.Context(), `INSERT INTO audit_log (category, action, actor_ip, target_type, target_id, details)
			VALUES ('token', 'token.revoked', ?, 'owner', ?, ?)`, actorIP, primary.OwnerID, string(details)); err != nil {
			return err
		}
		_, err = tx.ExecContext(r.Context(), `DELETE FROM owners WHERE id = ?`, primary.OwnerID)
		return err
	})
	if err != nil {
		return 0, 0, err
	}
	if s.logger != nil {
		s.logger.WriteAudit(caslogger.AuditEntry{Category: "token", Action: "token.revoked", ActorIP: actorIP,
			TargetType: "owner", TargetID: primary.OwnerID, Details: string(details), Success: true})
	}
	return tokens, resources, nil
}

func nullableTime(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return time.Unix(value.Int64, 0).UTC().Format(time.RFC3339)
}

func (s *Server) handleOwnerTokensPage(w http.ResponseWriter, r *http.Request) {
	page := ownerTokensPageData{translatablePageData: s.newPageData(w, r), Name: s.brandName()}
	var record *ownerTokenRecord
	var err error
	if cookie, cookieErr := r.Cookie(ownerTokenCookieName); cookieErr == nil {
		record, err = s.lookupOwnerToken(r.Context(), cookie.Value)
	} else {
		err = sql.ErrNoRows
	}
	if err == nil {
		if record.Kind != "primary" {
			clearOwnerCookie(w, r)
			err = sql.ErrNoRows
		}
	}
	if err == nil {
		page.HasOwner = true
		page.Primary = record
		prepareOwnerTokenPageRecord(record)
		rows, queryErr := s.database.Read().QueryContext(r.Context(), `SELECT id, owner_id, kind, name, token_prefix, token_last4, token_enc, created_at, expires_at, last_used_at, revoked_at FROM api_tokens WHERE owner_id = ? AND kind = 'linked' ORDER BY created_at`, record.OwnerID)
		if queryErr == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				linked := &ownerTokenRecord{}
				if rows.Scan(&linked.ID, &linked.OwnerID, &linked.Kind, &linked.Name, &linked.Prefix, &linked.Last4, &linked.Encrypted, &linked.CreatedAt, &linked.ExpiresAt, &linked.LastUsed, &linked.RevokedAt) == nil {
					prepareOwnerTokenPageRecord(linked)
					page.Linked = append(page.Linked, linked)
				}
			}
		}
		if viewCookie, viewErr := r.Cookie("caswhois_token_view"); viewErr == nil {
			viewID, validViewCookie := s.verifyTokenViewCookie(r.Context(), viewCookie.Value)
			viewRecord := record
			if !validViewCookie {
				viewRecord = nil
			} else if viewID != "primary" {
				if linked, linkedErr := s.getOwnedLinkedToken(r.Context(), record.OwnerID, viewID); linkedErr == nil && !linked.RevokedAt.Valid {
					viewRecord = linked
				} else {
					viewRecord = nil
				}
			} else if record.Kind != "primary" {
				viewRecord = nil
			}
			if viewRecord != nil {
				if key, keyErr := s.encryptionKey(); keyErr == nil {
					if raw, decryptErr := parseStoredToken(key, viewRecord.Encrypted); decryptErr == nil {
						page.RevealedToken = raw
						page.RevealedID = viewID
						w.Header().Set("Cache-Control", "private, no-store")
					}
				}
			}
			http.SetCookie(w, &http.Cookie{Name: "caswhois_token_view", Value: "", Path: "/server/preferences/tokens", MaxAge: -1, HttpOnly: true, Secure: !isI2PRequest(r), SameSite: http.SameSiteStrictMode})
		}
	} else {
		clearOwnerCookie(w, r)
		w.Header().Set("Cache-Control", "private, no-store")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ownerTokensTemplate.ExecuteTemplate(w, "public.tmpl", page); err != nil {
		return
	}
}

type ownerTokensPageData struct {
	translatablePageData
	Name          string
	HasOwner      bool
	Primary       *ownerTokenRecord
	Linked        []*ownerTokenRecord
	RevealedToken string
	RevealedID    string
}

var ownerTokensTemplate = mustParseTemplate("owner_tokens", "page/owner_tokens.tmpl")

func (s *Server) handleRestoreOwnerTokenPage(w http.ResponseWriter, r *http.Request) {
	if s.authFailureBlocked(w, r) {
		return
	}
	token := strings.TrimSpace(r.FormValue("token"))
	record, err := s.lookupOwnerToken(r.Context(), token)
	if err != nil || record.Kind != "primary" {
		if s.recordAuthFailure(w, r) {
			return
		}
		clearOwnerCookie(w, r)
		writeRequestError(w, r, http.StatusUnauthorized)
		return
	}
	if err := s.auditOwnerTokenEvent(r, "token.restored", record); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
		return
	}
	setOwnerCookie(w, r, token, ownerCookieMaxAge(s.config.Tokens.CookieMaxAge))
	http.Redirect(w, r, s.BuildURL(r, "/server/preferences/tokens"), http.StatusSeeOther)
}

func (s *Server) handleForgetOwnerTokenPage(w http.ResponseWriter, r *http.Request) {
	clearOwnerCookie(w, r)
	w.Header().Set("Clear-Site-Data", `"storage"`)
	http.Redirect(w, r, s.BuildURL(r, "/server/preferences/tokens"), http.StatusSeeOther)
}

func parseStoredToken(key []byte, encrypted string) (string, error) {
	return security.DecryptAESGCM(key, encrypted)
}

func (s *Server) auditOwnerTokenEvent(r *http.Request, action string, record *ownerTokenRecord) error {
	details, err := json.Marshal(map[string]string{"token_prefix": record.Prefix})
	if err != nil {
		return err
	}
	actorIP := extractClientIP(r, s.config.TrustedProxies.Additional)
	if err := s.database.ExecWrite(r.Context(), `INSERT INTO audit_log
		(category, action, actor_ip, target_type, target_id, details)
		VALUES ('token', ?, ?, 'owner', ?, ?)`, action, actorIP, record.OwnerID, string(details)); err != nil {
		return err
	}
	if s.logger != nil {
		s.logger.WriteAudit(caslogger.AuditEntry{Category: "token", Action: action, ActorIP: actorIP,
			TargetType: "owner", TargetID: record.OwnerID, Details: string(details), Success: true})
	}
	return nil
}
