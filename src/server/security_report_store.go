package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/apimgr/whois/src/security"
)

type securityReportInput struct {
	Name, Email, ResearcherGPG, Component, Endpoint, Severity                      string
	Summary, Steps, Impact, SuggestedFix, Timeline, CreditPreference, CreditHandle string
	CVERequested, CoordinatedAgreement                                             bool
	AppVersion, CommitHash, Timestamp, UserAgent                                   string
}

// storeSecurityReport encrypts both the vulnerability body and the separately
// retained researcher contact before writing either value to the database.
func (s *Server) storeSecurityReport(ctx context.Context, request *http.Request, suppliedID string, input securityReportInput) (string, string, error) {
	now := time.Now().UTC()
	if !s.validSecurityID(ctx, suppliedID, now) {
		return "", "", fmt.Errorf("invalid security id")
	}
	window := now.Unix() / securityIDWindowSeconds
	current, _ := s.currentSecurityID(ctx, now)
	if current != suppliedID {
		window--
	}
	key, err := base64.StdEncoding.DecodeString(s.config.Security.EncryptionKey)
	if err != nil || len(key) != 32 {
		return "", "", fmt.Errorf("security report encryption key is unavailable")
	}
	body, err := json.Marshal(map[string]any{"name": input.Name, "email": input.Email, "researcher_gpg": input.ResearcherGPG, "component": input.Component, "endpoint": input.Endpoint, "severity": input.Severity, "summary": input.Summary, "steps": input.Steps, "impact": input.Impact, "suggested_fix": input.SuggestedFix, "timeline_days": input.Timeline, "cve_requested": input.CVERequested, "credit_preference": input.CreditPreference, "credit_handle": input.CreditHandle, "coordinated_disclosure": input.CoordinatedAgreement, "app_version": input.AppVersion, "commit_hash": input.CommitHash, "timestamp": input.Timestamp, "request_user_agent": input.UserAgent})
	if err != nil {
		return "", "", err
	}
	bodyEnc := ""
	bodyAlg := "aes-256-gcm"
	projectPublicKey, keyErr := os.ReadFile(filepath.Join(s.config.ConfigDir, "security", security.PGPPublicKeyFile))
	if keyErr == nil {
		ciphertext, encryptErr := security.EncryptPGP(projectPublicKey, body)
		if encryptErr != nil {
			return "", "", fmt.Errorf("encrypt report with project PGP key: %w", encryptErr)
		}
		bodyEnc = string(ciphertext)
		bodyAlg = "pgp"
	} else if !os.IsNotExist(keyErr) {
		return "", "", fmt.Errorf("read project PGP public key: %w", keyErr)
	} else {
		bodyEnc, err = security.EncryptAESGCM(key, string(body))
		if err != nil {
			return "", "", err
		}
	}
	contactPlain, err := json.Marshal(map[string]string{"email": input.Email, "researcher_gpg": input.ResearcherGPG})
	if err != nil {
		return "", "", err
	}
	contactEnc, err := security.EncryptAESGCM(key, string(contactPlain))
	if err != nil {
		return "", "", err
	}
	trackingBytes := make([]byte, 8)
	if _, err := rand.Read(trackingBytes); err != nil {
		return "", "", err
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", err
	}
	trackingID := "sec_" + hex.EncodeToString(trackingBytes)
	statusToken := hex.EncodeToString(tokenBytes)
	creditPref := map[string]string{"name": "name", "handle": "handle", "anonymous": "anon", "anon": "anon", "no": "no"}[strings.ToLower(input.CreditPreference)]
	if creditPref == "" {
		return "", "", fmt.Errorf("invalid credit preference")
	}
	creditName := ""
	if creditPref == "name" {
		creditName = input.Name
	}
	if creditPref == "handle" {
		creditName = input.CreditHandle
	}
	err = s.database.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO security_reports (tracking_id,id_window,severity,component,body_enc,body_alg,contact_enc,credit_pref,credit_name,cve_requested,token_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)`, trackingID, window, strings.ToLower(input.Severity), input.Component, []byte(bodyEnc), bodyAlg, []byte(contactEnc), creditPref, nullableString(creditName), input.CVERequested, security.HashToken(statusToken))
		return err
	})
	if err != nil {
		return "", "", err
	}
	return trackingID, statusToken, nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func sanitizeLogField(value string) string {
	var b strings.Builder
	for _, r := range value {
		if b.Len() >= 255 {
			break
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(" ._/-", r) {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return strings.TrimSpace(b.String())
}
