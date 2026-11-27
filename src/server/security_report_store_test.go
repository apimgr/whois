package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apimgr/whois/src/config"
	"github.com/apimgr/whois/src/security"
)

func TestStoreSecurityReportUsesConfiguredEncryption(t *testing.T) {
	for _, usePGP := range []bool{false, true} {
		name := "aes_fallback"
		if usePGP {
			name = "project_pgp"
		}
		t.Run(name, func(t *testing.T) {
			s := newTestServer(t)
			cfg := config.Default()
			cfg.ConfigDir = t.TempDir()
			cfg.Security.EncryptionKey, _ = config.GenerateEncryptionKey()
			s.config = cfg
			if usePGP {
				secret, err := s.database.AppSecret(t.Context(), "installation_secret")
				if err != nil {
					t.Fatal(err)
				}
				if err := security.GeneratePGPKeypair(cfg.ConfigDir, "caswhois", "security@example.test", string(secret)); err != nil {
					t.Fatal(err)
				}
			}
			securityID, err := s.currentSecurityID(t.Context(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			input := securityReportInput{Name: "Researcher", Email: "researcher@example.test", Summary: "Example issue", Steps: "Step one", Impact: "Impact", Severity: "low", Component: "api", CreditPreference: "no"}
			tracking, _, err := s.storeSecurityReport(t.Context(), httptest.NewRequest("POST", "/server/contact", nil), securityID, input)
			if err != nil {
				t.Fatal(err)
			}
			var body, algorithm, contact string
			if err := s.database.Read().QueryRowContext(t.Context(), `SELECT body_enc,body_alg,contact_enc FROM security_reports WHERE tracking_id=?`, tracking).Scan(&body, &algorithm, &contact); err != nil {
				t.Fatal(err)
			}
			key, err := base64.StdEncoding.DecodeString(cfg.Security.EncryptionKey)
			if err != nil {
				t.Fatal(err)
			}
			plainContact, err := security.DecryptAESGCM(key, contact)
			if err != nil {
				t.Fatal(err)
			}
			var contactValues map[string]string
			if err := json.Unmarshal([]byte(plainContact), &contactValues); err != nil || contactValues["email"] != input.Email {
				t.Fatalf("contact decryption = %v, err %v", contactValues, err)
			}
			if usePGP {
				if algorithm != "pgp" || !strings.Contains(body, "-----BEGIN PGP MESSAGE-----") {
					t.Fatalf("PGP body algorithm=%q body prefix=%q", algorithm, body[:min(len(body), 40)])
				}
			} else {
				if algorithm != "aes-256-gcm" {
					t.Fatalf("fallback algorithm = %q", algorithm)
				}
				plainBody, err := security.DecryptAESGCM(key, body)
				if err != nil || !strings.Contains(plainBody, input.Summary) {
					t.Fatalf("AES report body decrypt failed: %v", err)
				}
			}
			if _, err := os.Stat(filepath.Join(cfg.ConfigDir, "security", security.PGPPublicKeyFile)); usePGP && err != nil {
				t.Fatalf("project PGP public key missing: %v", err)
			}
		})
	}
}
