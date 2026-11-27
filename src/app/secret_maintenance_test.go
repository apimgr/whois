package app

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apimgr/whois/src/config"
	"github.com/apimgr/whois/src/db"
	"github.com/apimgr/whois/src/security"
)

func openSecretTestDatabase(t *testing.T) *db.DB {
	t.Helper()
	databaseDir := filepath.Join(t.TempDir(), "database")
	if err := os.MkdirAll(databaseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := db.New(context.Background(), &db.DatabaseConfig{Driver: "sqlite", Path: databaseDir, Pool: db.DefaultPoolConfig()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func TestRotateEncryptionKeyReencryptsSensitiveRowsAndResumes(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.ConfigDir = filepath.Join(root, "config")
	cfg.Database.Dir = filepath.Join(root, "database")
	if err := os.MkdirAll(cfg.Database.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.Security.EncryptionKey, _ = config.GenerateEncryptionKey()
	cfg.Security.EncryptionKeyVersion = 1
	database, err := db.New(ctx, &db.DatabaseConfig{Driver: "sqlite", Path: cfg.Database.Dir, Pool: db.DefaultPoolConfig()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	oldKey, err := base64.StdEncoding.DecodeString(cfg.Security.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	ownerToken, err := security.EncryptAESGCM(oldKey, "own_test_token")
	if err != nil {
		t.Fatal(err)
	}
	reportBody, err := security.EncryptAESGCM(oldKey, `{"summary":"private"}`)
	if err != nil {
		t.Fatal(err)
	}
	contact, err := security.EncryptAESGCM(oldKey, `{"email":"researcher@example.test"}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO owners(id) VALUES('owner-1')`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO api_tokens(id,owner_id,kind,token_hash,token_prefix,token_last4,token_enc) VALUES('token-1','owner-1','primary','hash','own_test','oken',?)`, ownerToken); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO security_reports(tracking_id,id_window,severity,component,body_enc,body_alg,contact_enc,token_hash) VALUES('sec_test',1,'low','api',?,'aes-256-gcm',?,'status-hash')`, []byte(reportBody), []byte(contact))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := rotateEncryptionKey(ctx, database, cfg); err != nil {
		t.Fatal(err)
	}
	newKey, err := base64.StdEncoding.DecodeString(cfg.Security.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Security.EncryptionKeyVersion != 2 {
		t.Fatalf("key version = %d, want 2", cfg.Security.EncryptionKeyVersion)
	}
	var encryptedToken, encryptedBody, encryptedContact string
	if err := database.Read().QueryRowContext(ctx, `SELECT token_enc FROM api_tokens WHERE id='token-1'`).Scan(&encryptedToken); err != nil {
		t.Fatal(err)
	}
	if err := database.Read().QueryRowContext(ctx, `SELECT body_enc,contact_enc FROM security_reports WHERE tracking_id='sec_test'`).Scan(&encryptedBody, &encryptedContact); err != nil {
		t.Fatal(err)
	}
	for got, want := range map[string]string{encryptedToken: "own_test_token", encryptedBody: `{"summary":"private"}`, encryptedContact: `{"email":"researcher@example.test"}`} {
		plain, err := security.DecryptAESGCM(newKey, got)
		if err != nil || plain != want {
			t.Fatalf("decrypt rotated value: got %q, err %v; want %q", plain, err, want)
		}
	}
	previous, err := loadPreviousSecret(ctx, database, "encryption_key", newKey, true)
	if err != nil || string(previous) != string(oldKey) {
		t.Fatalf("previous key = %x, err %v; want old key", previous, err)
	}
	if err := resumeEncryptionKeyRotation(ctx, database, cfg); err != nil {
		t.Fatalf("idempotent resume: %v", err)
	}
	if err := refuseActivePreviousSecret(ctx, database, "encryption_key"); err == nil {
		t.Fatal("second rotation should be refused during the grace period")
	}
}

func TestRotateInstallationSecretKeepsGraceValue(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	databaseDir := filepath.Join(root, "database")
	if err := os.MkdirAll(databaseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := db.New(ctx, &db.DatabaseConfig{Driver: "sqlite", Path: databaseDir, Pool: db.DefaultPoolConfig()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	oldSecret, err := database.AppSecret(ctx, "installation_secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := rotateInstallationSecret(ctx, database, filepath.Join(root, "config")); err != nil {
		t.Fatal(err)
	}
	current, err := database.AppSecret(ctx, "installation_secret")
	if err != nil {
		t.Fatal(err)
	}
	previous, err := loadPreviousSecret(ctx, database, "installation_secret", current, false)
	if err != nil || string(previous) != string(oldSecret) {
		t.Fatalf("previous installation secret = %x, err %v; want old secret", previous, err)
	}
	if string(current) == string(oldSecret) {
		t.Fatal("installation secret did not change")
	}
}

func TestPreviousSecretGraceRetirement(t *testing.T) {
	ctx := context.Background()
	database := openSecretTestDatabase(t)
	if err := refuseActivePreviousSecret(ctx, database, "test_key"); err != nil {
		t.Fatalf("missing previous value: %v", err)
	}
	previous := []byte("previous-test-value")
	current := []byte("current-test-value")
	if err := saveRotatedAppSecret(ctx, database, "test_key", previous, current, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadPreviousSecret(ctx, database, "test_key", current, false)
	if err != nil || string(loaded) != string(previous) {
		t.Fatalf("load grace value = %q, err %v", loaded, err)
	}
	if err := database.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE app_secrets SET value=? WHERE name='test_key_previous_until'`, time.Now().UTC().Add(-time.Hour).Format(time.RFC3339))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := refuseActivePreviousSecret(ctx, database, "test_key"); err != nil {
		t.Fatalf("retire expired value: %v", err)
	}
	loaded, err = loadPreviousSecret(ctx, database, "test_key", current, false)
	if err != nil || len(loaded) != 0 {
		t.Fatalf("previous value after retirement = %q, err %v", loaded, err)
	}
}

func TestRotationConfirmationAndSafetyHelpers(t *testing.T) {
	originalStdin := os.Stdin
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintln(writer, "planned maintenance")
	_, _ = fmt.Fprintln(writer, "ROTATE encryption_key")
	_ = writer.Close()
	os.Stdin = reader
	reason, _, confirmed := confirmSecretRotation("encryption_key")
	os.Stdin = originalStdin
	_ = reader.Close()
	if !confirmed || reason != "planned maintenance" {
		t.Fatalf("confirmation = %q, %t", reason, confirmed)
	}
	if got := sanitizeRotationReason(" unsafe\nreason\x00 "); got != "unsafereason" {
		t.Fatalf("sanitized reason = %q", got)
	}
	if localOperatorIP() == "" {
		t.Fatal("local operator IP must have a fallback")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscan(portText, &port); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Address, cfg.HTTPPort = "127.0.0.1", port
	if !configuredServerIsListening(cfg) {
		t.Fatal("active configured listener was not detected")
	}
	_ = listener.Close()
	if configuredServerIsListening(cfg) {
		t.Fatal("closed configured listener was reported active")
	}
}
