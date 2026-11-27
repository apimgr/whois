package scheduler

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apimgr/whois/src/db"
)

func TestTaskSecretRotationRotatesOnlyDueSecrets(t *testing.T) {
	root := filepath.Join(t.TempDir(), "database")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := db.New(context.Background(), &db.DatabaseConfig{Driver: "sqlite", Path: root, Pool: db.DefaultPoolConfig()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	scheduler := &Scheduler{store: database}
	ctx := context.Background()
	oldValues := map[string]string{}
	for _, name := range []string{"cookie_signing_key", "csrf_token_secret"} {
		old, err := database.AppSecret(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		oldValues[name] = base64.StdEncoding.EncodeToString(old)
		if _, err := database.ExecResult(ctx, `UPDATE app_secrets SET updated_at=? WHERE name=?`, time.Now().UTC().Add(-400*24*time.Hour).Format(time.RFC3339), name); err != nil {
			t.Fatal(err)
		}
	}
	if err := scheduler.taskSecretRotation(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cookie_signing_key", "csrf_token_secret"} {
		var current, previous string
		if err := database.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name=?`, name).Scan(&current); err != nil {
			t.Fatal(err)
		}
		if err := database.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name=?`, name+"_previous").Scan(&previous); err != nil {
			t.Fatal(err)
		}
		if current == oldValues[name] || previous != oldValues[name] {
			t.Fatalf("%s rotation current/previous values are incorrect", name)
		}
		if err := scheduler.rotateAppSecretIfDue(ctx, name, 90*24*time.Hour, 7*24*time.Hour); err != nil {
			t.Fatal(err)
		}
		var unchanged string
		if err := database.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name=?`, name).Scan(&unchanged); err != nil || unchanged != current {
			t.Fatalf("%s rotated again before due: unchanged=%t, err=%v", name, unchanged == current, err)
		}
	}
}
