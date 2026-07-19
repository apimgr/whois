package db

import (
	"context"
	"strings"
	"testing"
	"time"
)

// --- validateLibSQL ---

func TestValidateLibSQL_NilConfig(t *testing.T) {
	if err := validateLibSQL(nil); err == nil {
		t.Fatal("expected error for nil config, got nil")
	}
}

func TestValidateLibSQL_EmptyURL(t *testing.T) {
	err := validateLibSQL(&DatabaseConfig{Driver: "libsql"})
	if err == nil {
		t.Fatal("expected error for empty url, got nil")
	}
	if !strings.Contains(err.Error(), "requires url") {
		t.Errorf("error = %v, want message mentioning %q", err, "requires url")
	}
}

func TestValidateLibSQL_WhitespaceOnlyURL(t *testing.T) {
	err := validateLibSQL(&DatabaseConfig{Driver: "libsql", URL: "   "})
	if err == nil {
		t.Fatal("expected error for whitespace-only url, got nil")
	}
}

func TestValidateLibSQL_ValidURL(t *testing.T) {
	err := validateLibSQL(&DatabaseConfig{Driver: "libsql", URL: "libsql://example.turso.io"})
	if err != nil {
		t.Fatalf("expected no error for valid url, got %v", err)
	}
}

// --- buildLibSQLDSN ---

func TestBuildLibSQLDSN_NoToken(t *testing.T) {
	dsn := buildLibSQLDSN("libsql://example.turso.io", "")
	if dsn != "libsql://example.turso.io" {
		t.Errorf("buildLibSQLDSN = %q, want unchanged url", dsn)
	}
}

func TestBuildLibSQLDSN_TokenAppendedWithQuestionMark(t *testing.T) {
	dsn := buildLibSQLDSN("libsql://example.turso.io", "secret-token")
	want := "libsql://example.turso.io?authToken=secret-token"
	if dsn != want {
		t.Errorf("buildLibSQLDSN = %q, want %q", dsn, want)
	}
}

func TestBuildLibSQLDSN_TokenAppendedWithAmpersand(t *testing.T) {
	dsn := buildLibSQLDSN("libsql://example.turso.io?foo=bar", "secret-token")
	want := "libsql://example.turso.io?foo=bar&authToken=secret-token"
	if dsn != want {
		t.Errorf("buildLibSQLDSN = %q, want %q", dsn, want)
	}
}

func TestBuildLibSQLDSN_ExistingAuthTokenNotDuplicated(t *testing.T) {
	url := "libsql://example.turso.io?authToken=already-set"
	dsn := buildLibSQLDSN(url, "different-token")
	if dsn != url {
		t.Errorf("buildLibSQLDSN = %q, want unchanged url %q", dsn, url)
	}
}

// --- NewLibSQL / New dispatch ---
//
// No live libsql/Turso server is available in the test environment, so these
// tests verify driver dispatch and error-handling wiring rather than a live
// round-trip: an invalid/empty URL must fail validation before any network
// connection is attempted. A syntactically valid but unreachable URL is
// accepted by sql.Open/Ping (the libsql HTTP driver is lazy and does not
// dial until the first query), so the failure surfaces once ensureSchema
// issues its first statement — that must still be a connection error, never
// a fall-through to "unsupported database driver".

func TestNewLibSQL_MissingURL(t *testing.T) {
	cfg := &DatabaseConfig{
		Driver: "libsql",
		Pool:   DefaultPoolConfig(),
	}
	_, err := NewLibSQL(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for missing url, got nil")
	}
	if !strings.Contains(err.Error(), "requires url") {
		t.Errorf("error = %v, want message mentioning %q", err, "requires url")
	}
}

func TestNewLibSQL_UnreachableURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := &DatabaseConfig{
		Driver: "libsql",
		URL:    "http://127.0.0.1:1",
		Pool:   DefaultPoolConfig(),
	}
	_, err := NewLibSQL(ctx, cfg)
	if err == nil {
		t.Fatal("expected error for unreachable libsql url, got nil")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %v, want a connection error mentioning %q", err, "connection refused")
	}
}

func TestNew_DispatchesToLibSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := &DatabaseConfig{
		Driver: "libsql",
		URL:    "http://127.0.0.1:1",
		Pool:   DefaultPoolConfig(),
	}
	_, err := New(ctx, cfg)
	if err == nil {
		t.Fatal("expected error for unreachable libsql url via New, got nil")
	}
	if strings.Contains(err.Error(), "unsupported database driver") {
		t.Errorf("New(driver=libsql) fell through to unsupported-driver error: %v", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %v, want a connection error mentioning %q", err, "connection refused")
	}
}

func TestNew_LibSQLWithoutURL(t *testing.T) {
	cfg := &DatabaseConfig{
		Driver: "libsql",
		Pool:   DefaultPoolConfig(),
	}
	_, err := New(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for libsql driver without url, got nil")
	}
	if !strings.Contains(err.Error(), "requires url") {
		t.Errorf("error = %v, want message mentioning %q", err, "requires url")
	}
}
