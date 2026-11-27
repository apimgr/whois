package db

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// openTempDB opens a real SQLite DB in a temp directory via New, exercising
// the full NewSQLite + ensureSchema path.
func openTempDB(t *testing.T) *DB {
	t.Helper()
	cfg := &DatabaseConfig{
		Driver: "sqlite",
		Path:   t.TempDir(),
		Pool:   DefaultPoolConfig(),
	}
	database, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("openTempDB: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

// --- DefaultPoolConfig ---

func TestDefaultPoolConfig(t *testing.T) {
	cfg := DefaultPoolConfig()

	if cfg.MaxOpen != 25 {
		t.Errorf("MaxOpen: got %d, want 25", cfg.MaxOpen)
	}
	if cfg.MaxIdle != 5 {
		t.Errorf("MaxIdle: got %d, want 5", cfg.MaxIdle)
	}
	if cfg.MaxLifetime != 5*time.Minute {
		t.Errorf("MaxLifetime: got %v, want 5m", cfg.MaxLifetime)
	}
	if cfg.MaxIdleTime != 1*time.Minute {
		t.Errorf("MaxIdleTime: got %v, want 1m", cfg.MaxIdleTime)
	}
}

// --- NormalizeDriver ---

func TestNormalizeDriver(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// All SQLite aliases must normalize to "sqlite"
		{"sqlite", "sqlite"},
		{"sqlite3", "sqlite"},
		{"sqlite2", "sqlite"},
		{"file", "sqlite"},
		// Case and whitespace must be handled
		{"SQLite3", "sqlite"},
		{"  SQLite  ", "sqlite"},
		{"FILE", "sqlite"},
		// libsql/Turso aliases must normalize to "libsql"
		{"libsql", "libsql"},
		{"turso", "libsql"},
		{"LibSQL", "libsql"},
		{"  Turso  ", "libsql"},
		// Unknown drivers are returned lowercased
		{"postgres", "postgres"},
		{"mysql", "mysql"},
		{"MYSQL", "mysql"},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := NormalizeDriver(tc.input)
			if got != tc.want {
				t.Errorf("NormalizeDriver(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// --- New ---

func TestNew_NilConfig(t *testing.T) {
	_, err := New(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil config, got nil")
	}
}

func TestNew_SQLiteSuccess(t *testing.T) {
	cfg := &DatabaseConfig{
		Driver: "sqlite",
		Path:   t.TempDir(),
	}
	database, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New with sqlite: %v", err)
	}
	if database == nil {
		t.Fatal("expected non-nil DB")
	}
	if database.Driver != "sqlite" {
		t.Errorf("Driver: got %q, want %q", database.Driver, "sqlite")
	}
	if database.Read() == nil {
		t.Error("Server db should not be nil")
	}
	_ = database.Close()
}

func TestNew_DefaultPoolApplied(t *testing.T) {
	// Pool.MaxOpen == 0 should trigger DefaultPoolConfig inside New
	cfg := &DatabaseConfig{
		Driver: "sqlite",
		Path:   t.TempDir(),
		Pool:   PoolConfig{},
	}
	database, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = database.Close()
	// Pool was zero → New must have filled it in without error
}

func TestNew_UnsupportedDriver(t *testing.T) {
	cfg := &DatabaseConfig{
		Driver: "postgres",
		Path:   t.TempDir(),
	}
	_, err := New(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for unsupported driver, got nil")
	}
}

func TestNew_MySQLUnsupported(t *testing.T) {
	cfg := &DatabaseConfig{
		Driver: "mysql",
		Path:   t.TempDir(),
	}
	_, err := New(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for mysql driver, got nil")
	}
}

// --- NewSQLite ---

func TestNewSQLite_EmptyPath(t *testing.T) {
	cfg := &DatabaseConfig{
		Driver: "sqlite",
		Path:   "",
		Pool:   DefaultPoolConfig(),
	}
	_, err := NewSQLite(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for empty path, got nil")
	}
}

func TestNewSQLite_ValidPath(t *testing.T) {
	cfg := &DatabaseConfig{
		Driver: "sqlite",
		Path:   t.TempDir(),
		Pool:   DefaultPoolConfig(),
	}
	database, err := NewSQLite(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	if database.Driver != "sqlite" {
		t.Errorf("Driver: got %q, want %q", database.Driver, "sqlite")
	}
	_ = database.Close()
}

func TestNewSQLiteEscapesFileURIPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database dir ? one")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("create database path: %v", err)
	}
	database, err := NewSQLite(context.Background(), &DatabaseConfig{Driver: "sqlite", Path: path, Pool: DefaultPoolConfig()})
	if err != nil {
		t.Fatalf("NewSQLite with URI-special path: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}

func TestSQLiteConcurrentReadersAndWriters(t *testing.T) {
	database := openTempDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := database.ExecWrite(ctx, `CREATE TABLE contention_test (id INTEGER PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatalf("create contention table: %v", err)
	}

	const workers = 20
	errorsFound := make(chan error, workers*2)
	var group sync.WaitGroup
	for i := 0; i < workers; i++ {
		group.Add(2)
		go func(worker int) {
			defer group.Done()
			for n := 0; ; n++ {
				if ctx.Err() != nil {
					return
				}
				if err := database.ExecWrite(ctx, `INSERT INTO contention_test(value) VALUES (?)`, fmt.Sprintf("writer-%d-%d", worker, n)); err != nil {
					if ctx.Err() == nil {
						errorsFound <- err
					}
					return
				}
			}
		}(i)
		go func() {
			defer group.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				var count int
				if err := database.Read().QueryRowContext(ctx, `SELECT COUNT(*) FROM contention_test`).Scan(&count); err != nil {
					if ctx.Err() == nil {
						errorsFound <- err
					}
					return
				}
			}
		}()
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Errorf("concurrent database operation failed: %v", err)
	}
}

func TestSQLiteReadHandleIsQueryOnly(t *testing.T) {
	database := openTempDB(t)
	if database.readDB == database.writeDB {
		t.Fatal("SQLite read and write handles must be independent")
	}
	var queryOnly int
	if err := database.Read().QueryRow(`PRAGMA query_only`).Scan(&queryOnly); err != nil {
		t.Fatalf("read query_only pragma: %v", err)
	}
	if queryOnly != 1 {
		t.Fatalf("query_only = %d, want 1", queryOnly)
	}
	if _, err := database.Read().Exec(`INSERT INTO config(key, value) VALUES ('read-only-test', 'x')`); err == nil {
		t.Fatal("write through read handle unexpectedly succeeded")
	}
}

// --- ConfigurePool ---

func TestConfigurePool(t *testing.T) {
	// Use a real sqlite connection to call ConfigurePool against
	rawDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() { _ = rawDB.Close() }()

	pool := PoolConfig{
		MaxOpen:     10,
		MaxIdle:     3,
		MaxLifetime: 2 * time.Minute,
		MaxIdleTime: 30 * time.Second,
	}
	// ConfigurePool must not panic and must accept any PoolConfig value
	ConfigurePool(rawDB, pool)

	stats := rawDB.Stats()
	if stats.MaxOpenConnections != 10 {
		t.Errorf("MaxOpenConnections: got %d, want 10", stats.MaxOpenConnections)
	}
}

// --- Ping ---

func TestPing_ValidConnection(t *testing.T) {
	database := openTempDB(t)
	if err := Ping(context.Background(), database.Read()); err != nil {
		t.Errorf("Ping: unexpected error: %v", err)
	}
}

// --- DB.Close ---

func TestClose_NoError(t *testing.T) {
	cfg := &DatabaseConfig{
		Driver: "sqlite",
		Path:   t.TempDir(),
		Pool:   DefaultPoolConfig(),
	}
	database, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestClose_NilServer(t *testing.T) {
	// DB with nil Server must not panic and must return nil
	database := &DB{Driver: "sqlite", readDB: nil}
	if err := database.Close(); err != nil {
		t.Errorf("Close with nil Server: %v", err)
	}
}

func TestClose_HookError(t *testing.T) {
	// Inject a close hook that returns an error to cover the error return path.
	database := openTempDB(t)
	sentinel := errors.New("injected close error")
	database.closeHook = func() error { return sentinel }
	err := database.Close()
	if err == nil {
		t.Fatal("expected error from closeHook, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Close() error does not wrap sentinel: %v", err)
	}
}

// --- WithTransaction ---

func TestWithTransaction_CommitSuccess(t *testing.T) {
	database := openTempDB(t)

	called := false
	err := database.Write(context.Background(), func(tx *sql.Tx) error {
		called = true
		// Insert a row to prove the transaction is real
		_, execErr := tx.ExecContext(context.Background(),
			`INSERT INTO config (key, value) VALUES ('txtest', '1')`)
		return execErr
	})
	if err != nil {
		t.Fatalf("WithTransaction: %v", err)
	}
	if !called {
		t.Error("transaction function was never called")
	}

	// Verify the row was committed
	var val string
	row := database.Read().QueryRowContext(context.Background(),
		`SELECT value FROM config WHERE key = 'txtest'`)
	if err := row.Scan(&val); err != nil {
		t.Errorf("committed row not found: %v", err)
	}
	if val != "1" {
		t.Errorf("committed value: got %q, want %q", val, "1")
	}
}

func TestWithTransaction_RollbackOnError(t *testing.T) {
	database := openTempDB(t)

	sentinel := errors.New("intentional error")
	err := database.Write(context.Background(), func(tx *sql.Tx) error {
		// Insert a row that should be rolled back
		_, execErr := tx.ExecContext(context.Background(),
			`INSERT INTO config (key, value) VALUES ('should_not_exist', '1')`)
		if execErr != nil {
			return execErr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got: %v", err)
	}

	// Verify the row was rolled back
	row := database.Read().QueryRowContext(context.Background(),
		`SELECT value FROM config WHERE key = 'should_not_exist'`)
	var val string
	if scanErr := row.Scan(&val); !errors.Is(scanErr, sql.ErrNoRows) {
		t.Errorf("expected ErrNoRows after rollback, got: %v (val=%q)", scanErr, val)
	}
}

// --- IsColumnExistsError ---

func TestIsColumnExistsError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		// nil error must return false
		{"nil error", nil, false},
		// lowercase "duplicate column" substring
		{"duplicate column lowercase", errors.New("duplicate column: foo"), true},
		// "already exists" substring (SQLite typical message)
		{"already exists", errors.New("table already exists"), true},
		// MySQL-style capitalised message
		{"Duplicate column name", errors.New("Duplicate column name 'id'"), true},
		// Unrelated error must return false
		{"unrelated error", errors.New("connection refused"), false},
		// Empty error string must return false
		{"empty message", errors.New(""), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsColumnExistsError(tc.err)
			if got != tc.want {
				t.Errorf("IsColumnExistsError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// --- HandleQueryError ---

func TestHandleQueryError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantNil     bool
		wantContain string
	}{
		// nil input must return nil
		{"nil", nil, true, ""},
		// context deadline exceeded maps to TIMEOUT
		{"deadline exceeded", context.DeadlineExceeded, false, "TIMEOUT"},
		// sql.ErrNoRows maps to NOT_FOUND
		{"no rows", sql.ErrNoRows, false, "NOT_FOUND"},
		// context canceled maps to CANCELED
		{"canceled", context.Canceled, false, "CANCELED"},
		// any other error maps to SERVER_ERROR
		{"other error", errors.New("boom"), false, "SERVER_ERROR"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := HandleQueryError(tc.err)
			if tc.wantNil {
				if got != nil {
					t.Errorf("HandleQueryError(nil): expected nil, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("HandleQueryError: expected non-nil error, got nil")
			}
			if !containsString(got.Error(), tc.wantContain) {
				t.Errorf("HandleQueryError(%v).Error() = %q, want to contain %q",
					tc.err, got.Error(), tc.wantContain)
			}
		})
	}
}

// HandleQueryError must wrap the original error so errors.Is still works for
// the SERVER_ERROR branch (the original is wrapped with %w).
func TestHandleQueryError_ServerErrorWraps(t *testing.T) {
	inner := errors.New("disk full")
	result := HandleQueryError(inner)
	if result == nil {
		t.Fatal("expected non-nil error")
	}
	if !errors.Is(result, inner) {
		t.Errorf("expected result to wrap inner error via %%w; errors.Is returned false")
	}
}

// --- ensureSchema idempotency ---

func TestEnsureSchema_Idempotent(t *testing.T) {
	database := openTempDB(t)

	// Call ensureSchema a second time; CREATE TABLE IF NOT EXISTS means this
	// must succeed without error.
	if err := database.ensureSchema(context.Background()); err != nil {
		t.Errorf("ensureSchema second call: %v", err)
	}
}

func TestEnsureSchema_TablesExist(t *testing.T) {
	database := openTempDB(t)

	// Every table defined in the schema must be queryable after open.
	expectedTables := []string{
		"config",
		"config_meta",
		"rate_limits",
		"rate_limit_events",
		"audit_log",
		"app_secrets",
		"scheduler_tasks",
		"scheduler_history",
		"backups",
		"api_tokens",
		"owners",
		"security_reports",
		"security_thanks",
		"captcha_challenges",
		"whois_records",
	}

	for _, table := range expectedTables {
		t.Run(table, func(t *testing.T) {
			row := database.Read().QueryRowContext(
				context.Background(),
				"SELECT name FROM sqlite_master WHERE type='table' AND name=?",
				table,
			)
			var name string
			if err := row.Scan(&name); err != nil {
				t.Errorf("table %q not found in schema: %v", table, err)
			}
		})
	}
}

func TestEnsureSchemaMigratesWHOISRecordMetadataColumns(t *testing.T) {
	databasePath := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(databasePath, "server.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	_, err = legacy.Exec(`CREATE TABLE whois_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		query TEXT NOT NULL,
		query_type TEXT NOT NULL,
		registrant_name TEXT,
		registrant_org TEXT,
		registrant_email TEXT,
		registrant_country TEXT,
		registrar TEXT,
		created_date TEXT,
		expiry_date TEXT,
		nameservers TEXT,
		status TEXT,
		whois_server TEXT,
		raw_whois TEXT,
		first_seen INTEGER NOT NULL DEFAULT 1,
		last_seen INTEGER NOT NULL DEFAULT 1,
		last_updated INTEGER NOT NULL DEFAULT 1
	)`)
	if err != nil {
		t.Fatalf("create legacy whois_records: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}
	database, err := New(context.Background(), &DatabaseConfig{Driver: "sqlite", Path: databasePath})
	if err != nil {
		t.Fatalf("migrate legacy database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	rows, err := database.Read().QueryContext(context.Background(), `PRAGMA table_info(whois_records)`)
	if err != nil {
		t.Fatalf("inspect migrated whois_records: %v", err)
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			t.Fatalf("scan migrated column: %v", err)
		}
		columns[name] = true
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close migrated column query: %v", err)
	}
	for _, name := range []string{"source", "updated_date", "rdap_server", "raw_rdap", "network_name", "network_range", "network_type", "asn_number", "asn_name", "rir"} {
		if !columns[name] {
			t.Errorf("migrated whois_records missing %q", name)
		}
	}
}

func TestEnsureSchemaPreservesLegacyAPITokensDuringMigration(t *testing.T) {
	raw, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	_, err = raw.Exec(`CREATE TABLE api_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		token_hash TEXT NOT NULL UNIQUE,
		token_prefix TEXT NOT NULL,
		resource_type TEXT NOT NULL,
		resource_id TEXT NOT NULL,
		created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
		expires_at INTEGER,
		last_used_at INTEGER,
		revoked_at INTEGER,
		revoked_reason TEXT
	)`)
	if err != nil {
		t.Fatalf("create legacy token schema: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO api_tokens (token_hash, token_prefix, resource_type, resource_id) VALUES ('hash', 'own_legacy', 'domain', 'example.test')`); err != nil {
		t.Fatalf("insert legacy token: %v", err)
	}
	database := &DB{Driver: "sqlite", readDB: raw, writeDB: raw}
	if err := database.ensureSchema(context.Background()); err != nil {
		t.Fatalf("ensureSchema: %v", err)
	}
	var prefix, resourceType, resourceID string
	if err := raw.QueryRow(`SELECT token_prefix, resource_type, resource_id FROM api_tokens_legacy WHERE token_hash='hash'`).Scan(&prefix, &resourceType, &resourceID); err != nil {
		t.Fatalf("read preserved token: %v", err)
	}
	if prefix != "own_legacy" || resourceType != "domain" || resourceID != "example.test" {
		t.Fatalf("legacy token = %q %q/%q; values changed", prefix, resourceType, resourceID)
	}
	var columns int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('api_tokens') WHERE name='owner_id'`).Scan(&columns); err != nil || columns != 1 {
		t.Fatalf("canonical api_tokens schema missing owner_id: count=%d err=%v", columns, err)
	}
}

func TestEnsureSchemaRefusesDuplicateLinkedNamesWithoutDeletingTokens(t *testing.T) {
	raw, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open SQLite database: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := raw.Exec(`CREATE TABLE owners (id TEXT PRIMARY KEY, created_at INTEGER, last_seen_at INTEGER)`); err != nil {
		t.Fatalf("create owners: %v", err)
	}
	if _, err := raw.Exec(`CREATE TABLE api_tokens (
		id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, kind TEXT NOT NULL, name TEXT,
		token_hash TEXT NOT NULL UNIQUE, token_prefix TEXT NOT NULL, token_last4 TEXT NOT NULL,
		token_enc TEXT NOT NULL, created_at INTEGER, rotated_at INTEGER, expires_at INTEGER,
		last_used_at INTEGER, revoked_at INTEGER, revoked_reason TEXT
	)`); err != nil {
		t.Fatalf("create api_tokens: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO owners (id) VALUES ('owner')`); err != nil {
		t.Fatalf("insert owner: %v", err)
	}
	for _, id := range []string{"one", "two"} {
		if _, err := raw.Exec(`INSERT INTO api_tokens (id, owner_id, kind, name, token_hash, token_prefix, token_last4, token_enc)
			VALUES (?, 'owner', 'linked', 'automation', ?, 'own_prefix', 'last', 'encrypted')`, id, id+"-hash"); err != nil {
			t.Fatalf("insert existing linked token %s: %v", id, err)
		}
	}
	database := &DB{Driver: "sqlite", readDB: raw, writeDB: raw}
	err = database.ensureSchema(context.Background())
	if err == nil || !strings.Contains(err.Error(), "duplicate linked-token names") {
		t.Fatalf("ensureSchema error = %v, want actionable duplicate-name migration error", err)
	}
	var count int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE owner_id = 'owner' AND name = 'automation'`).Scan(&count); err != nil {
		t.Fatalf("count preserved linked tokens: %v", err)
	}
	if count != 2 {
		t.Fatalf("preserved linked-token rows = %d, want 2", count)
	}
}

func TestEnsureSchemaMigratesTokenScopes(t *testing.T) {
	raw, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open SQLite database: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := raw.Exec(`CREATE TABLE owners (id TEXT PRIMARY KEY, created_at INTEGER, last_seen_at INTEGER)`); err != nil {
		t.Fatalf("create owners: %v", err)
	}
	if _, err := raw.Exec(`CREATE TABLE api_tokens (
		id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, kind TEXT NOT NULL, name TEXT,
		token_hash TEXT NOT NULL UNIQUE, token_prefix TEXT NOT NULL, token_last4 TEXT NOT NULL,
		token_enc TEXT NOT NULL, created_at INTEGER, rotated_at INTEGER, expires_at INTEGER,
		last_used_at INTEGER, revoked_at INTEGER, revoked_reason TEXT
	)`); err != nil {
		t.Fatalf("create legacy api_tokens: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO owners (id) VALUES ('owner')`); err != nil {
		t.Fatalf("insert owner: %v", err)
	}
	for _, token := range []struct{ id, kind string }{{"primary", "primary"}, {"linked", "linked"}} {
		_, err := raw.Exec(`INSERT INTO api_tokens (id, owner_id, kind, token_hash, token_prefix, token_last4, token_enc)
			VALUES (?, 'owner', ?, ?, 'own_prefix', 'last', 'encrypted')`, token.id, token.kind, token.id+"-hash")
		if err != nil {
			t.Fatalf("insert %s token: %v", token.kind, err)
		}
	}
	database := &DB{Driver: "sqlite", readDB: raw, writeDB: raw}
	if err := database.ensureSchema(context.Background()); err != nil {
		t.Fatalf("ensureSchema: %v", err)
	}
	for _, token := range []struct{ id, want string }{{"primary", "global"}, {"linked", "read-write"}} {
		var scope string
		if err := raw.QueryRow(`SELECT scope FROM api_tokens WHERE id = ?`, token.id).Scan(&scope); err != nil {
			t.Fatalf("read %s token scope: %v", token.id, err)
		}
		if scope != token.want {
			t.Errorf("%s token scope = %q, want %q", token.id, scope, token.want)
		}
	}
}

func TestEnsureSchema_InitializesPersistentSecrets(t *testing.T) {
	database := openTempDB(t)
	secretNames := []string{"installation_secret", "cookie_signing_key", "csrf_token_secret"}
	initial := make(map[string]string, len(secretNames))
	for _, name := range secretNames {
		var value string
		if err := database.Read().QueryRow(`SELECT value FROM app_secrets WHERE name = ?`, name).Scan(&value); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("%s must be base64-encoded 32 bytes; got %q (decode error %v)", name, value, err)
		}
		initial[name] = value
	}

	if err := database.ensureSchema(context.Background()); err != nil {
		t.Fatalf("repeat ensureSchema: %v", err)
	}
	for _, name := range secretNames {
		var value string
		if err := database.Read().QueryRow(`SELECT value FROM app_secrets WHERE name = ?`, name).Scan(&value); err != nil {
			t.Fatalf("read %s after repeat: %v", name, err)
		}
		if value != initial[name] {
			t.Errorf("%s changed during schema initialization", name)
		}
	}
}

// --- WithTransaction begin-fails path ---

// TestWithTransaction_BeginFails exercises the branch where BeginTx returns an
// error because the underlying DB is already closed.
func TestWithTransaction_BeginFails(t *testing.T) {
	rawDB, err := sql.Open("sqlite", t.TempDir()+"/tx_begin_fail.db")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	// Close before calling WithTransaction so BeginTx will fail.
	_ = rawDB.Close()

	err = WithTransaction(context.Background(), rawDB, func(_ *sql.Tx) error {
		return nil
	})
	if err == nil {
		t.Error("expected error when BeginTx fails on closed DB, got nil")
	}
}

// TestWithTransaction_CommitFails exercises the commit-error branch. We commit
// the transaction inside fn to invalidate it, so the outer Commit call fails.
func TestWithTransaction_CommitFails(t *testing.T) {
	database := openTempDB(t)

	err := database.Write(context.Background(), func(tx *sql.Tx) error {
		// Commit early inside fn; the deferred outer Commit will then fail.
		return tx.Commit()
	})
	if err == nil {
		t.Error("expected error when commit is called on already-committed tx, got nil")
	}
}

// --- WithTransaction rollback-also-fails path ---

// TestWithTransaction_RollbackAlsoFails exercises the path where fn returns an
// error AND the subsequent Rollback also fails (because the DB is closed).
func TestWithTransaction_RollbackAlsoFails(t *testing.T) {
	// Open a fresh DB just for this test — we will close it mid-transaction.
	rawDB, err := sql.Open("sqlite", t.TempDir()+"/tx_rb_err.db?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	// Ping to ensure the connection is live before we start.
	if err := rawDB.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	sentinel := errors.New("fn error")
	err = WithTransaction(context.Background(), rawDB, func(tx *sql.Tx) error {
		// Close the underlying DB while inside the transaction so that
		// tx.Rollback() will also fail.
		_ = rawDB.Close()
		return sentinel
	})
	// WithTransaction must return a non-nil error; the exact message depends on
	// whether rollback itself errored first.
	if err == nil {
		t.Error("expected error from WithTransaction when rollback also fails, got nil")
	}
}

// --- ensureSchema error path ---

// TestEnsureSchema_ClosedDB exercises the error branch inside ensureSchema
// where ExecContext fails because the underlying DB is closed.
func TestEnsureSchema_ClosedDB(t *testing.T) {
	rawDB, err := sql.Open("sqlite", t.TempDir()+"/schema_err.db")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	// Close the DB so every subsequent Exec will fail.
	_ = rawDB.Close()

	database := &DB{Driver: "sqlite", readDB: rawDB}
	if err := database.ensureSchema(context.Background()); err == nil {
		t.Error("expected error from ensureSchema on closed DB, got nil")
	}
}

// --- NewSQLite path-not-writable ---

// TestNewSQLite_UnwritablePath exercises the ping-failure branch in NewSQLite
// by pointing it at a path where the SQLite file cannot be created.
func TestNewSQLite_UnwritablePath(t *testing.T) {
	cfg := &DatabaseConfig{
		Driver: "sqlite",
		// /proc/nonexistent does not exist and cannot be written to.
		Path: "/proc/nonexistent/deeply/nested",
		Pool: DefaultPoolConfig(),
	}
	_, err := NewSQLite(context.Background(), cfg)
	if err == nil {
		t.Error("expected error for unwritable path, got nil")
	}
}

// containsString is a small helper used only in this test file.
func containsString(s, substr string) bool {
	return len(substr) == 0 || len(s) >= len(substr) && (s == substr ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
