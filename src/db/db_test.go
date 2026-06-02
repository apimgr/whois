package db

import (
	"context"
	"database/sql"
	"errors"
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
	if database.Server == nil {
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

// --- ConfigurePool ---

func TestConfigurePool(t *testing.T) {
	// Use a real sqlite connection to call ConfigurePool against
	rawDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer rawDB.Close()

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
	if err := Ping(context.Background(), database.Server); err != nil {
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
	database := &DB{Driver: "sqlite", Server: nil}
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
	err := WithTransaction(context.Background(), database.Server, func(tx *sql.Tx) error {
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
	row := database.Server.QueryRowContext(context.Background(),
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
	err := WithTransaction(context.Background(), database.Server, func(tx *sql.Tx) error {
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
	row := database.Server.QueryRowContext(context.Background(),
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
		"rate_limits",
		"audit_log",
		"scheduler_tasks",
		"scheduler_history",
		"backups",
		"api_tokens",
		"whois_cache_meta",
	}

	for _, table := range expectedTables {
		t.Run(table, func(t *testing.T) {
			row := database.Server.QueryRowContext(
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

	err := WithTransaction(context.Background(), database.Server, func(tx *sql.Tx) error {
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

	database := &DB{Driver: "sqlite", Server: rawDB}
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
