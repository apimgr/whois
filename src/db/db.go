package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/url"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// DB represents a database connection with common operations.
type DB struct {
	readDB  *sql.DB
	writeDB *sql.DB
	// Driver is the normalized driver name ("sqlite" or "libsql").
	Driver string
	// closeHook is an optional close override used in tests to inject close errors.
	closeHook    func() error
	writeMetrics WriteMetrics
}

// WriteMetrics receives SQLite writer contention observations without coupling
// the database package to a particular metrics implementation.
type WriteMetrics interface {
	IncDBBusy()
	ObserveDBWriteWait(float64)
}

// SetWriteMetrics installs optional SQLite writer contention instrumentation.
func (db *DB) SetWriteMetrics(metrics WriteMetrics) {
	db.writeMetrics = metrics
}

// AppSecret returns a generated secret decoded from the server database.
func (db *DB) AppSecret(ctx context.Context, name string) ([]byte, error) {
	var encoded string
	if err := db.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name = ?`, name).Scan(&encoded); err != nil {
		return nil, fmt.Errorf("read application secret %q: %w", name, err)
	}
	secret, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode application secret %q: %w", name, err)
	}
	return secret, nil
}

// ExportAppSecrets returns every encrypted application-secret row for backup.
func (db *DB) ExportAppSecrets(ctx context.Context) (map[string]string, error) {
	if db == nil || db.Read() == nil {
		return nil, errors.New("database read handle is unavailable")
	}
	rows, err := db.Read().QueryContext(ctx, `SELECT name, value FROM app_secrets ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("query application secrets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	secrets := make(map[string]string)
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, fmt.Errorf("read application secret: %w", err)
		}
		secrets[name] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate application secrets: %w", err)
	}
	return secrets, nil
}

// RestoreAppSecretsIfEmpty seeds generated secrets only on a new remote database.
func (db *DB) RestoreAppSecretsIfEmpty(ctx context.Context, secrets map[string]string) error {
	return db.Write(ctx, func(tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_secrets`).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return nil
		}
		now := time.Now().UTC().Format(time.RFC3339)
		for _, name := range sortedSecretNames(secrets) {
			if _, err := tx.ExecContext(ctx, `INSERT INTO app_secrets(name,value,updated_at) VALUES(?,?,?) ON CONFLICT(name) DO NOTHING`, name, secrets[name], now); err != nil {
				return err
			}
		}
		return nil
	})
}

// SeedFromSQLite copies an archived local database into an empty remote database.
// The schema is created by the normal remote startup path before this runs.
func (db *DB) SeedFromSQLite(ctx context.Context, sourcePath string) error {
	const seedMarker = "__apimgr_restore_seed_pending"
	if db == nil || db.Driver != "libsql" || db.writeDB == nil {
		return errors.New("remote database write handle is unavailable")
	}
	absPath, err := filepath.Abs(sourcePath)
	if err != nil {
		return fmt.Errorf("resolve SQLite seed path: %w", err)
	}
	sourceURI := (&url.URL{Path: filepath.ToSlash(absPath)}).EscapedPath()
	source, err := sql.Open("sqlite", "file:"+sourceURI+"?mode=ro")
	if err != nil {
		return fmt.Errorf("open SQLite seed database: %w", err)
	}
	defer func() { _ = source.Close() }()
	if err := source.PingContext(ctx); err != nil {
		return fmt.Errorf("connect SQLite seed database: %w", err)
	}
	rows, err := source.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY rowid`)
	if err != nil {
		return fmt.Errorf("list SQLite seed tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read SQLite seed table: %w", err)
		}
		tables = append(tables, name)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close SQLite seed table list: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate SQLite seed tables: %w", err)
	}
	var marker string
	markerErr := db.Read().QueryRowContext(ctx, `SELECT value FROM config WHERE key = ?`, seedMarker).Scan(&marker)
	if markerErr != nil && !errors.Is(markerErr, sql.ErrNoRows) {
		return fmt.Errorf("check remote restore marker: %w", markerErr)
	}
	if markerErr == nil {
		if err := db.rollbackSQLiteSeed(ctx, tables); err != nil {
			return fmt.Errorf("clear interrupted remote restore: %w", err)
		}
	}
	for _, table := range tables {
		if table == "app_secrets" || table == "config_meta" {
			continue
		}
		var count int
		if err := db.Read().QueryRowContext(ctx, `SELECT COUNT(*) FROM `+quoteIdentifier(DatabaseObjectName(db.Driver, table))).Scan(&count); err != nil {
			return fmt.Errorf("check remote table %s: %w", table, err)
		}
		if count != 0 {
			return nil
		}
	}
	if err := db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO config(key,value,type) VALUES(?,?,'string') ON CONFLICT(key) DO UPDATE SET value=excluded.value,type=excluded.type`, seedMarker, "pending"); err != nil {
			return fmt.Errorf("mark remote restore in progress: %w", err)
		}
		for _, table := range []string{"app_secrets", "config_meta"} {
			if containsSeedTable(tables, table) {
				if _, err := tx.ExecContext(ctx, `DELETE FROM `+quoteIdentifier(DatabaseObjectName(db.Driver, table))); err != nil {
					return fmt.Errorf("clear initialized remote table %s: %w", table, err)
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	for _, table := range tables {
		if err := copySQLiteTable(ctx, source, db, db.Driver, table); err != nil {
			rollbackErr := db.rollbackSQLiteSeed(ctx, tables)
			if rollbackErr != nil {
				markErr := db.Write(ctx, func(tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, `INSERT INTO config(key,value,type) VALUES(?,?,'string') ON CONFLICT(key) DO UPDATE SET value=excluded.value,type=excluded.type`, seedMarker, "pending")
					return err
				})
				rollbackErr = errors.Join(rollbackErr, markErr)
			}
			return errors.Join(fmt.Errorf("seed table %s: %w", table, err), rollbackErr)
		}
	}
	return db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM config WHERE key = ?`, seedMarker)
		return err
	})
}

func (db *DB) rollbackSQLiteSeed(ctx context.Context, tables []string) error {
	var failures []error
	for index := len(tables) - 1; index >= 0; index-- {
		table := tables[index]
		if err := db.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `DELETE FROM `+quoteIdentifier(DatabaseObjectName(db.Driver, table)))
			return err
		}); err != nil {
			failures = append(failures, fmt.Errorf("clear partially seeded table %s: %w", table, err))
		}
	}
	if err := db.ensureSchema(ctx); err != nil {
		failures = append(failures, fmt.Errorf("reinitialize empty remote schema: %w", err))
	}
	return errors.Join(failures...)
}

func copySQLiteTable(ctx context.Context, source *sql.DB, target *DB, driverName, table string) error {
	const batchSize = 500
	quotedSource := quoteIdentifier(table)
	columns, err := sqliteTableColumns(ctx, source, table)
	if err != nil {
		return err
	}
	quotedColumns := make([]string, len(columns))
	placeholders := make([]string, len(columns))
	for i, column := range columns {
		quotedColumns[i] = quoteIdentifier(column)
		placeholders[i] = "?"
	}
	selectColumns := strings.Join(quotedColumns, ",")
	query := `INSERT INTO ` + quoteIdentifier(DatabaseObjectName(driverName, table)) + ` (` + strings.Join(quotedColumns, ",") + `) VALUES (` + strings.Join(placeholders, ",") + `)`
	first, err := source.QueryContext(ctx, `SELECT `+selectColumns+` FROM `+quotedSource+` ORDER BY rowid LIMIT ? OFFSET 0`, batchSize)
	if err != nil {
		return fmt.Errorf("read SQLite table %s: %w", table, err)
	}
	var offset int64
	rows := first
	for {
		batch := make([][]any, 0, batchSize)
		for rows.Next() {
			values := make([]any, len(columns))
			destinations := make([]any, len(columns))
			for i := range values {
				destinations[i] = &values[i]
			}
			if err := rows.Scan(destinations...); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan SQLite table %s: %w", table, err)
			}
			for i, value := range values {
				if data, ok := value.([]byte); ok {
					values[i] = append([]byte(nil), data...)
				}
			}
			batch = append(batch, values)
		}
		rowsErr := rows.Err()
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close SQLite table %s: %w", table, err)
		}
		if rowsErr != nil {
			return fmt.Errorf("iterate SQLite table %s: %w", table, rowsErr)
		}
		if len(batch) == 0 {
			return nil
		}
		if err := target.Write(ctx, func(tx *sql.Tx) error {
			for _, values := range batch {
				if _, err := tx.ExecContext(ctx, query, values...); err != nil {
					return fmt.Errorf("seed remote table %s: %w", table, err)
				}
			}
			return nil
		}); err != nil {
			return err
		}
		offset += int64(len(batch))
		if len(batch) < batchSize {
			return nil
		}
		rows, err = source.QueryContext(ctx, `SELECT `+selectColumns+` FROM `+quotedSource+` ORDER BY rowid LIMIT ? OFFSET ?`, batchSize, offset)
		if err != nil {
			return fmt.Errorf("read SQLite table %s: %w", table, err)
		}
	}
}

func sqliteTableColumns(ctx context.Context, source *sql.DB, table string) ([]string, error) {
	rows, err := source.QueryContext(ctx, `PRAGMA table_info(`+quoteIdentifier(table)+`)`)
	if err != nil {
		return nil, fmt.Errorf("inspect SQLite columns for %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	var columns []string
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, fmt.Errorf("read SQLite column for %s: %w", table, err)
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate SQLite columns for %s: %w", table, err)
	}
	if len(columns) == 0 {
		return nil, fmt.Errorf("SQLite table %s has no readable columns", table)
	}
	return columns, nil
}

func quoteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func containsSeedTable(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func sortedSecretNames(secrets map[string]string) []string {
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// DatabaseConfig holds database configuration. Only SQLite/libsql are
// supported (PART 10) — Name is used for libsql/Turso remote database names.
type DatabaseConfig struct {
	// Driver is "sqlite" or "libsql" (normalized via NormalizeDriver).
	Driver string
	// Name is the remote database name for libsql/Turso connections.
	Name string
	// Path is the directory containing SQLite files (server.db).
	Path string
	// URL is the libsql/Turso remote connection string
	// (libsql://host?authToken=xxx or https://host). Required for the
	// libsql driver — libSQL has no embedded/local mode (PART 10).
	URL string
	// Token is the Turso auth token, used when URL does not already embed
	// an authToken query parameter.
	Token string
	// Pool holds connection-pool tuning.
	Pool PoolConfig
}

// PoolConfig holds connection pool settings.
type PoolConfig struct {
	// MaxOpen is the maximum number of open connections.
	MaxOpen int
	// MaxIdle is the maximum number of idle connections kept in the pool.
	MaxIdle int
	// MaxLifetime is the maximum lifetime of a connection.
	MaxLifetime time.Duration
	// MaxIdleTime is the maximum time a connection can sit idle.
	MaxIdleTime time.Duration
}

// DefaultPoolConfig returns sensible pool defaults
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxOpen:     25,
		MaxIdle:     5,
		MaxLifetime: 5 * time.Minute,
		MaxIdleTime: 1 * time.Minute,
	}
}

// New creates a new database connection based on config
func New(ctx context.Context, cfg *DatabaseConfig) (*DB, error) {
	if cfg == nil {
		return nil, errors.New("database config is nil")
	}

	// Normalize driver name
	cfg.Driver = NormalizeDriver(cfg.Driver)

	// Set default pool config if not provided
	if cfg.Pool.MaxOpen == 0 {
		cfg.Pool = DefaultPoolConfig()
	}

	// Create connections based on driver
	switch cfg.Driver {
	case "sqlite":
		return NewSQLite(ctx, cfg)
	case "libsql":
		return NewLibSQL(ctx, cfg)
	default:
		return nil, fmt.Errorf("unsupported database driver: %s (only sqlite and libsql are supported)", cfg.Driver)
	}
}

// NormalizeDriver normalizes database driver name
func NormalizeDriver(driver string) string {
	driver = strings.ToLower(strings.TrimSpace(driver))
	switch driver {
	case "sqlite", "sqlite3", "sqlite2", "file":
		return "sqlite"
	case "libsql", "turso":
		return "libsql"
	default:
		return driver
	}
}

// ConfigurePool configures connection pool settings
func ConfigurePool(db *sql.DB, cfg PoolConfig) {
	db.SetMaxOpenConns(cfg.MaxOpen)
	db.SetMaxIdleConns(cfg.MaxIdle)
	db.SetConnMaxLifetime(cfg.MaxLifetime)
	db.SetConnMaxIdleTime(cfg.MaxIdleTime)
}

// Ping verifies database connection with timeout
func Ping(ctx context.Context, db *sql.DB) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return db.PingContext(ctx)
}

// Close closes all database connections
func (db *DB) Close() error {
	var firstErr error
	if db.writeDB != nil && db.writeDB != db.readDB {
		if db.Driver == "sqlite" {
			var busy, logFrames, checkpointed int
			if err := db.writeDB.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("checkpoint SQLite WAL: %w", err)
			} else if err == nil && busy != 0 && firstErr == nil {
				firstErr = fmt.Errorf("checkpoint SQLite WAL: database remained busy")
			}
		}
	}
	if db.readDB != nil {
		closeErr := db.readDB.Close()
		if db.closeHook != nil {
			closeErr = db.closeHook()
		}
		if closeErr != nil && firstErr == nil {
			firstErr = closeErr
		}
	}
	if db.writeDB != nil && db.writeDB != db.readDB {
		if err := db.writeDB.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return fmt.Errorf("close database: %w", firstErr)
	}
	return nil
}

// Read returns the read pool. SQLite callers never receive the write handle.
func (db *DB) Read() *sql.DB {
	if db == nil {
		return nil
	}
	return db.readDB
}

// Write runs a short write transaction, retrying SQLite busy errors while the
// caller's context remains live. The callback must not perform external I/O.
func (db *DB) Write(ctx context.Context, fn func(*sql.Tx) error) error {
	if db.writeDB == nil {
		return errors.New("database write handle is unavailable")
	}
	if db.Driver != "sqlite" {
		return WithTransaction(ctx, db.writeDB, fn)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		started := time.Now()
		err = db.writeOnce(ctx, fn)
		waited := time.Since(started)
		if db.writeMetrics != nil {
			db.writeMetrics.ObserveDBWriteWait(waited.Seconds())
		}
		if waited > time.Second {
			log.Printf("WARN: db.busy wait_ms=%d caller=%s", waited.Milliseconds(), callerName())
		}
		if !isSQLiteBusy(err) {
			return err
		}
		if db.writeMetrics != nil {
			db.writeMetrics.IncDBBusy()
		}
		backoff := time.Duration(25<<attempt)*time.Millisecond + time.Duration(jitterMillis())*time.Millisecond
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

// ExecWrite executes one statement in the serialized SQLite writer transaction.
func (db *DB) ExecWrite(ctx context.Context, query string, args ...any) error {
	_, err := db.ExecResult(ctx, query, args...)
	return err
}

// ExecResult executes a statement and returns its result after the write commits.
func (db *DB) ExecResult(ctx context.Context, query string, args ...any) (sql.Result, error) {
	var result sql.Result
	err := db.Write(ctx, func(tx *sql.Tx) error {
		var err error
		result, err = tx.ExecContext(ctx, query, args...)
		return err
	})
	return result, err
}

func (db *DB) writeOnce(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func isSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToUpper(err.Error())
	return strings.Contains(message, "SQLITE_BUSY") || strings.Contains(message, "SQLITE_LOCKED") || strings.Contains(message, "DATABASE IS LOCKED")
}

func jitterMillis() int {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int(b[0] % 25)
}

func callerName() string {
	var pcs [8]uintptr
	n := runtime.Callers(3, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	frame, _ := frames.Next()
	if frame.Function == "" {
		return "unknown"
	}
	return frame.Function
}

// WithTransaction executes a function within a transaction
func WithTransaction(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("rollback failed: %v (original error: %w)", rbErr, err)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// IsColumnExistsError checks if error is "column already exists"
func IsColumnExistsError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "duplicate column") ||
		strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "Duplicate column name")
}

// HandleQueryError converts database errors to user-friendly messages
func HandleQueryError(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return errors.New("TIMEOUT: Request timed out")
	case errors.Is(err, sql.ErrNoRows):
		return errors.New("NOT_FOUND: Resource not found")
	case errors.Is(err, context.Canceled):
		return errors.New("CANCELED: Request was canceled")
	default:
		return fmt.Errorf("SERVER_ERROR: Database error: %w", err)
	}
}
