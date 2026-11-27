package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"runtime"
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
