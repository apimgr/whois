package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DB represents a database connection with common operations.
type DB struct {
	// Server is the primary database handle (server.db).
	Server *sql.DB
	// Driver is the normalized driver name (always "sqlite").
	Driver string
	// closeHook is an optional close override used in tests to inject close errors.
	closeHook func() error
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
	if db.Server != nil {
		closeErr := db.Server.Close()
		if db.closeHook != nil {
			closeErr = db.closeHook()
		}
		if closeErr != nil {
			return fmt.Errorf("close server db: %w", closeErr)
		}
	}
	return nil
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
