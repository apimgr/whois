package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DB represents a database connection with common operations
type DB struct {
	Server *sql.DB // Server database (srv_* tables or server.db)
	Users  *sql.DB // Users database (usr_* tables or users.db)
	Driver string  // "sqlite", "postgres", "mysql"
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Driver   string     // "sqlite", "postgres", "mysql"
	Host     string     // Database host (postgres/mysql)
	Port     int        // Database port
	Name     string     // Database name
	Username string     // Database username
	Password string     // Database password
	Path     string     // Path for SQLite files
	Pool     PoolConfig // Connection pool config
}

// PoolConfig holds connection pool settings
type PoolConfig struct {
	MaxOpen     int           // Maximum open connections
	MaxIdle     int           // Maximum idle connections
	MaxLifetime time.Duration // Maximum connection lifetime
	MaxIdleTime time.Duration // Maximum idle time
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
	case "postgres":
		return NewPostgres(ctx, cfg)
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.Driver)
	}
}

// NormalizeDriver normalizes database driver name
func NormalizeDriver(driver string) string {
	driver = strings.ToLower(strings.TrimSpace(driver))
	switch driver {
	case "sqlite", "sqlite3", "sqlite2", "file":
		return "sqlite"
	case "postgres", "postgresql", "pgsql":
		return "postgres"
	case "mysql", "mariadb":
		return "mysql"
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
	var errs []error

	if db.Server != nil {
		if err := db.Server.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close server db: %w", err))
		}
	}

	if db.Users != nil {
		if err := db.Users.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close users db: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("database close errors: %v", errs)
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
