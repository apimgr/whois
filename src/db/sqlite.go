package db

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

// NewSQLite creates a SQLite database connection for server.db
func NewSQLite(ctx context.Context, cfg *DatabaseConfig) (*DB, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("sqlite path is required")
	}

	database := &DB{
		Driver: "sqlite",
	}

	// Open server database (server.db)
	serverPath := filepath.Join(cfg.Path, "server.db")
	serverDB, err := sql.Open("sqlite3", serverPath+"?_journal_mode=WAL&_timeout=5000&_foreign_keys=ON")
	if err != nil {
		return nil, fmt.Errorf("open server.db: %w", err)
	}

	// Configure pool
	ConfigurePool(serverDB, cfg.Pool)

	// Verify connection
	if err := Ping(ctx, serverDB); err != nil {
		serverDB.Close()
		return nil, fmt.Errorf("ping server.db: %w", err)
	}

	database.Server = serverDB

	// Ensure schema exists (idempotent CREATE TABLE IF NOT EXISTS)
	if err := database.ensureSchema(ctx); err != nil {
		database.Close()
		return nil, fmt.Errorf("ensure schema: %w", err)
	}

	return database, nil
}

// ensureSchema creates all tables if they don't exist (idempotent)
func (db *DB) ensureSchema(ctx context.Context) error {
	statements := []string{
		// Configuration key-value store
		`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_by TEXT
		)`,

		// Rate limiting sliding window counters
		`CREATE TABLE IF NOT EXISTS rate_limits (
			key TEXT PRIMARY KEY,
			count INTEGER DEFAULT 0,
			reset_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// Audit log for config changes and security events
		`CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			action TEXT NOT NULL,
			resource_type TEXT,
			resource_id TEXT,
			details TEXT,
			ip_address TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// Scheduler task definitions
		`CREATE TABLE IF NOT EXISTS scheduler_tasks (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			schedule TEXT NOT NULL,
			enabled INTEGER DEFAULT 1,
			last_run TIMESTAMP,
			next_run TIMESTAMP,
			last_status TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// Scheduler execution history
		`CREATE TABLE IF NOT EXISTS scheduler_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			task_id TEXT NOT NULL,
			started_at TIMESTAMP NOT NULL,
			completed_at TIMESTAMP,
			status TEXT NOT NULL,
			error TEXT,
			FOREIGN KEY (task_id) REFERENCES scheduler_tasks(id) ON DELETE CASCADE
		)`,

		// Backup metadata
		`CREATE TABLE IF NOT EXISTS backups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			filename TEXT NOT NULL,
			size INTEGER NOT NULL,
			type TEXT NOT NULL,
			encrypted INTEGER DEFAULT 0,
			checksum TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			status TEXT DEFAULT 'completed'
		)`,

		// API tokens (SHA-256 hashes only — never plaintext)
		// server.token from config is NOT stored here; it is validated
		// directly via constant-time SHA-256 comparison.
		`CREATE TABLE IF NOT EXISTS api_tokens (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			token_hash    TEXT NOT NULL UNIQUE,
			token_prefix  TEXT NOT NULL,
			name          TEXT,
			resource_type TEXT,
			resource_id   TEXT,
			created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at    TIMESTAMP,
			last_used_at  TIMESTAMP,
			revoked_at    TIMESTAMP
		)`,

		// WHOIS query cache metadata
		`CREATE TABLE IF NOT EXISTS whois_cache_meta (
			query TEXT PRIMARY KEY,
			query_type TEXT NOT NULL,
			hits INTEGER DEFAULT 0,
			last_hit TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL
		)`,

		// Indexes
		`CREATE INDEX IF NOT EXISTS idx_rate_limits_reset ON rate_limits(reset_at)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_scheduler_history_task ON scheduler_history(task_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_hash     ON api_tokens(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_prefix   ON api_tokens(token_prefix)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_resource ON api_tokens(resource_type, resource_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_active   ON api_tokens(revoked_at) WHERE revoked_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_whois_cache_expires ON whois_cache_meta(expires_at)`,
	}

	for _, stmt := range statements {
		if _, err := db.Server.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("execute schema statement: %w", err)
		}
	}

	return nil
}
