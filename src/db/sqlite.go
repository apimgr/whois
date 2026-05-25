package db

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

// NewSQLite creates SQLite database connections
func NewSQLite(ctx context.Context, cfg *Config) (*DB, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("sqlite path is required")
	}

	db := &DB{
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

	db.Server = serverDB

	// Open users database (users.db)
	usersPath := filepath.Join(cfg.Path, "users.db")
	usersDB, err := sql.Open("sqlite3", usersPath+"?_journal_mode=WAL&_timeout=5000&_foreign_keys=ON")
	if err != nil {
		serverDB.Close()
		return nil, fmt.Errorf("open users.db: %w", err)
	}

	// Configure pool
	ConfigurePool(usersDB, cfg.Pool)

	// Verify connection
	if err := Ping(ctx, usersDB); err != nil {
		serverDB.Close()
		usersDB.Close()
		return nil, fmt.Errorf("ping users.db: %w", err)
	}

	db.Users = usersDB

	// Ensure schema exists
	if err := db.ensureSchema(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ensure schema: %w", err)
	}

	return db, nil
}

// ensureSchema creates tables if they don't exist (idempotent)
func (db *DB) ensureSchema(ctx context.Context) error {
	// Create server tables
	if err := db.ensureServerSchema(ctx); err != nil {
		return fmt.Errorf("server schema: %w", err)
	}

	// Create users tables
	if err := db.ensureUsersSchema(ctx); err != nil {
		return fmt.Errorf("users schema: %w", err)
	}

	// Apply schema updates (idempotent)
	if err := db.applySchemaUpdates(ctx); err != nil {
		return fmt.Errorf("schema updates: %w", err)
	}

	return nil
}

// ensureServerSchema creates server database tables
func (db *DB) ensureServerSchema(ctx context.Context) error {
	statements := []string{
		// Configuration table
		`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_by TEXT
		)`,

		// Configuration metadata
		`CREATE TABLE IF NOT EXISTS config_meta (
			key TEXT PRIMARY KEY,
			default_value TEXT,
			description TEXT,
			requires_restart INTEGER DEFAULT 0,
			validation_rule TEXT
		)`,

		// Admin sessions
		`CREATE TABLE IF NOT EXISTS admin_sessions (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			ip_address TEXT,
			user_agent TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// Rate limiting counters
		`CREATE TABLE IF NOT EXISTS rate_limits (
			key TEXT PRIMARY KEY,
			count INTEGER DEFAULT 0,
			reset_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// Audit log
		`CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			action TEXT NOT NULL,
			resource_type TEXT,
			resource_id TEXT,
			details TEXT,
			ip_address TEXT,
			user_agent TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// Scheduler tasks
		`CREATE TABLE IF NOT EXISTS scheduler_tasks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			schedule TEXT NOT NULL,
			command TEXT NOT NULL,
			enabled INTEGER DEFAULT 1,
			last_run TIMESTAMP,
			next_run TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// Scheduler history
		`CREATE TABLE IF NOT EXISTS scheduler_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			task_id INTEGER NOT NULL,
			started_at TIMESTAMP NOT NULL,
			completed_at TIMESTAMP,
			status TEXT NOT NULL,
			output TEXT,
			error TEXT,
			FOREIGN KEY (task_id) REFERENCES scheduler_tasks(id) ON DELETE CASCADE
		)`,

		// Backup metadata
		`CREATE TABLE IF NOT EXISTS backups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			filename TEXT NOT NULL,
			size INTEGER NOT NULL,
			type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by TEXT,
			status TEXT DEFAULT 'completed'
		)`,

		// WHOIS cache metadata
		`CREATE TABLE IF NOT EXISTS whois_cache_meta (
			query TEXT PRIMARY KEY,
			query_type TEXT NOT NULL,
			hits INTEGER DEFAULT 0,
			last_hit TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL
		)`,

		// Indexes for server tables
		`CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_rate_limits_reset ON rate_limits(reset_at)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_scheduler_history_task ON scheduler_history(task_id)`,
		`CREATE INDEX IF NOT EXISTS idx_whois_cache_expires ON whois_cache_meta(expires_at)`,
	}

	for _, stmt := range statements {
		if _, err := db.Server.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("execute statement: %w", err)
		}
	}

	return nil
}

// ensureUsersSchema creates users database tables
func (db *DB) ensureUsersSchema(ctx context.Context) error {
	statements := []string{
		// Admin accounts
		`CREATE TABLE IF NOT EXISTS admins (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			name TEXT,
			is_super INTEGER DEFAULT 0,
			is_active INTEGER DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_login TIMESTAMP
		)`,

		// API keys
		`CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			key_prefix TEXT NOT NULL,
			key_hash TEXT NOT NULL,
			name TEXT,
			scopes TEXT,
			last_used TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES admins(id) ON DELETE CASCADE
		)`,

		// Password reset tokens
		`CREATE TABLE IF NOT EXISTS password_resets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			token_hash TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			used INTEGER DEFAULT 0,
			FOREIGN KEY (user_id) REFERENCES admins(id) ON DELETE CASCADE
		)`,

		// Email verifications
		`CREATE TABLE IF NOT EXISTS email_verifications (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			token_hash TEXT NOT NULL,
			email TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			verified INTEGER DEFAULT 0,
			FOREIGN KEY (user_id) REFERENCES admins(id) ON DELETE CASCADE
		)`,

		// TOTP secrets for 2FA
		`CREATE TABLE IF NOT EXISTS totp_secrets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER UNIQUE NOT NULL,
			secret TEXT NOT NULL,
			enabled INTEGER DEFAULT 0,
			backup_codes TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES admins(id) ON DELETE CASCADE
		)`,

		// Trusted devices for 2FA
		`CREATE TABLE IF NOT EXISTS trusted_devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			device_id TEXT NOT NULL,
			device_name TEXT,
			ip_address TEXT,
			user_agent TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			FOREIGN KEY (user_id) REFERENCES admins(id) ON DELETE CASCADE,
			UNIQUE (user_id, device_id)
		)`,

		// Indexes for users tables
		`CREATE INDEX IF NOT EXISTS idx_admins_email ON admins(email)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_email_verifications_token ON email_verifications(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_trusted_devices_user ON trusted_devices(user_id)`,
	}

	for _, stmt := range statements {
		if _, err := db.Users.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("execute statement: %w", err)
		}
	}

	return nil
}

// applySchemaUpdates applies idempotent schema updates
func (db *DB) applySchemaUpdates(ctx context.Context) error {
	updates := []string{
		// Future schema updates go here
		// Each statement must be idempotent (safe to run multiple times)
	}

	for _, stmt := range updates {
		// Try to execute, ignore "already exists" errors
		if _, err := db.Server.ExecContext(ctx, stmt); err != nil {
			if !IsColumnExistsError(err) {
				return fmt.Errorf("schema update: %w", err)
			}
		}
	}

	return nil
}
