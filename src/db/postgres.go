package db

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// NewPostgres creates PostgreSQL database connections
func NewPostgres(ctx context.Context, cfg *Config) (*DB, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("postgres host is required")
	}
	if cfg.Name == "" {
		return nil, fmt.Errorf("postgres database name is required")
	}

	db := &DB{
		Driver: "postgres",
	}

	// Default port
	if cfg.Port == 0 {
		cfg.Port = 5432
	}

	// Build connection string
	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=prefer",
		cfg.Host, cfg.Port, cfg.Name, cfg.Username, cfg.Password)

	// Open database connection (single connection for both server and users tables)
	pgDB, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	// Configure pool
	ConfigurePool(pgDB, cfg.Pool)

	// Verify connection
	if err := Ping(ctx, pgDB); err != nil {
		pgDB.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	// Use same connection for both (tables are prefixed with srv_ and usr_)
	db.Server = pgDB
	db.Users = pgDB

	// Ensure schema exists
	if err := db.ensurePostgresSchema(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ensure schema: %w", err)
	}

	return db, nil
}

// ensurePostgresSchema creates tables if they don't exist (idempotent)
func (db *DB) ensurePostgresSchema(ctx context.Context) error {
	// Create server tables
	if err := db.ensurePostgresServerSchema(ctx); err != nil {
		return fmt.Errorf("server schema: %w", err)
	}

	// Create users tables
	if err := db.ensurePostgresUsersSchema(ctx); err != nil {
		return fmt.Errorf("users schema: %w", err)
	}

	// Apply schema updates (idempotent)
	if err := db.applyPostgresSchemaUpdates(ctx); err != nil {
		return fmt.Errorf("schema updates: %w", err)
	}

	return nil
}

// ensurePostgresServerSchema creates server database tables with srv_ prefix
func (db *DB) ensurePostgresServerSchema(ctx context.Context) error {
	statements := []string{
		// Configuration table
		`CREATE TABLE IF NOT EXISTS srv_config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_by TEXT
		)`,

		// Configuration metadata
		`CREATE TABLE IF NOT EXISTS srv_config_meta (
			key TEXT PRIMARY KEY,
			default_value TEXT,
			description TEXT,
			requires_restart INTEGER DEFAULT 0,
			validation_rule TEXT
		)`,

		// Admin sessions
		`CREATE TABLE IF NOT EXISTS srv_admin_sessions (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			ip_address TEXT,
			user_agent TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// Rate limiting counters
		`CREATE TABLE IF NOT EXISTS srv_rate_limits (
			key TEXT PRIMARY KEY,
			count INTEGER DEFAULT 0,
			reset_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// Audit log
		`CREATE TABLE IF NOT EXISTS srv_audit_log (
			id SERIAL PRIMARY KEY,
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
		`CREATE TABLE IF NOT EXISTS srv_scheduler_tasks (
			id SERIAL PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			schedule TEXT NOT NULL,
			command TEXT NOT NULL,
			enabled INTEGER DEFAULT 1,
			last_run TIMESTAMP,
			next_run TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// Scheduler history
		`CREATE TABLE IF NOT EXISTS srv_scheduler_history (
			id SERIAL PRIMARY KEY,
			task_id INTEGER NOT NULL,
			started_at TIMESTAMP NOT NULL,
			completed_at TIMESTAMP,
			status TEXT NOT NULL,
			output TEXT,
			error TEXT,
			FOREIGN KEY (task_id) REFERENCES srv_scheduler_tasks(id) ON DELETE CASCADE
		)`,

		// Backup metadata
		`CREATE TABLE IF NOT EXISTS srv_backups (
			id SERIAL PRIMARY KEY,
			filename TEXT NOT NULL,
			size BIGINT NOT NULL,
			type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by TEXT,
			status TEXT DEFAULT 'completed'
		)`,

		// WHOIS cache metadata
		`CREATE TABLE IF NOT EXISTS srv_whois_cache_meta (
			query TEXT PRIMARY KEY,
			query_type TEXT NOT NULL,
			hits INTEGER DEFAULT 0,
			last_hit TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL
		)`,

		// Indexes for server tables
		`CREATE INDEX IF NOT EXISTS idx_srv_admin_sessions_expires ON srv_admin_sessions(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_srv_rate_limits_reset ON srv_rate_limits(reset_at)`,
		`CREATE INDEX IF NOT EXISTS idx_srv_audit_log_created ON srv_audit_log(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_srv_scheduler_history_task ON srv_scheduler_history(task_id)`,
		`CREATE INDEX IF NOT EXISTS idx_srv_whois_cache_expires ON srv_whois_cache_meta(expires_at)`,
	}

	for _, stmt := range statements {
		if _, err := db.Server.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("execute statement: %w", err)
		}
	}

	return nil
}

// ensurePostgresUsersSchema creates users database tables with usr_ prefix
func (db *DB) ensurePostgresUsersSchema(ctx context.Context) error {
	statements := []string{
		// Admin accounts
		`CREATE TABLE IF NOT EXISTS usr_admins (
			id SERIAL PRIMARY KEY,
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
		`CREATE TABLE IF NOT EXISTS usr_api_keys (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL,
			key_prefix TEXT NOT NULL,
			key_hash TEXT NOT NULL,
			name TEXT,
			scopes TEXT,
			last_used TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES usr_admins(id) ON DELETE CASCADE
		)`,

		// Password reset tokens
		`CREATE TABLE IF NOT EXISTS usr_password_resets (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL,
			token_hash TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			used INTEGER DEFAULT 0,
			FOREIGN KEY (user_id) REFERENCES usr_admins(id) ON DELETE CASCADE
		)`,

		// Email verifications
		`CREATE TABLE IF NOT EXISTS usr_email_verifications (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL,
			token_hash TEXT NOT NULL,
			email TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			verified INTEGER DEFAULT 0,
			FOREIGN KEY (user_id) REFERENCES usr_admins(id) ON DELETE CASCADE
		)`,

		// TOTP secrets for 2FA
		`CREATE TABLE IF NOT EXISTS usr_totp_secrets (
			id SERIAL PRIMARY KEY,
			user_id INTEGER UNIQUE NOT NULL,
			secret TEXT NOT NULL,
			enabled INTEGER DEFAULT 0,
			backup_codes TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES usr_admins(id) ON DELETE CASCADE
		)`,

		// Trusted devices for 2FA
		`CREATE TABLE IF NOT EXISTS usr_trusted_devices (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL,
			device_id TEXT NOT NULL,
			device_name TEXT,
			ip_address TEXT,
			user_agent TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			FOREIGN KEY (user_id) REFERENCES usr_admins(id) ON DELETE CASCADE,
			UNIQUE (user_id, device_id)
		)`,

		// Indexes for users tables
		`CREATE INDEX IF NOT EXISTS idx_usr_admins_email ON usr_admins(email)`,
		`CREATE INDEX IF NOT EXISTS idx_usr_api_keys_hash ON usr_api_keys(key_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_usr_api_keys_user ON usr_api_keys(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_usr_password_resets_token ON usr_password_resets(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_usr_email_verifications_token ON usr_email_verifications(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_usr_trusted_devices_user ON usr_trusted_devices(user_id)`,
	}

	for _, stmt := range statements {
		if _, err := db.Users.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("execute statement: %w", err)
		}
	}

	return nil
}

// applyPostgresSchemaUpdates applies idempotent schema updates
func (db *DB) applyPostgresSchemaUpdates(ctx context.Context) error {
	updates := []string{
		// Future schema updates go here
		// Each statement must be idempotent (safe to run multiple times)
		// Use "IF NOT EXISTS" or check for existence before adding
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
