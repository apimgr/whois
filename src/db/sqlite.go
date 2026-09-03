package db

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"

	_ "modernc.org/sqlite"
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
	serverDB, err := sql.Open("sqlite", serverPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)")
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
		// Configuration key-value store (dot-notation keys, JSON-encoded values)
		`CREATE TABLE IF NOT EXISTS config (
			key        TEXT PRIMARY KEY,
			value      TEXT NOT NULL,
			type       TEXT NOT NULL DEFAULT 'string',
			updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
		)`,

		// Single-row config change-detection sentinel; version bumped by trigger
		`CREATE TABLE IF NOT EXISTS config_meta (
			id         INTEGER PRIMARY KEY CHECK (id = 1),
			version    INTEGER NOT NULL DEFAULT 1,
			updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
		)`,

		// Seed the single config_meta row (idempotent)
		`INSERT OR IGNORE INTO config_meta (id, version) VALUES (1, 1)`,

		// Auto-increment config version on any config change
		`CREATE TRIGGER IF NOT EXISTS config_version_bump
		AFTER INSERT ON config
		BEGIN
			UPDATE config_meta SET version = version + 1,
			updated_at = strftime('%s', 'now') WHERE id = 1;
		END`,

		`CREATE TRIGGER IF NOT EXISTS config_version_bump_upd
		AFTER UPDATE ON config
		BEGIN
			UPDATE config_meta SET version = version + 1,
			updated_at = strftime('%s', 'now') WHERE id = 1;
		END`,

		`CREATE TRIGGER IF NOT EXISTS config_version_bump_del
		AFTER DELETE ON config
		BEGIN
			UPDATE config_meta SET version = version + 1,
			updated_at = strftime('%s', 'now') WHERE id = 1;
		END`,

		// Rate limiting sliding-window counters
		`CREATE TABLE IF NOT EXISTS rate_limits (
			key          TEXT PRIMARY KEY,
			count        INTEGER NOT NULL DEFAULT 1,
			window_start INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			updated_at   INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
		)`,

		// Audit log for config changes and security events
		`CREATE TABLE IF NOT EXISTS audit_log (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp   INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			level       TEXT NOT NULL DEFAULT 'info',
			category    TEXT NOT NULL,
			action      TEXT NOT NULL,
			actor_ip    TEXT,
			target_type TEXT,
			target_id   TEXT,
			details     TEXT,
			success     INTEGER NOT NULL DEFAULT 1
		)`,

		// Scheduler task definitions and state (see PART 18)
		`CREATE TABLE IF NOT EXISTS scheduler_tasks (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL,
			enabled     INTEGER NOT NULL DEFAULT 1,
			schedule    TEXT NOT NULL,
			last_run    INTEGER,
			next_run    INTEGER,
			last_status TEXT,
			last_error  TEXT,
			run_count   INTEGER NOT NULL DEFAULT 0,
			fail_count  INTEGER NOT NULL DEFAULT 0
		)`,

		// Per-run execution history for scheduler tasks
		`CREATE TABLE IF NOT EXISTS scheduler_history (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			task_id     TEXT NOT NULL,
			started_at  INTEGER NOT NULL,
			finished_at INTEGER,
			status      TEXT NOT NULL,
			error       TEXT,
			duration_ms INTEGER,
			FOREIGN KEY (task_id) REFERENCES scheduler_tasks(id) ON DELETE CASCADE
		)`,

		// Backup file metadata (see PART 21)
		`CREATE TABLE IF NOT EXISTS backups (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			filename   TEXT NOT NULL UNIQUE,
			filepath   TEXT NOT NULL,
			size_bytes INTEGER NOT NULL,
			type       TEXT NOT NULL DEFAULT 'auto',
			created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			checksum   TEXT,
			notes      TEXT
		)`,

		// API tokens — SHA-256 hashes only; server.token is NOT stored here
		`CREATE TABLE IF NOT EXISTS api_tokens (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			token_hash     TEXT NOT NULL UNIQUE,
			token_prefix   TEXT NOT NULL,
			resource_type  TEXT NOT NULL,
			resource_id    TEXT NOT NULL,
			created_at     INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			expires_at     INTEGER,
			last_used_at   INTEGER,
			revoked_at     INTEGER,
			revoked_reason TEXT
		)`,

		// Permanent WHOIS record store indexed by registrant fields for reverse-owner search (AI.md PART 14).
		// Records are never expired; they are upserted in place and periodically refreshed.
		`CREATE TABLE IF NOT EXISTS whois_records (
			id                 INTEGER PRIMARY KEY AUTOINCREMENT,
			query              TEXT NOT NULL,
			query_type         TEXT NOT NULL,
			registrant_name    TEXT,
			registrant_org     TEXT,
			registrant_email   TEXT,
			registrant_country TEXT,
			registrar          TEXT,
			created_date       TEXT,
			expiry_date        TEXT,
			nameservers        TEXT,
			status             TEXT,
			whois_server       TEXT,
			raw_whois          TEXT,
			first_seen         INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			last_seen          INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			last_updated       INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
		)`,

		// Unique constraint — upsert by query (one permanent row per query)
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_whois_records_query ON whois_records(query)`,

		// Covering indexes for registrant-field searches and staleness scans
		`CREATE INDEX IF NOT EXISTS idx_whois_records_name      ON whois_records(registrant_name)`,
		`CREATE INDEX IF NOT EXISTS idx_whois_records_org       ON whois_records(registrant_org)`,
		`CREATE INDEX IF NOT EXISTS idx_whois_records_email     ON whois_records(registrant_email)`,
		`CREATE INDEX IF NOT EXISTS idx_whois_records_country   ON whois_records(registrant_country)`,
		`CREATE INDEX IF NOT EXISTS idx_whois_records_expiry    ON whois_records(expiry_date)`,
		`CREATE INDEX IF NOT EXISTS idx_whois_records_last_seen ON whois_records(last_seen)`,

		// Indexes
		`CREATE INDEX IF NOT EXISTS idx_config_key ON config(key)`,
		`CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_category ON audit_log(category)`,
		`CREATE INDEX IF NOT EXISTS idx_scheduler_history_task ON scheduler_history(task_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scheduler_history_started ON scheduler_history(started_at)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_prefix ON api_tokens(token_prefix)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_resource ON api_tokens(resource_type, resource_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_active ON api_tokens(revoked_at) WHERE revoked_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_backups_created ON backups(created_at)`,
	}

	for _, stmt := range statements {
		if _, err := db.Server.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("execute schema statement: %w", err)
		}
	}

	return nil
}
