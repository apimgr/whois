package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

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

	// Open an independent single-connection writer and pooled read-only handle.
	serverPath, err := filepath.Abs(filepath.Join(cfg.Path, "server.db"))
	if err != nil {
		return nil, fmt.Errorf("resolve server.db path: %w", err)
	}
	base := "file:" + (&url.URL{Path: filepath.ToSlash(serverPath)}).EscapedPath() + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"
	writeDB, err := sql.Open("sqlite", base+"&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("open server.db writer: %w", err)
	}
	writeDB.SetMaxOpenConns(1)
	writeDB.SetMaxIdleConns(1)
	writeDB.SetConnMaxLifetime(0)
	writeDB.SetConnMaxIdleTime(0)
	readDB, err := sql.Open("sqlite", base+"&_pragma=query_only(1)")
	if err != nil {
		_ = writeDB.Close()
		return nil, fmt.Errorf("open server.db reader: %w", err)
	}
	ConfigurePool(readDB, cfg.Pool)

	if err := Ping(ctx, writeDB); err != nil {
		_ = writeDB.Close()
		_ = readDB.Close()
		return nil, fmt.Errorf("ping server.db writer: %w", err)
	}
	var journalMode string
	if err := writeDB.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		_ = writeDB.Close()
		_ = readDB.Close()
		return nil, fmt.Errorf("check SQLite journal mode: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		_ = writeDB.Close()
		_ = readDB.Close()
		return nil, fmt.Errorf("SQLite database %s requires WAL mode, got %q", serverPath, journalMode)
	}
	if err := Ping(ctx, readDB); err != nil {
		_ = writeDB.Close()
		_ = readDB.Close()
		return nil, fmt.Errorf("ping server.db reader: %w", err)
	}

	database.writeDB = writeDB
	database.readDB = readDB

	// Ensure schema exists (idempotent CREATE TABLE IF NOT EXISTS)
	if err := database.ensureSchema(ctx); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("ensure schema: %w", err)
	}

	return database, nil
}

// ensureSchema creates all tables if they don't exist (idempotent)
func (db *DB) ensureSchema(ctx context.Context) error {
	if err := db.migrateLegacyAPITokens(ctx); err != nil {
		return err
	}
	if err := db.migrateWhoisRecords(ctx); err != nil {
		return err
	}
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
		`CREATE TABLE IF NOT EXISTS rate_limit_events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			event_key    TEXT NOT NULL,
			occurred_at  INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_rate_limit_events_key_time ON rate_limit_events(event_key, occurred_at)`,
		`CREATE INDEX IF NOT EXISTS idx_rate_limit_events_time ON rate_limit_events(occurred_at)`,

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

		// Generated application secrets and key-rotation state (AI.md PART 11).
		`CREATE TABLE IF NOT EXISTS app_secrets (
			name       TEXT PRIMARY KEY,
			value      TEXT NOT NULL,
			updated_at TEXT NOT NULL
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

		`CREATE TABLE IF NOT EXISTS owners (
			id TEXT PRIMARY KEY,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			last_seen_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
		)`,

		`CREATE TABLE IF NOT EXISTS api_tokens (
			id TEXT PRIMARY KEY,
			owner_id TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
			kind TEXT NOT NULL CHECK (kind IN ('primary', 'linked')),
			name TEXT,
			token_hash TEXT NOT NULL UNIQUE,
			token_prefix TEXT NOT NULL,
			token_last4 TEXT NOT NULL,
			token_enc TEXT NOT NULL,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			rotated_at INTEGER,
			expires_at INTEGER,
			last_used_at INTEGER,
			revoked_at INTEGER,
			revoked_reason TEXT
		)`,

		`CREATE TABLE IF NOT EXISTS security_reports (
			tracking_id        TEXT PRIMARY KEY,
			id_window          INTEGER NOT NULL,
			severity           TEXT NOT NULL,
			component          TEXT NOT NULL,
			status             TEXT NOT NULL DEFAULT 'received',
			body_enc           BLOB NOT NULL,
			body_alg           TEXT NOT NULL,
			contact_enc        BLOB,
			credit_pref        TEXT NOT NULL DEFAULT 'no',
			credit_name        TEXT,
			researcher_comment TEXT NOT NULL DEFAULT '',
			disclosure_date    TEXT,
			cve_requested      INTEGER NOT NULL DEFAULT 0,
			token_hash         TEXT NOT NULL,
			token_last_used    TEXT,
			created_at         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			closed_at          TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS security_thanks (
			tracking_id TEXT PRIMARY KEY,
			credit      TEXT NOT NULL,
			severity    TEXT NOT NULL,
			disclosed_on TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_security_reports_status ON security_reports(status, created_at)`,
		`CREATE TABLE IF NOT EXISTS captcha_challenges (
			id          TEXT PRIMARY KEY,
			answer_hash TEXT NOT NULL,
			expires_at  INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_captcha_challenges_expires ON captcha_challenges(expires_at)`,

		// Permanent WHOIS record store indexed by registrant fields for reverse-owner search (AI.md PART 14).
		// Records are never expired; they are upserted in place and periodically refreshed.
		`CREATE TABLE IF NOT EXISTS whois_records (
			id                 INTEGER PRIMARY KEY AUTOINCREMENT,
			query              TEXT NOT NULL,
			query_type         TEXT NOT NULL,
			source             TEXT NOT NULL DEFAULT 'whois',
			registrant_name    TEXT,
			registrant_org     TEXT,
			registrant_email   TEXT,
			registrant_country TEXT,
			registrar          TEXT,
			created_date       TEXT,
			updated_date       TEXT,
			expiry_date        TEXT,
			nameservers        TEXT,
			status             TEXT,
			whois_server       TEXT,
			rdap_server        TEXT,
			raw_whois          TEXT,
			raw_rdap           TEXT,
			network_name       TEXT,
			network_range      TEXT,
			network_type       TEXT,
			asn_number         INTEGER,
			asn_name           TEXT,
			rir                TEXT,
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
		`CREATE INDEX IF NOT EXISTS idx_whois_records_network_range ON whois_records(network_range)`,
		`CREATE INDEX IF NOT EXISTS idx_whois_records_asn_number ON whois_records(asn_number)`,

		// Indexes
		`CREATE INDEX IF NOT EXISTS idx_config_key ON config(key)`,
		`CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_category ON audit_log(category)`,
		`CREATE INDEX IF NOT EXISTS idx_scheduler_history_task ON scheduler_history(task_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scheduler_history_started ON scheduler_history(started_at)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_prefix ON api_tokens(token_prefix)`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_owner ON api_tokens(owner_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_api_tokens_primary ON api_tokens(owner_id) WHERE kind = 'primary' AND revoked_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_api_tokens_active ON api_tokens(revoked_at) WHERE revoked_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_backups_created ON backups(created_at)`,
	}

	for _, stmt := range statements {
		if err := db.ExecWrite(ctx, stmt); err != nil {
			return fmt.Errorf("execute schema statement: %w", err)
		}
	}
	if err := db.migrateLinkedTokenNameIndex(ctx); err != nil {
		return err
	}

	if err := db.initializeAppSecrets(ctx); err != nil {
		return fmt.Errorf("initialize application secrets: %w", err)
	}

	return nil
}

func (db *DB) migrateLinkedTokenNameIndex(ctx context.Context) error {
	rows, err := db.Read().QueryContext(ctx, `SELECT 1 FROM api_tokens
		WHERE kind = 'linked' AND name IS NOT NULL
		GROUP BY owner_id, name HAVING COUNT(*) > 1 LIMIT 1`)
	if err != nil {
		return fmt.Errorf("check existing linked-token names: %w", err)
	}
	duplicateNames := rows.Next()
	rowsErr := rows.Err()
	closeErr := rows.Close()
	if rowsErr != nil {
		return fmt.Errorf("read existing linked-token names: %w", rowsErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close linked-token name check: %w", closeErr)
	}
	if duplicateNames {
		return fmt.Errorf("existing API token data contains duplicate linked-token names for an owner; resolve duplicate names without deleting tokens, then restart")
	}
	if err := db.ExecWrite(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS idx_api_tokens_linked_owner_name
		ON api_tokens(owner_id, name) WHERE kind = 'linked' AND name IS NOT NULL`); err != nil {
		return fmt.Errorf("create unique linked-token name index: %w", err)
	}
	return nil
}

func (db *DB) migrateLegacyAPITokens(ctx context.Context) error {
	var exists int
	if err := db.Read().QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='api_tokens'`).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return nil
	}
	columns := map[string]bool{}
	rows, err := db.Read().QueryContext(ctx, `PRAGMA table_info(api_tokens)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		columns[name] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if columns["owner_id"] || !columns["resource_type"] {
		return nil
	}
	var legacyExists int
	if err := db.Read().QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='api_tokens_legacy'`).Scan(&legacyExists); err != nil {
		return err
	}
	if legacyExists != 0 {
		return fmt.Errorf("both legacy api_tokens and api_tokens_legacy exist; refusing to overwrite token data")
	}
	for _, index := range []string{"idx_api_tokens_hash", "idx_api_tokens_prefix", "idx_api_tokens_resource", "idx_api_tokens_active"} {
		if err := db.ExecWrite(ctx, `DROP INDEX IF EXISTS `+index); err != nil {
			return fmt.Errorf("drop legacy token index %s: %w", index, err)
		}
	}
	if err := db.ExecWrite(ctx, `ALTER TABLE api_tokens RENAME TO api_tokens_legacy`); err != nil {
		return fmt.Errorf("preserve legacy API tokens: %w", err)
	}
	return nil
}

func (db *DB) migrateWhoisRecords(ctx context.Context) error {
	var exists int
	if err := db.Read().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='whois_records'`).Scan(&exists); err != nil {
		return fmt.Errorf("check whois_records table: %w", err)
	}
	if exists == 0 {
		return nil
	}
	rows, err := db.Read().QueryContext(ctx, `PRAGMA table_info(whois_records)`)
	if err != nil {
		return fmt.Errorf("inspect whois_records columns: %w", err)
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan whois_records columns: %w", err)
		}
		columns[name] = true
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close whois_records column query: %w", err)
	}
	additions := []struct {
		name    string
		typeSQL string
	}{
		{name: "source", typeSQL: `TEXT NOT NULL DEFAULT 'whois'`},
		{name: "updated_date", typeSQL: "TEXT"},
		{name: "rdap_server", typeSQL: "TEXT"},
		{name: "raw_rdap", typeSQL: "TEXT"},
		{name: "network_name", typeSQL: "TEXT"},
		{name: "network_range", typeSQL: "TEXT"},
		{name: "network_type", typeSQL: "TEXT"},
		{name: "asn_number", typeSQL: "INTEGER"},
		{name: "asn_name", typeSQL: "TEXT"},
		{name: "rir", typeSQL: "TEXT"},
	}
	for _, column := range additions {
		if columns[column.name] {
			continue
		}
		if err := db.ExecWrite(ctx,
			`ALTER TABLE whois_records ADD COLUMN `+column.name+` `+column.typeSQL); err != nil && !IsColumnExistsError(err) {
			return fmt.Errorf("add whois_records.%s: %w", column.name, err)
		}
	}
	return nil
}

func (db *DB) initializeAppSecrets(ctx context.Context) error {
	return db.Write(ctx, func(tx *sql.Tx) error {
		for _, name := range []string{"installation_secret", "cookie_signing_key", "csrf_token_secret"} {
			var exists int
			err := tx.QueryRowContext(ctx, `SELECT 1 FROM app_secrets WHERE name = ?`, name).Scan(&exists)
			if err == nil {
				continue
			}
			if err != sql.ErrNoRows {
				return fmt.Errorf("check %s: %w", name, err)
			}

			value := make([]byte, 32)
			if _, err := rand.Read(value); err != nil {
				return fmt.Errorf("generate %s: %w", name, err)
			}
			_, err = tx.ExecContext(ctx,
				`INSERT INTO app_secrets (name, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO NOTHING`,
				name, base64.StdEncoding.EncodeToString(value), time.Now().UTC().Format(time.RFC3339),
			)
			if err != nil {
				return fmt.Errorf("store %s: %w", name, err)
			}
		}
		return nil
	})
}
