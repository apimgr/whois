package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

// NewLibSQL creates a libsql/Turso remote database connection for server.db.
// libSQL has no embedded/local mode under CGO_ENABLED=0 (PART 10), so cfg.URL
// is required and points at a remote libsql/sqld/Turso server.
func NewLibSQL(ctx context.Context, cfg *DatabaseConfig) (*DB, error) {
	if err := validateLibSQL(cfg); err != nil {
		return nil, err
	}

	database := &DB{
		Driver: "libsql",
	}

	dsn := buildLibSQLDSN(cfg.URL, cfg.Token)
	serverDB, err := sql.Open("libsql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open libsql connection: %w", err)
	}

	ConfigurePool(serverDB, cfg.Pool)

	if err := Ping(ctx, serverDB); err != nil {
		serverDB.Close()
		return nil, fmt.Errorf("ping libsql connection: %w", err)
	}

	database.Server = serverDB

	// Ensure schema exists (idempotent CREATE TABLE IF NOT EXISTS) — libsql
	// is SQLite wire-compatible, so the same schema statements apply
	// (AI.md PART 10, "Remote Database Updates").
	if err := database.ensureSchema(ctx); err != nil {
		database.Close()
		return nil, fmt.Errorf("ensure schema: %w", err)
	}

	return database, nil
}

// validateLibSQL checks that the config carries a usable remote URL.
func validateLibSQL(cfg *DatabaseConfig) error {
	if cfg == nil {
		return fmt.Errorf("database config is nil")
	}
	if strings.TrimSpace(cfg.URL) == "" {
		return fmt.Errorf("libsql driver requires url: use libsql://host?authToken=xxx or https://host with token field")
	}
	return nil
}

// buildLibSQLDSN appends the auth token to the URL when the caller supplied
// it via the separate Token field rather than embedding it in the URL.
func buildLibSQLDSN(url, token string) string {
	if token == "" || strings.Contains(url, "authToken=") {
		return url
	}
	separator := "?"
	if strings.Contains(url, "?") {
		separator = "&"
	}
	return url + separator + "authToken=" + token
}
