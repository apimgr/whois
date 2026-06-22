package history

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/casapps/caswhois/src/whois/parser"
)

// Entry represents one row in the whois_history table.
type Entry struct {
	Query              string    `json:"query"`
	QueryType          string    `json:"query_type"`
	RegistrantName     string    `json:"registrant_name,omitempty"`
	RegistrantOrg      string    `json:"registrant_org,omitempty"`
	RegistrantEmail    string    `json:"registrant_email,omitempty"`
	RegistrantCountry  string    `json:"registrant_country,omitempty"`
	LookedUpAt         time.Time `json:"looked_up_at"`
	ExpiresAt          time.Time `json:"expires_at"`
}

// domainTTL is the cache lifetime for domain history entries (mirrors whois.DefaultTTLs.Domain).
const domainTTL = 24 * time.Hour

// SaveDomain upserts a domain WHOIS lookup into whois_history.
// Only domain-type results carry registrant fields; other types are ignored.
func SaveDomain(ctx context.Context, db *sql.DB, query string, result *parser.DomainResult) error {
	if result == nil {
		return nil
	}

	now := time.Now().Unix()
	expires := time.Now().Add(domainTTL).Unix()

	_, err := db.ExecContext(ctx,
		`INSERT INTO whois_history
			(query, query_type, registrant_name, registrant_org, registrant_email, registrant_country, looked_up_at, expires_at)
		VALUES
			(?, 'domain', ?, ?, ?, ?, ?, ?)
		ON CONFLICT(query) DO UPDATE SET
			registrant_name    = excluded.registrant_name,
			registrant_org     = excluded.registrant_org,
			registrant_email   = excluded.registrant_email,
			registrant_country = excluded.registrant_country,
			looked_up_at       = excluded.looked_up_at,
			expires_at         = excluded.expires_at`,
		strings.ToLower(strings.TrimSpace(query)),
		nullableString(result.Registrant),
		nullableString(result.Organization),
		nullableString(result.Email),
		nullableString(result.Country),
		now,
		expires,
	)
	if err != nil {
		return fmt.Errorf("save domain history: %w", err)
	}
	return nil
}

// SearchByOwner returns history entries where registrant_name, registrant_org, or
// registrant_email contains the owner term (case-insensitive substring match).
// Expired entries are excluded. Results are ordered by looked_up_at DESC.
func SearchByOwner(ctx context.Context, db *sql.DB, owner string, limit, offset int) ([]Entry, error) {
	if strings.TrimSpace(owner) == "" {
		return nil, fmt.Errorf("owner search term must not be empty")
	}

	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	now := time.Now().Unix()
	pattern := "%" + strings.ToLower(strings.TrimSpace(owner)) + "%"

	rows, err := db.QueryContext(ctx,
		`SELECT query, query_type,
		        COALESCE(registrant_name, ''),
		        COALESCE(registrant_org, ''),
		        COALESCE(registrant_email, ''),
		        COALESCE(registrant_country, ''),
		        looked_up_at,
		        expires_at
		FROM whois_history
		WHERE expires_at > ?
		  AND (
		    LOWER(registrant_name)  LIKE ?
		    OR LOWER(registrant_org)   LIKE ?
		    OR LOWER(registrant_email) LIKE ?
		  )
		ORDER BY looked_up_at DESC
		LIMIT ? OFFSET ?`,
		now, pattern, pattern, pattern, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("search whois history: %w", err)
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var lookedUpUnix, expiresUnix int64
		if err := rows.Scan(
			&e.Query, &e.QueryType,
			&e.RegistrantName, &e.RegistrantOrg, &e.RegistrantEmail, &e.RegistrantCountry,
			&lookedUpUnix, &expiresUnix,
		); err != nil {
			return nil, fmt.Errorf("scan whois history row: %w", err)
		}
		e.LookedUpAt = time.Unix(lookedUpUnix, 0).UTC()
		e.ExpiresAt = time.Unix(expiresUnix, 0).UTC()
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate whois history rows: %w", err)
	}

	return entries, nil
}

// DeleteExpired removes all whois_history rows whose expires_at is in the past.
// Called by the scheduler's history_cleanup task.
func DeleteExpired(ctx context.Context, db *sql.DB) (int64, error) {
	res, err := db.ExecContext(ctx,
		`DELETE FROM whois_history WHERE expires_at <= ?`,
		time.Now().Unix(),
	)
	if err != nil {
		return 0, fmt.Errorf("delete expired whois history: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// nullableString returns an empty string as nil so SQLite stores NULL instead of "".
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
