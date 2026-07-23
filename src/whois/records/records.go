// Package records provides permanent persistence of WHOIS lookups in the
// whois_records table, indexed by registrant fields for reverse-owner search
// (AI.md PART 14). Records are never expired; they are upserted in place and
// periodically refreshed by the scheduler.
package records

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/apimgr/whois/src/whois/parser"
)

// Record represents one row in the whois_records table.
type Record struct {
	Query             string   `json:"query"`
	QueryType         string   `json:"query_type"`
	RegistrantName    string   `json:"registrant_name,omitempty"`
	RegistrantOrg     string   `json:"registrant_org,omitempty"`
	RegistrantEmail   string   `json:"registrant_email,omitempty"`
	RegistrantCountry string   `json:"registrant_country,omitempty"`
	Registrar         string   `json:"registrar,omitempty"`
	CreatedDate       string   `json:"created_date,omitempty"`
	ExpiryDate        string   `json:"expiry_date,omitempty"`
	Nameservers       []string `json:"nameservers,omitempty"`
	Status            []string `json:"status,omitempty"`
	WHOISServer       string   `json:"whois_server,omitempty"`
	RawWHOIS          string   `json:"raw_whois,omitempty"`
	FirstSeen         int64    `json:"first_seen"`
	LastSeen          int64    `json:"last_seen"`
	LastUpdated       int64    `json:"last_updated"`
}

// UpsertRecord permanently stores or updates a WHOIS lookup in whois_records.
// On insert, first_seen is set to now. On conflict (same query), the registrant
// and record fields are refreshed and last_seen/last_updated are bumped, while
// first_seen is preserved. Only domain-type results carry registrant fields.
func UpsertRecord(ctx context.Context, db *sql.DB, query, queryType string, result *parser.DomainResult) error {
	if result == nil {
		return nil
	}

	now := time.Now().Unix()
	normalizedQuery := strings.ToLower(strings.TrimSpace(query))

	createdDate := nullableTime(result.CreatedDate)
	expiryDate := nullableTime(result.ExpiryDate)
	nameservers := nullableJSON(result.Nameservers)
	status := nullableJSON(result.Status)

	_, err := db.ExecContext(ctx,
		`INSERT INTO whois_records
			(query, query_type, registrant_name, registrant_org, registrant_email, registrant_country,
			 registrar, created_date, expiry_date, nameservers, status, whois_server, raw_whois,
			 first_seen, last_seen, last_updated)
		VALUES
			(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(query) DO UPDATE SET
			query_type         = excluded.query_type,
			registrant_name    = excluded.registrant_name,
			registrant_org     = excluded.registrant_org,
			registrant_email   = excluded.registrant_email,
			registrant_country = excluded.registrant_country,
			registrar          = excluded.registrar,
			created_date       = excluded.created_date,
			expiry_date        = excluded.expiry_date,
			nameservers        = excluded.nameservers,
			status             = excluded.status,
			whois_server       = excluded.whois_server,
			raw_whois          = excluded.raw_whois,
			last_seen          = excluded.last_seen,
			last_updated       = excluded.last_updated`,
		normalizedQuery,
		queryType,
		nullableString(result.Registrant),
		nullableString(result.Organization),
		nullableString(result.Email),
		nullableString(result.Country),
		nullableString(result.Registrar),
		createdDate,
		expiryDate,
		nameservers,
		status,
		nil,
		nullableString(result.Raw),
		now,
		now,
		now,
	)
	if err != nil {
		return fmt.Errorf("upsert whois record: %w", err)
	}
	return nil
}

// SearchByOwner returns records where registrant_name, registrant_org, or
// registrant_email contains the owner term (case-insensitive substring match).
// There is no TTL filter — all stored records are searched. Results are ordered
// by last_seen DESC.
func SearchByOwner(ctx context.Context, db *sql.DB, owner string, limit, offset int) ([]Record, error) {
	if strings.TrimSpace(owner) == "" {
		return nil, fmt.Errorf("owner search term must not be empty")
	}

	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	pattern := "%" + strings.ToLower(strings.TrimSpace(owner)) + "%"

	rows, err := db.QueryContext(ctx,
		`SELECT query, query_type,
		        COALESCE(registrant_name, ''),
		        COALESCE(registrant_org, ''),
		        COALESCE(registrant_email, ''),
		        COALESCE(registrant_country, ''),
		        COALESCE(registrar, ''),
		        COALESCE(created_date, ''),
		        COALESCE(expiry_date, ''),
		        COALESCE(nameservers, ''),
		        COALESCE(status, ''),
		        COALESCE(whois_server, ''),
		        first_seen,
		        last_seen,
		        last_updated
		FROM whois_records
		WHERE LOWER(registrant_name)  LIKE ?
		   OR LOWER(registrant_org)   LIKE ?
		   OR LOWER(registrant_email) LIKE ?
		ORDER BY last_seen DESC
		LIMIT ? OFFSET ?`,
		pattern, pattern, pattern, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("search whois records: %w", err)
	}
	defer rows.Close()

	var recs []Record
	for rows.Next() {
		var r Record
		var nameserversJSON, statusJSON string
		if err := rows.Scan(
			&r.Query, &r.QueryType,
			&r.RegistrantName, &r.RegistrantOrg, &r.RegistrantEmail, &r.RegistrantCountry,
			&r.Registrar, &r.CreatedDate, &r.ExpiryDate,
			&nameserversJSON, &statusJSON, &r.WHOISServer,
			&r.FirstSeen, &r.LastSeen, &r.LastUpdated,
		); err != nil {
			return nil, fmt.Errorf("scan whois record row: %w", err)
		}
		r.Nameservers = decodeJSON(nameserversJSON)
		r.Status = decodeJSON(statusJSON)
		recs = append(recs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate whois record rows: %w", err)
	}

	return recs, nil
}

// CountByOwner returns the total number of local whois_records rows matching
// the same owner search term used by SearchByOwner, for pagination totals.
func CountByOwner(ctx context.Context, db *sql.DB, owner string) (int, error) {
	if strings.TrimSpace(owner) == "" {
		return 0, fmt.Errorf("owner search term must not be empty")
	}

	pattern := "%" + strings.ToLower(strings.TrimSpace(owner)) + "%"

	var total int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM whois_records
		WHERE LOWER(registrant_name)  LIKE ?
		   OR LOWER(registrant_org)   LIKE ?
		   OR LOWER(registrant_email) LIKE ?`,
		pattern, pattern, pattern,
	).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("count whois records: %w", err)
	}

	return total, nil
}

// RefreshStale returns the list of queries whose last_updated is older than
// maxAgeDays days. The scheduler re-queries each returned query and calls
// UpsertRecord to refresh it.
func RefreshStale(ctx context.Context, db *sql.DB, maxAgeDays int) ([]string, error) {
	if maxAgeDays <= 0 {
		maxAgeDays = 30
	}
	cutoff := time.Now().Add(-time.Duration(maxAgeDays) * 24 * time.Hour).Unix()

	rows, err := db.QueryContext(ctx,
		`SELECT query FROM whois_records WHERE last_updated < ? ORDER BY last_updated ASC`,
		cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("find stale whois records: %w", err)
	}
	defer rows.Close()

	var queries []string
	for rows.Next() {
		var q string
		if err := rows.Scan(&q); err != nil {
			return nil, fmt.Errorf("scan stale whois query: %w", err)
		}
		queries = append(queries, q)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate stale whois rows: %w", err)
	}

	return queries, nil
}

// nullableString returns an empty string as nil so SQLite stores NULL instead of "".
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// nullableTime returns a zero time as nil, otherwise an RFC3339 string.
func nullableTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// nullableJSON marshals a slice to a JSON array string, or nil when empty.
func nullableJSON(v []string) interface{} {
	if len(v) == 0 {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return string(b)
}

// decodeJSON parses a JSON array string into a slice; returns nil on empty or error.
func decodeJSON(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}
