package records

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/apimgr/whois/src/whois/parser"
	_ "modernc.org/sqlite"
)

// openTestDB creates an in-memory SQLite database with the whois_records table.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open in-memory db: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS whois_records (
		query              TEXT PRIMARY KEY,
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
		first_seen         INTEGER NOT NULL,
		last_seen          INTEGER NOT NULL,
		last_updated       INTEGER NOT NULL
	)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

// --- nullableString ---

func TestNullableString_Empty(t *testing.T) {
	got := nullableString("")
	if got != nil {
		t.Errorf("nullableString(\"\") = %v, want nil", got)
	}
}

func TestNullableString_NonEmpty(t *testing.T) {
	got := nullableString("hello")
	if got != "hello" {
		t.Errorf("nullableString(\"hello\") = %v, want \"hello\"", got)
	}
}

// --- nullableTime ---

func TestNullableTime_Zero(t *testing.T) {
	got := nullableTime(time.Time{})
	if got != nil {
		t.Errorf("nullableTime(zero) = %v, want nil", got)
	}
}

func TestNullableTime_NonZero(t *testing.T) {
	ts := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	got := nullableTime(ts)
	s, ok := got.(string)
	if !ok {
		t.Fatalf("nullableTime(non-zero) returned %T, want string", got)
	}
	if !strings.Contains(s, "2024-01-15") {
		t.Errorf("nullableTime returned %q, expected date to contain 2024-01-15", s)
	}
}

func TestNullableTime_RFC3339Format(t *testing.T) {
	ts := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	got := nullableTime(ts)
	s := got.(string)
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Errorf("nullableTime output %q is not RFC3339: %v", s, err)
	}
	if !parsed.Equal(ts) {
		t.Errorf("parsed time %v != original %v", parsed, ts)
	}
}

// --- nullableJSON ---

func TestNullableJSON_Empty(t *testing.T) {
	got := nullableJSON(nil)
	if got != nil {
		t.Errorf("nullableJSON(nil) = %v, want nil", got)
	}
}

func TestNullableJSON_EmptySlice(t *testing.T) {
	got := nullableJSON([]string{})
	if got != nil {
		t.Errorf("nullableJSON(empty slice) = %v, want nil", got)
	}
}

func TestNullableJSON_SingleElement(t *testing.T) {
	got := nullableJSON([]string{"ns1.example.com"})
	s, ok := got.(string)
	if !ok {
		t.Fatalf("nullableJSON single element returned %T, want string", got)
	}
	if !strings.Contains(s, "ns1.example.com") {
		t.Errorf("nullableJSON output %q missing expected element", s)
	}
}

func TestNullableJSON_MultipleElements(t *testing.T) {
	got := nullableJSON([]string{"ns1.example.com", "ns2.example.com"})
	s, ok := got.(string)
	if !ok {
		t.Fatalf("nullableJSON multi element returned %T, want string", got)
	}
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		t.Errorf("nullableJSON multi output %q is not a JSON array", s)
	}
}

// --- decodeJSON ---

func TestDecodeJSON_Empty(t *testing.T) {
	got := decodeJSON("")
	if got != nil {
		t.Errorf("decodeJSON(\"\") = %v, want nil", got)
	}
}

func TestDecodeJSON_Whitespace(t *testing.T) {
	got := decodeJSON("   ")
	if got != nil {
		t.Errorf("decodeJSON(whitespace) = %v, want nil", got)
	}
}

func TestDecodeJSON_InvalidJSON(t *testing.T) {
	got := decodeJSON("not json")
	if got != nil {
		t.Errorf("decodeJSON(invalid) = %v, want nil", got)
	}
}

func TestDecodeJSON_ValidArray(t *testing.T) {
	got := decodeJSON(`["ns1.example.com","ns2.example.com"]`)
	if len(got) != 2 {
		t.Fatalf("decodeJSON valid array len = %d, want 2", len(got))
	}
	if got[0] != "ns1.example.com" {
		t.Errorf("got[0] = %q, want ns1.example.com", got[0])
	}
	if got[1] != "ns2.example.com" {
		t.Errorf("got[1] = %q, want ns2.example.com", got[1])
	}
}

func TestDecodeJSON_EmptyArray(t *testing.T) {
	got := decodeJSON(`[]`)
	if len(got) != 0 {
		t.Errorf("decodeJSON(empty array) len = %d, want 0", len(got))
	}
}

// --- UpsertRecord ---

func TestUpsertRecord_NilResult(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	err := UpsertRecord(context.Background(), db, "example.com", "domain", nil)
	if err != nil {
		t.Errorf("UpsertRecord with nil result: unexpected error %v", err)
	}
}

func TestUpsertRecord_BasicInsert(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	result := &parser.DomainResult{
		Registrant:   "Jane Doe",
		Organization: "Acme Corp",
		Email:        "jane@acme.com",
		Country:      "US",
		Registrar:    "GoDaddy",
		Nameservers:  []string{"ns1.acme.com", "ns2.acme.com"},
		Status:       []string{"clientTransferProhibited"},
		Raw:          "raw whois data",
	}

	err := UpsertRecord(context.Background(), db, "example.com", "domain", result)
	if err != nil {
		t.Fatalf("UpsertRecord insert: %v", err)
	}

	var query, registrantName string
	row := db.QueryRow(`SELECT query, registrant_name FROM whois_records WHERE query = ?`, "example.com")
	if err := row.Scan(&query, &registrantName); err != nil {
		t.Fatalf("scan inserted row: %v", err)
	}
	if query != "example.com" {
		t.Errorf("query = %q, want example.com", query)
	}
	if registrantName != "Jane Doe" {
		t.Errorf("registrant_name = %q, want Jane Doe", registrantName)
	}
}

func TestUpsertRecord_NormalizesQuery(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	result := &parser.DomainResult{Registrant: "Tester"}
	err := UpsertRecord(context.Background(), db, "  EXAMPLE.COM  ", "domain", result)
	if err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM whois_records WHERE query = ?`, "example.com").Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 1 {
		t.Errorf("normalized query count = %d, want 1", count)
	}
}

func TestUpsertRecord_ConflictUpdates(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	first := &parser.DomainResult{Registrant: "First Owner"}
	if err := UpsertRecord(context.Background(), db, "example.com", "domain", first); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	var firstSeen1 int64
	if err := db.QueryRow(`SELECT first_seen FROM whois_records WHERE query = ?`, "example.com").Scan(&firstSeen1); err != nil {
		t.Fatalf("scan first_seen: %v", err)
	}

	second := &parser.DomainResult{Registrant: "Second Owner"}
	if err := UpsertRecord(context.Background(), db, "example.com", "domain", second); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	var firstSeen2 int64
	var registrantName string
	row := db.QueryRow(`SELECT first_seen, registrant_name FROM whois_records WHERE query = ?`, "example.com")
	if err := row.Scan(&firstSeen2, &registrantName); err != nil {
		t.Fatalf("scan after second upsert: %v", err)
	}

	if firstSeen2 != firstSeen1 {
		t.Errorf("first_seen changed on conflict: was %d, got %d", firstSeen1, firstSeen2)
	}
	if registrantName != "Second Owner" {
		t.Errorf("registrant_name = %q after conflict update, want Second Owner", registrantName)
	}
}

func TestUpsertRecord_WithDates(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	createdAt := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	result := &parser.DomainResult{
		Registrant:  "Owner",
		CreatedDate: createdAt,
		ExpiryDate:  expiresAt,
	}

	err := UpsertRecord(context.Background(), db, "dated.com", "domain", result)
	if err != nil {
		t.Fatalf("UpsertRecord with dates: %v", err)
	}

	var createdDate, expiryDate string
	row := db.QueryRow(`SELECT COALESCE(created_date,''), COALESCE(expiry_date,'') FROM whois_records WHERE query = ?`, "dated.com")
	if err := row.Scan(&createdDate, &expiryDate); err != nil {
		t.Fatalf("scan dates: %v", err)
	}
	if !strings.Contains(createdDate, "2020") {
		t.Errorf("created_date = %q, want to contain 2020", createdDate)
	}
	if !strings.Contains(expiryDate, "2025") {
		t.Errorf("expiry_date = %q, want to contain 2025", expiryDate)
	}
}

func TestUpsertRecord_EmptyFields(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	result := &parser.DomainResult{}
	err := UpsertRecord(context.Background(), db, "minimal.com", "domain", result)
	if err != nil {
		t.Fatalf("UpsertRecord with empty fields: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM whois_records WHERE query = ?`, "minimal.com").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
}

func TestUpsertRecord_BadDB(t *testing.T) {
	db := openTestDB(t)
	db.Close()
	result := &parser.DomainResult{Registrant: "Owner"}
	err := UpsertRecord(context.Background(), db, "fail.com", "domain", result)
	if err == nil {
		t.Error("UpsertRecord on closed db should return error")
	}
}

// --- SearchByOwner ---

func TestSearchByOwner_EmptyOwner(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	_, err := SearchByOwner(context.Background(), db, "", 10, 0)
	if err == nil {
		t.Error("SearchByOwner with empty owner should return error")
	}
}

func TestSearchByOwner_WhitespaceOnlyOwner(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	_, err := SearchByOwner(context.Background(), db, "   ", 10, 0)
	if err == nil {
		t.Error("SearchByOwner with whitespace-only owner should return error")
	}
}

func TestSearchByOwner_EmptyDB(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	recs, err := SearchByOwner(context.Background(), db, "acme", 10, 0)
	if err != nil {
		t.Fatalf("SearchByOwner empty db: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("got %d records from empty db, want 0", len(recs))
	}
}

func TestSearchByOwner_FindsByName(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	r := &parser.DomainResult{Registrant: "Acme Corp", Organization: "Acme Inc", Email: "admin@acme.com"}
	if err := UpsertRecord(context.Background(), db, "acme.com", "domain", r); err != nil {
		t.Fatalf("setup: %v", err)
	}

	recs, err := SearchByOwner(context.Background(), db, "Acme", 10, 0)
	if err != nil {
		t.Fatalf("SearchByOwner: %v", err)
	}
	if len(recs) != 1 {
		t.Errorf("got %d records, want 1", len(recs))
	}
	if recs[0].Query != "acme.com" {
		t.Errorf("record query = %q, want acme.com", recs[0].Query)
	}
}

func TestSearchByOwner_FindsByEmail(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	r := &parser.DomainResult{Email: "user@domain.com"}
	if err := UpsertRecord(context.Background(), db, "domain.com", "domain", r); err != nil {
		t.Fatalf("setup: %v", err)
	}

	recs, err := SearchByOwner(context.Background(), db, "user@domain.com", 10, 0)
	if err != nil {
		t.Fatalf("SearchByOwner by email: %v", err)
	}
	if len(recs) != 1 {
		t.Errorf("got %d records, want 1", len(recs))
	}
}

func TestSearchByOwner_CaseInsensitive(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	r := &parser.DomainResult{Registrant: "UPPERCASE ORG"}
	if err := UpsertRecord(context.Background(), db, "upper.com", "domain", r); err != nil {
		t.Fatalf("setup: %v", err)
	}

	recs, err := SearchByOwner(context.Background(), db, "uppercase", 10, 0)
	if err != nil {
		t.Fatalf("SearchByOwner case insensitive: %v", err)
	}
	if len(recs) != 1 {
		t.Errorf("case-insensitive search: got %d records, want 1", len(recs))
	}
}

func TestSearchByOwner_NoMatch(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	r := &parser.DomainResult{Registrant: "SomeCompany"}
	if err := UpsertRecord(context.Background(), db, "some.com", "domain", r); err != nil {
		t.Fatalf("setup: %v", err)
	}

	recs, err := SearchByOwner(context.Background(), db, "differentowner", 10, 0)
	if err != nil {
		t.Fatalf("SearchByOwner no match: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("got %d records for non-matching query, want 0", len(recs))
	}
}

func TestSearchByOwner_LimitClamping(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	for i := 0; i < 3; i++ {
		r := &parser.DomainResult{Registrant: "BigOrg"}
		domain := "domain" + string(rune('0'+i)) + ".com"
		if err := UpsertRecord(context.Background(), db, domain, "domain", r); err != nil {
			t.Fatalf("setup i=%d: %v", i, err)
		}
	}

	recs, err := SearchByOwner(context.Background(), db, "BigOrg", -1, 0)
	if err != nil {
		t.Fatalf("SearchByOwner clamp limit: %v", err)
	}
	if len(recs) != 3 {
		t.Errorf("got %d records with clamped limit, want 3", len(recs))
	}
}

func TestSearchByOwner_LimitTooLarge(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	r := &parser.DomainResult{Registrant: "BigOrg"}
	if err := UpsertRecord(context.Background(), db, "big.com", "domain", r); err != nil {
		t.Fatalf("setup: %v", err)
	}

	recs, err := SearchByOwner(context.Background(), db, "BigOrg", 600, 0)
	if err != nil {
		t.Fatalf("SearchByOwner limit>500: %v", err)
	}
	if len(recs) != 1 {
		t.Errorf("got %d records, want 1", len(recs))
	}
}

func TestSearchByOwner_NegativeOffset(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	r := &parser.DomainResult{Registrant: "Owner"}
	if err := UpsertRecord(context.Background(), db, "off.com", "domain", r); err != nil {
		t.Fatalf("setup: %v", err)
	}

	recs, err := SearchByOwner(context.Background(), db, "Owner", 10, -5)
	if err != nil {
		t.Fatalf("SearchByOwner negative offset: %v", err)
	}
	if len(recs) != 1 {
		t.Errorf("got %d records with negative offset, want 1", len(recs))
	}
}

func TestSearchByOwner_DecodesNameservers(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	r := &parser.DomainResult{
		Registrant:  "NsOwner",
		Nameservers: []string{"ns1.example.com", "ns2.example.com"},
	}
	if err := UpsertRecord(context.Background(), db, "ns.com", "domain", r); err != nil {
		t.Fatalf("setup: %v", err)
	}

	recs, err := SearchByOwner(context.Background(), db, "NsOwner", 10, 0)
	if err != nil {
		t.Fatalf("SearchByOwner: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if len(recs[0].Nameservers) != 2 {
		t.Errorf("nameservers len = %d, want 2", len(recs[0].Nameservers))
	}
}

func TestSearchByOwner_ClosedDB(t *testing.T) {
	db := openTestDB(t)
	db.Close()
	_, err := SearchByOwner(context.Background(), db, "owner", 10, 0)
	if err == nil {
		t.Error("SearchByOwner on closed db should return error")
	}
}

// --- RefreshStale ---

func TestRefreshStale_EmptyDB(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	queries, err := RefreshStale(context.Background(), db, 30)
	if err != nil {
		t.Fatalf("RefreshStale empty db: %v", err)
	}
	if len(queries) != 0 {
		t.Errorf("got %d queries from empty db, want 0", len(queries))
	}
}

func TestRefreshStale_NegativeMaxAge(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	queries, err := RefreshStale(context.Background(), db, -1)
	if err != nil {
		t.Fatalf("RefreshStale negative maxAge: %v", err)
	}
	if len(queries) != 0 {
		t.Errorf("expected 0 stale queries from empty db, got %d", len(queries))
	}
}

func TestRefreshStale_FindsStaleRecords(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	staleTime := time.Now().Add(-60 * 24 * time.Hour).Unix()
	_, err := db.Exec(`INSERT INTO whois_records
		(query, query_type, first_seen, last_seen, last_updated)
		VALUES (?, ?, ?, ?, ?)`,
		"stale.com", "domain", staleTime, staleTime, staleTime)
	if err != nil {
		t.Fatalf("insert stale record: %v", err)
	}

	freshTime := time.Now().Unix()
	_, err = db.Exec(`INSERT INTO whois_records
		(query, query_type, first_seen, last_seen, last_updated)
		VALUES (?, ?, ?, ?, ?)`,
		"fresh.com", "domain", freshTime, freshTime, freshTime)
	if err != nil {
		t.Fatalf("insert fresh record: %v", err)
	}

	queries, err := RefreshStale(context.Background(), db, 30)
	if err != nil {
		t.Fatalf("RefreshStale: %v", err)
	}
	if len(queries) != 1 {
		t.Fatalf("got %d stale queries, want 1", len(queries))
	}
	if queries[0] != "stale.com" {
		t.Errorf("stale query = %q, want stale.com", queries[0])
	}
}

func TestRefreshStale_ZeroMaxAge(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	staleTime := time.Now().Add(-60 * 24 * time.Hour).Unix()
	_, err := db.Exec(`INSERT INTO whois_records
		(query, query_type, first_seen, last_seen, last_updated)
		VALUES (?, ?, ?, ?, ?)`,
		"stale2.com", "domain", staleTime, staleTime, staleTime)
	if err != nil {
		t.Fatalf("insert stale record: %v", err)
	}

	queries, err := RefreshStale(context.Background(), db, 0)
	if err != nil {
		t.Fatalf("RefreshStale zero maxAge: %v", err)
	}
	if len(queries) != 1 {
		t.Errorf("RefreshStale(0) should default to 30 days: got %d queries, want 1", len(queries))
	}
}

func TestRefreshStale_ClosedDB(t *testing.T) {
	db := openTestDB(t)
	db.Close()
	_, err := RefreshStale(context.Background(), db, 30)
	if err == nil {
		t.Error("RefreshStale on closed db should return error")
	}
}
