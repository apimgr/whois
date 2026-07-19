// Package scheduler tests for built-in task handlers (tasks.go).
// Covers no-op behavior when hooks are nil and hook invocation when set.
package scheduler

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// openTasksDB opens an in-memory SQLite DB with both scheduler_tasks and api_tokens tables.
func openTasksDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS scheduler_tasks (
		id         TEXT PRIMARY KEY,
		name       TEXT NOT NULL DEFAULT '',
		schedule   TEXT NOT NULL DEFAULT '',
		last_run   DATETIME,
		last_status TEXT NOT NULL DEFAULT '',
		last_error TEXT NOT NULL DEFAULT '',
		next_run   DATETIME,
		run_count  INTEGER NOT NULL DEFAULT 0,
		fail_count INTEGER NOT NULL DEFAULT 0,
		enabled    INTEGER NOT NULL DEFAULT 1
	)`)
	if err != nil {
		t.Fatalf("create scheduler_tasks: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS api_tokens (
		id         TEXT PRIMARY KEY,
		token_hash TEXT,
		revoked_at DATETIME
	)`)
	if err != nil {
		t.Fatalf("create api_tokens: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS whois_records (
		query             TEXT PRIMARY KEY,
		query_type        TEXT NOT NULL DEFAULT '',
		registrant_name   TEXT,
		registrant_org    TEXT,
		registrant_email  TEXT,
		registrant_country TEXT,
		registrar         TEXT,
		created_date      TEXT,
		expiry_date       TEXT,
		nameservers       TEXT,
		status            TEXT,
		whois_server      TEXT,
		raw_whois         TEXT,
		first_seen        INTEGER NOT NULL DEFAULT 0,
		last_seen         INTEGER NOT NULL DEFAULT 0,
		last_updated      INTEGER NOT NULL DEFAULT 0
	)`)
	if err != nil {
		t.Fatalf("create whois_records: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// newTasksScheduler creates a Scheduler for task handler tests.
func newTasksScheduler(t *testing.T) *Scheduler {
	t.Helper()
	db := openTasksDB(t)
	s, err := New(db, "UTC", 10*time.Minute)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// TestRegisterBuiltInTasks verifies all 13 built-in tasks are registered without error.
func TestRegisterBuiltInTasks(t *testing.T) {
	s := newTasksScheduler(t)
	if err := s.RegisterBuiltInTasks(); err != nil {
		t.Fatalf("RegisterBuiltInTasks: %v", err)
	}
	tasks := s.GetTasks()
	if len(tasks) != 13 {
		t.Errorf("got %d tasks, want 13", len(tasks))
	}
}

// TestRegisterBuiltInTasks_IDs verifies each built-in task ID is present.
func TestRegisterBuiltInTasks_IDs(t *testing.T) {
	s := newTasksScheduler(t)
	if err := s.RegisterBuiltInTasks(); err != nil {
		t.Fatalf("RegisterBuiltInTasks: %v", err)
	}
	requiredIDs := []string{
		"token_cleanup",
		"log_rotation",
		"backup_daily",
		"backup_hourly",
		"ssl_renewal",
		"geoip_update",
		"blocklist_update",
		"cve_update",
		"healthcheck_self",
		"tor_health",
		"whois_records_refresh",
		"rdap_bootstrap_update",
		"update_check",
	}
	for _, id := range requiredIDs {
		if _, err := s.GetTask(id); err != nil {
			t.Errorf("built-in task %q not registered: %v", id, err)
		}
	}
}

// TestRegisterBuiltInTasks_BackupHourlyDisabled verifies backup_hourly is registered
// with Enabled=false per the spec.
func TestRegisterBuiltInTasks_BackupHourlyDisabled(t *testing.T) {
	s := newTasksScheduler(t)
	if err := s.RegisterBuiltInTasks(); err != nil {
		t.Fatalf("RegisterBuiltInTasks: %v", err)
	}
	task, err := s.GetTask("backup_hourly")
	if err != nil {
		t.Fatalf("GetTask(backup_hourly): %v", err)
	}
	if task.Enabled {
		t.Error("backup_hourly should be disabled by default")
	}
}

// TestTaskLogRotation_NilHook verifies taskLogRotation is a no-op when hook is nil.
func TestTaskLogRotation_NilHook(t *testing.T) {
	s := newTasksScheduler(t)
	s.LogRotateHook = nil
	if err := s.taskLogRotation(context.Background()); err != nil {
		t.Errorf("taskLogRotation(nil hook) returned error: %v", err)
	}
}

// TestTaskLogRotation_WithHook verifies taskLogRotation delegates to the hook.
func TestTaskLogRotation_WithHook(t *testing.T) {
	s := newTasksScheduler(t)
	called := false
	s.LogRotateHook = func(_ context.Context) error {
		called = true
		return nil
	}
	if err := s.taskLogRotation(context.Background()); err != nil {
		t.Errorf("taskLogRotation(hook) returned error: %v", err)
	}
	if !called {
		t.Error("LogRotateHook was not called")
	}
}

// TestTaskLogRotation_HookError verifies taskLogRotation propagates hook errors.
func TestTaskLogRotation_HookError(t *testing.T) {
	s := newTasksScheduler(t)
	s.LogRotateHook = func(_ context.Context) error { return errors.New("rotate error") }
	if err := s.taskLogRotation(context.Background()); err == nil {
		t.Error("expected error from LogRotateHook, got nil")
	}
}

// TestTaskHourlyBackup_NilHook verifies taskHourlyBackup is a no-op when hook is nil.
func TestTaskHourlyBackup_NilHook(t *testing.T) {
	s := newTasksScheduler(t)
	s.BackupHourlyHook = nil
	if err := s.taskHourlyBackup(context.Background()); err != nil {
		t.Errorf("taskHourlyBackup(nil hook) returned error: %v", err)
	}
}

// TestTaskHourlyBackup_WithHook verifies taskHourlyBackup delegates to the hook.
func TestTaskHourlyBackup_WithHook(t *testing.T) {
	s := newTasksScheduler(t)
	called := false
	s.BackupHourlyHook = func(_ context.Context) error {
		called = true
		return nil
	}
	if err := s.taskHourlyBackup(context.Background()); err != nil {
		t.Errorf("taskHourlyBackup(hook): %v", err)
	}
	if !called {
		t.Error("BackupHourlyHook was not called")
	}
}

// TestTaskDailyBackup_NilHook verifies taskDailyBackup is a no-op when hook is nil.
func TestTaskDailyBackup_NilHook(t *testing.T) {
	s := newTasksScheduler(t)
	s.BackupDailyHook = nil
	if err := s.taskDailyBackup(context.Background()); err != nil {
		t.Errorf("taskDailyBackup(nil hook) returned error: %v", err)
	}
}

// TestTaskDailyBackup_WithHook verifies taskDailyBackup delegates to the hook.
func TestTaskDailyBackup_WithHook(t *testing.T) {
	s := newTasksScheduler(t)
	called := false
	s.BackupDailyHook = func(_ context.Context) error {
		called = true
		return nil
	}
	if err := s.taskDailyBackup(context.Background()); err != nil {
		t.Errorf("taskDailyBackup(hook): %v", err)
	}
	if !called {
		t.Error("BackupDailyHook was not called")
	}
}

// TestTaskSSLRenewal_NilHook verifies taskSSLRenewal is a no-op when hook is nil.
func TestTaskSSLRenewal_NilHook(t *testing.T) {
	s := newTasksScheduler(t)
	s.SSLRenewHook = nil
	if err := s.taskSSLRenewal(context.Background()); err != nil {
		t.Errorf("taskSSLRenewal(nil hook) returned error: %v", err)
	}
}

// TestTaskSSLRenewal_WithHook verifies taskSSLRenewal delegates to the hook.
func TestTaskSSLRenewal_WithHook(t *testing.T) {
	s := newTasksScheduler(t)
	called := false
	s.SSLRenewHook = func(_ context.Context) error {
		called = true
		return nil
	}
	if err := s.taskSSLRenewal(context.Background()); err != nil {
		t.Errorf("taskSSLRenewal(hook): %v", err)
	}
	if !called {
		t.Error("SSLRenewHook was not called")
	}
}

// TestTaskGeoIPUpdate_NilHook verifies taskGeoIPUpdate is a no-op when hook is nil.
func TestTaskGeoIPUpdate_NilHook(t *testing.T) {
	s := newTasksScheduler(t)
	s.GeoIPUpdateHook = nil
	if err := s.taskGeoIPUpdate(context.Background()); err != nil {
		t.Errorf("taskGeoIPUpdate(nil hook) returned error: %v", err)
	}
}

// TestTaskGeoIPUpdate_WithHook verifies taskGeoIPUpdate delegates to the hook.
func TestTaskGeoIPUpdate_WithHook(t *testing.T) {
	s := newTasksScheduler(t)
	called := false
	s.GeoIPUpdateHook = func(_ context.Context) error {
		called = true
		return nil
	}
	if err := s.taskGeoIPUpdate(context.Background()); err != nil {
		t.Errorf("taskGeoIPUpdate(hook): %v", err)
	}
	if !called {
		t.Error("GeoIPUpdateHook was not called")
	}
}

// TestTaskBlocklistUpdate_NilHook verifies taskBlocklistUpdate is a no-op when hook is nil.
func TestTaskBlocklistUpdate_NilHook(t *testing.T) {
	s := newTasksScheduler(t)
	s.BlocklistUpdateHook = nil
	if err := s.taskBlocklistUpdate(context.Background()); err != nil {
		t.Errorf("taskBlocklistUpdate(nil hook) returned error: %v", err)
	}
}

// TestTaskBlocklistUpdate_WithHook verifies taskBlocklistUpdate delegates to the hook.
func TestTaskBlocklistUpdate_WithHook(t *testing.T) {
	s := newTasksScheduler(t)
	called := false
	s.BlocklistUpdateHook = func(_ context.Context) error {
		called = true
		return nil
	}
	if err := s.taskBlocklistUpdate(context.Background()); err != nil {
		t.Errorf("taskBlocklistUpdate(hook): %v", err)
	}
	if !called {
		t.Error("BlocklistUpdateHook was not called")
	}
}

// TestTaskCVEUpdate_NilHook verifies taskCVEUpdate is a no-op when hook is nil.
func TestTaskCVEUpdate_NilHook(t *testing.T) {
	s := newTasksScheduler(t)
	s.CVEUpdateHook = nil
	if err := s.taskCVEUpdate(context.Background()); err != nil {
		t.Errorf("taskCVEUpdate(nil hook) returned error: %v", err)
	}
}

// TestTaskCVEUpdate_WithHook verifies taskCVEUpdate delegates to the hook.
func TestTaskCVEUpdate_WithHook(t *testing.T) {
	s := newTasksScheduler(t)
	called := false
	s.CVEUpdateHook = func(_ context.Context) error {
		called = true
		return nil
	}
	if err := s.taskCVEUpdate(context.Background()); err != nil {
		t.Errorf("taskCVEUpdate(hook): %v", err)
	}
	if !called {
		t.Error("CVEUpdateHook was not called")
	}
}

// TestTaskTorHealth_NilHook verifies taskTorHealth is a no-op when hook is nil.
func TestTaskTorHealth_NilHook(t *testing.T) {
	s := newTasksScheduler(t)
	s.TorHealthHook = nil
	if err := s.taskTorHealth(context.Background()); err != nil {
		t.Errorf("taskTorHealth(nil hook) returned error: %v", err)
	}
}

// TestTaskTorHealth_WithHook verifies taskTorHealth delegates to the hook.
func TestTaskTorHealth_WithHook(t *testing.T) {
	s := newTasksScheduler(t)
	called := false
	s.TorHealthHook = func(_ context.Context) error {
		called = true
		return nil
	}
	if err := s.taskTorHealth(context.Background()); err != nil {
		t.Errorf("taskTorHealth(hook): %v", err)
	}
	if !called {
		t.Error("TorHealthHook was not called")
	}
}

// TestTaskHealthCheck_Passes verifies taskHealthCheck succeeds on a live DB.
func TestTaskHealthCheck_Passes(t *testing.T) {
	s := newTasksScheduler(t)
	if err := s.taskHealthCheck(context.Background()); err != nil {
		t.Errorf("taskHealthCheck returned error on live DB: %v", err)
	}
}

// TestTaskHealthCheck_ClosedDB verifies taskHealthCheck returns an error after DB is closed.
func TestTaskHealthCheck_ClosedDB(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS scheduler_tasks (
		id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', schedule TEXT NOT NULL DEFAULT '',
		last_run DATETIME, last_status TEXT NOT NULL DEFAULT '', last_error TEXT NOT NULL DEFAULT '',
		next_run DATETIME, run_count INTEGER NOT NULL DEFAULT 0,
		fail_count INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1
	)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	s, _ := New(db, "UTC", 5*time.Minute)
	db.Close()
	if err := s.taskHealthCheck(context.Background()); err == nil {
		t.Error("taskHealthCheck expected error on closed DB, got nil")
	}
}

// TestTaskTokenCleanup_NoTokens verifies taskTokenCleanup runs without error when
// there are no tokens to clean up.
func TestTaskTokenCleanup_NoTokens(t *testing.T) {
	s := newTasksScheduler(t)
	if err := s.taskTokenCleanup(context.Background()); err != nil {
		t.Errorf("taskTokenCleanup(no tokens): %v", err)
	}
}

// TestTaskTokenCleanup_RemovesRevoked verifies that revoked tokens older than 30 days
// are deleted while recently revoked tokens remain.
func TestTaskTokenCleanup_RemovesRevoked(t *testing.T) {
	s := newTasksScheduler(t)

	// Use a date well beyond 30 days (100 days ago) to ensure it is deleted.
	oldDate := time.Now().Add(-100 * 24 * time.Hour).UTC().Format("2006-01-02 15:04:05")
	_, err := s.db.Exec(
		`INSERT INTO api_tokens (id, token_hash, revoked_at) VALUES (?, ?, ?)`,
		"old_token", "hash1", oldDate,
	)
	if err != nil {
		t.Fatalf("insert old token: %v", err)
	}

	// Use NULL revoked_at for an active (non-revoked) token so it is never deleted.
	_, err = s.db.Exec(
		`INSERT INTO api_tokens (id, token_hash, revoked_at) VALUES (?, ?, NULL)`,
		"active_token", "hash2",
	)
	if err != nil {
		t.Fatalf("insert active token: %v", err)
	}

	if err := s.taskTokenCleanup(context.Background()); err != nil {
		t.Errorf("taskTokenCleanup: %v", err)
	}

	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM api_tokens").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 token remaining, got %d", count)
	}

	var id string
	s.db.QueryRow("SELECT id FROM api_tokens").Scan(&id)
	if id != "active_token" {
		t.Errorf("remaining token id = %q, want active_token", id)
	}
}

// TestTaskWhoisRecordsRefresh_NilHook verifies taskWhoisRecordsRefresh is a no-op
// when WhoisRefreshHook is nil (returns before calling records.RefreshStale).
func TestTaskWhoisRecordsRefresh_NilHook(t *testing.T) {
	s := newTasksScheduler(t)
	s.WhoisRefreshHook = nil
	if err := s.taskWhoisRecordsRefresh(context.Background()); err != nil {
		t.Errorf("taskWhoisRecordsRefresh(nil hook): %v", err)
	}
}

// TestTaskWhoisRecordsRefresh_WithHook_NoStaleRecords verifies taskWhoisRecordsRefresh
// returns nil when a hook is set but no stale records exist (empty table).
func TestTaskWhoisRecordsRefresh_WithHook_NoStaleRecords(t *testing.T) {
	s := newTasksScheduler(t)
	called := false
	s.WhoisRefreshHook = func(_ context.Context, _ []string) error {
		called = true
		return nil
	}
	if err := s.taskWhoisRecordsRefresh(context.Background()); err != nil {
		t.Errorf("taskWhoisRecordsRefresh(empty table): %v", err)
	}
	if called {
		t.Error("hook was called when no stale records exist")
	}
}

// TestTaskWhoisRecordsRefresh_WithHook_StaleRecords verifies taskWhoisRecordsRefresh
// calls the hook with stale query strings when records older than 30 days are present.
func TestTaskWhoisRecordsRefresh_WithHook_StaleRecords(t *testing.T) {
	s := newTasksScheduler(t)

	// Insert a record with last_updated set to 60 days ago (well beyond 30-day threshold).
	staleTS := time.Now().Add(-60 * 24 * time.Hour).Unix()
	_, err := s.db.Exec(
		`INSERT INTO whois_records (query, query_type, first_seen, last_seen, last_updated)
		 VALUES (?, ?, ?, ?, ?)`,
		"example.com", "domain", staleTS, staleTS, staleTS,
	)
	if err != nil {
		t.Fatalf("insert stale record: %v", err)
	}

	var gotQueries []string
	s.WhoisRefreshHook = func(_ context.Context, queries []string) error {
		gotQueries = queries
		return nil
	}
	if err := s.taskWhoisRecordsRefresh(context.Background()); err != nil {
		t.Errorf("taskWhoisRecordsRefresh(stale record): %v", err)
	}
	if len(gotQueries) != 1 || gotQueries[0] != "example.com" {
		t.Errorf("expected hook called with [example.com], got %v", gotQueries)
	}
}

// TestTaskWhoisRecordsRefresh_HookError verifies taskWhoisRecordsRefresh propagates
// an error returned by the WhoisRefreshHook.
func TestTaskWhoisRecordsRefresh_HookError(t *testing.T) {
	s := newTasksScheduler(t)

	// Insert a stale record so the hook is reached.
	staleTS := time.Now().Add(-60 * 24 * time.Hour).Unix()
	_, err := s.db.Exec(
		`INSERT INTO whois_records (query, query_type, first_seen, last_seen, last_updated)
		 VALUES (?, ?, ?, ?, ?)`,
		"stale.io", "domain", staleTS, staleTS, staleTS,
	)
	if err != nil {
		t.Fatalf("insert stale record: %v", err)
	}

	s.WhoisRefreshHook = func(_ context.Context, _ []string) error {
		return errors.New("refresh failed")
	}
	if err := s.taskWhoisRecordsRefresh(context.Background()); err == nil {
		t.Error("expected error from WhoisRefreshHook, got nil")
	}
}
