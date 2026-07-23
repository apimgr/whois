// Package scheduler tests cover Scheduler creation, task registration,
// state persistence, enable/disable, start/stop lifecycle, and status reporting.
package scheduler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// openTestDB opens an in-memory SQLite database and creates the scheduler_tasks
// table required by scheduler.go (mirrors the schema in PART 10).
func openTestDB(t *testing.T) *sql.DB {
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
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS scheduler_history (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id     TEXT NOT NULL,
		started_at  INTEGER NOT NULL,
		finished_at INTEGER,
		status      TEXT NOT NULL,
		error       TEXT,
		duration_ms INTEGER
	)`)
	if err != nil {
		t.Fatalf("create scheduler_history: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestScheduler creates a Scheduler backed by an in-memory SQLite DB.
func newTestScheduler(t *testing.T) *Scheduler {
	t.Helper()
	db := openTestDB(t)
	s, err := New(db, "UTC", 10*time.Minute)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// nopHandler is a task handler that always succeeds immediately.
func nopHandler(_ context.Context) error { return nil }

// errHandler is a task handler that always returns an error.
func errHandler(_ context.Context) error { return errors.New("task error") }

// TestNew_ValidTimezone verifies that New succeeds with a valid timezone string.
func TestNew_ValidTimezone(t *testing.T) {
	db := openTestDB(t)
	s, err := New(db, "America/New_York", 5*time.Minute)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if s == nil {
		t.Fatal("New returned nil scheduler")
	}
	if s.GetTimezone() != "America/New_York" {
		t.Errorf("GetTimezone() = %q, want America/New_York", s.GetTimezone())
	}
}

// TestNew_InvalidTimezone verifies that New falls back to America/New_York when
// given an invalid timezone string (should not return an error).
func TestNew_InvalidTimezone(t *testing.T) {
	db := openTestDB(t)
	s, err := New(db, "Not/A/Timezone", 5*time.Minute)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if s == nil {
		t.Fatal("New returned nil scheduler")
	}
}

// TestGetCatchUpWindow verifies the catch-up window is preserved from New.
func TestGetCatchUpWindow(t *testing.T) {
	s := newTestScheduler(t)
	want := 10 * time.Minute
	if got := s.GetCatchUpWindow(); got != want {
		t.Errorf("GetCatchUpWindow() = %v, want %v", got, want)
	}
}

// TestRegister_EmptyID verifies that Register returns an error for an empty task ID.
func TestRegister_EmptyID(t *testing.T) {
	s := newTestScheduler(t)
	err := s.Register(&Task{ID: "", Name: "Bad Task", Schedule: "* * * * *", Handler: nopHandler})
	if err == nil {
		t.Fatal("Register(empty ID) expected error, got nil")
	}
}

// TestRegister_Success verifies that a task is stored and retrievable after Register.
func TestRegister_Success(t *testing.T) {
	s := newTestScheduler(t)
	task := &Task{
		ID:       "test_task",
		Name:     "Test Task",
		Schedule: "*/5 * * * *",
		Enabled:  true,
		Handler:  nopHandler,
	}
	if err := s.Register(task); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := s.GetTask("test_task")
	if err != nil {
		t.Fatalf("GetTask: %v", err)
	}
	if got.ID != "test_task" {
		t.Errorf("GetTask().ID = %q, want %q", got.ID, "test_task")
	}
}

// TestRegister_PersistsToDBOnNew verifies that a task not yet in the DB gets
// inserted by loadTaskState (which calls saveTaskState for a missing row).
func TestRegister_PersistsToDBOnNew(t *testing.T) {
	db := openTestDB(t)
	s, _ := New(db, "UTC", 5*time.Minute)
	task := &Task{
		ID:       "persist_task",
		Name:     "Persist Task",
		Schedule: "@hourly",
		Enabled:  true,
		Handler:  nopHandler,
	}
	if err := s.Register(task); err != nil {
		t.Fatalf("Register: %v", err)
	}

	var id string
	err := db.QueryRow("SELECT id FROM scheduler_tasks WHERE id = ?", "persist_task").Scan(&id)
	if err != nil {
		t.Errorf("task not persisted to DB: %v", err)
	}
}

// TestRegister_LoadsExistingState verifies that Register reads run_count and
// last_status from a pre-existing scheduler_tasks row.
func TestRegister_LoadsExistingState(t *testing.T) {
	db := openTestDB(t)
	_, err := db.Exec(`INSERT INTO scheduler_tasks
		(id, name, schedule, last_run, last_status, last_error, next_run, run_count, fail_count, enabled)
		VALUES (?, ?, ?, NULL, ?, '', NULL, ?, ?, 1)`,
		"pre_existing", "Pre Existing", "0 0 * * *", "success", int64(42), int64(3))
	if err != nil {
		t.Fatalf("pre-insert: %v", err)
	}

	s, _ := New(db, "UTC", 5*time.Minute)
	task := &Task{
		ID:       "pre_existing",
		Name:     "Pre Existing",
		Schedule: "0 0 * * *",
		Enabled:  true,
		Handler:  nopHandler,
	}
	if err := s.Register(task); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if task.RunCount != 42 {
		t.Errorf("task.RunCount = %d, want 42", task.RunCount)
	}
	if task.LastStatus != "success" {
		t.Errorf("task.LastStatus = %q, want success", task.LastStatus)
	}
	if task.FailCount != 3 {
		t.Errorf("task.FailCount = %d, want 3", task.FailCount)
	}
}

// TestGetTask_NotFound verifies GetTask returns an error for an unknown ID.
func TestGetTask_NotFound(t *testing.T) {
	s := newTestScheduler(t)
	_, err := s.GetTask("nonexistent")
	if err == nil {
		t.Fatal("GetTask(unknown) expected error, got nil")
	}
}

// TestGetTasks_Empty verifies GetTasks returns empty slice when no tasks registered.
func TestGetTasks_Empty(t *testing.T) {
	s := newTestScheduler(t)
	tasks := s.GetTasks()
	if len(tasks) != 0 {
		t.Errorf("GetTasks() len = %d, want 0", len(tasks))
	}
}

// TestGetTasks_Multiple verifies GetTasks returns all registered tasks.
func TestGetTasks_Multiple(t *testing.T) {
	s := newTestScheduler(t)
	for i := range 3 {
		task := &Task{
			ID:       fmt.Sprintf("task_%d", i),
			Name:     fmt.Sprintf("Task %d", i),
			Schedule: "* * * * *",
			Enabled:  true,
			Handler:  nopHandler,
		}
		if err := s.Register(task); err != nil {
			t.Fatalf("Register task_%d: %v", i, err)
		}
	}
	tasks := s.GetTasks()
	if len(tasks) != 3 {
		t.Errorf("GetTasks() len = %d, want 3", len(tasks))
	}
}

// TestStatus_Empty verifies Status returns an empty slice when no tasks are registered.
func TestStatus_Empty(t *testing.T) {
	s := newTestScheduler(t)
	out := s.Status()
	if len(out) != 0 {
		t.Errorf("Status() len = %d, want 0", len(out))
	}
}

// TestStatus_Fields verifies Status snapshot contains correct field values.
func TestStatus_Fields(t *testing.T) {
	s := newTestScheduler(t)
	task := &Task{
		ID:         "status_task",
		Name:       "Status Task",
		Schedule:   "0 9 * * *",
		Enabled:    true,
		LastStatus: "success",
		RunCount:   7,
		FailCount:  1,
		Handler:    nopHandler,
	}
	if err := s.Register(task); err != nil {
		t.Fatalf("Register: %v", err)
	}
	statuses := s.Status()
	if len(statuses) != 1 {
		t.Fatalf("Status() len = %d, want 1", len(statuses))
	}
	st := statuses[0]
	if st.ID != "status_task" {
		t.Errorf("Status.ID = %q, want status_task", st.ID)
	}
	if st.Name != "Status Task" {
		t.Errorf("Status.Name = %q, want Status Task", st.Name)
	}
	if !st.Enabled {
		t.Error("Status.Enabled = false, want true")
	}
}

// TestIsRunning_BeforeStart verifies IsRunning returns true after New (context not cancelled).
func TestIsRunning_BeforeStart(t *testing.T) {
	s := newTestScheduler(t)
	if !s.IsRunning() {
		t.Error("IsRunning() = false, want true before Stop")
	}
}

// TestIsRunning_AfterStop verifies IsRunning returns false after Stop cancels the context.
func TestIsRunning_AfterStop(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if s.IsRunning() {
		t.Error("IsRunning() = true, want false after Stop")
	}
}

// TestStart_ThenStop verifies Start returns nil and the scheduler can be stopped.
func TestStart_ThenStop(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if s.IsRunning() {
		t.Error("IsRunning() = true after Stop")
	}
}

// TestStart_WithEnabledDisabledTasks exercises catchUpMissedTasks with both
// enabled and disabled tasks, and one with an overdue NextRun.
func TestStart_WithEnabledDisabledTasks(t *testing.T) {
	s := newTestScheduler(t)

	enabled := &Task{
		ID:       "enabled_overdue",
		Name:     "Enabled Overdue",
		Schedule: "* * * * *",
		Enabled:  true,
		NextRun:  time.Now().Add(-30 * time.Second),
		Handler:  nopHandler,
	}
	disabled := &Task{
		ID:       "disabled_task",
		Name:     "Disabled Task",
		Schedule: "* * * * *",
		Enabled:  false,
		NextRun:  time.Now().Add(-30 * time.Second),
		Handler:  nopHandler,
	}

	if err := s.Register(enabled); err != nil {
		t.Fatalf("Register enabled: %v", err)
	}
	if err := s.Register(disabled); err != nil {
		t.Fatalf("Register disabled: %v", err)
	}

	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()
}

// TestRunTaskNow_Success verifies RunTaskNow triggers execution for a valid task ID.
func TestRunTaskNow_Success(t *testing.T) {
	s := newTestScheduler(t)
	done := make(chan struct{}, 1)
	task := &Task{
		ID:       "run_now_task",
		Name:     "Run Now Task",
		Schedule: "0 0 1 1 *",
		Enabled:  true,
		Handler: func(_ context.Context) error {
			done <- struct{}{}
			return nil
		},
	}
	if err := s.Register(task); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := s.RunTaskNow("run_now_task"); err != nil {
		t.Fatalf("RunTaskNow: %v", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("RunTaskNow: handler did not execute within 3 seconds")
	}
}

// TestRunTaskNow_NotFound verifies RunTaskNow returns an error for an unknown task ID.
func TestRunTaskNow_NotFound(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.RunTaskNow("does_not_exist"); err == nil {
		t.Fatal("RunTaskNow(unknown) expected error, got nil")
	}
}

// TestEnableTask_Success verifies EnableTask sets Enabled=true and persists it.
func TestEnableTask_Success(t *testing.T) {
	db := openTestDB(t)
	s, _ := New(db, "UTC", 5*time.Minute)
	task := &Task{
		ID:       "toggle_task",
		Name:     "Toggle Task",
		Schedule: "* * * * *",
		Enabled:  false,
		Handler:  nopHandler,
	}
	if err := s.Register(task); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := s.EnableTask("toggle_task"); err != nil {
		t.Fatalf("EnableTask: %v", err)
	}
	got, _ := s.GetTask("toggle_task")
	if !got.Enabled {
		t.Error("task.Enabled = false after EnableTask")
	}

	var enabled int
	db.QueryRow("SELECT enabled FROM scheduler_tasks WHERE id = ?", "toggle_task").Scan(&enabled)
	if enabled != 1 {
		t.Errorf("DB enabled = %d, want 1", enabled)
	}
}

// TestEnableTask_NotFound verifies EnableTask returns an error for an unknown task ID.
func TestEnableTask_NotFound(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.EnableTask("no_such_task"); err == nil {
		t.Fatal("EnableTask(unknown) expected error, got nil")
	}
}

// TestDisableTask_Success verifies DisableTask sets Enabled=false and persists it.
func TestDisableTask_Success(t *testing.T) {
	db := openTestDB(t)
	s, _ := New(db, "UTC", 5*time.Minute)
	task := &Task{
		ID:       "disable_task",
		Name:     "Disable Task",
		Schedule: "* * * * *",
		Enabled:  true,
		Handler:  nopHandler,
	}
	if err := s.Register(task); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := s.DisableTask("disable_task"); err != nil {
		t.Fatalf("DisableTask: %v", err)
	}
	got, _ := s.GetTask("disable_task")
	if got.Enabled {
		t.Error("task.Enabled = true after DisableTask")
	}

	var enabled int
	db.QueryRow("SELECT enabled FROM scheduler_tasks WHERE id = ?", "disable_task").Scan(&enabled)
	if enabled != 0 {
		t.Errorf("DB enabled = %d, want 0", enabled)
	}
}

// TestDisableTask_NotFound verifies DisableTask returns an error for an unknown task ID.
func TestDisableTask_NotFound(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.DisableTask("no_such_task"); err == nil {
		t.Fatal("DisableTask(unknown) expected error, got nil")
	}
}

// TestExecuteTask_Success verifies that a successful handler sets LastStatus to "success"
// and increments RunCount.
func TestExecuteTask_Success(t *testing.T) {
	s := newTestScheduler(t)
	task := &Task{
		ID:       "exec_success",
		Name:     "Exec Success",
		Schedule: "* * * * *",
		Enabled:  true,
		Handler:  nopHandler,
	}
	if err := s.Register(task); err != nil {
		t.Fatalf("Register: %v", err)
	}

	s.executeTask(task)

	if task.LastStatus != "success" {
		t.Errorf("LastStatus = %q, want success", task.LastStatus)
	}
	if task.RunCount != 1 {
		t.Errorf("RunCount = %d, want 1", task.RunCount)
	}
	if task.FailCount != 0 {
		t.Errorf("FailCount = %d, want 0", task.FailCount)
	}
	if task.LastError != "" {
		t.Errorf("LastError = %q, want empty", task.LastError)
	}
}

// TestExecuteTask_Failure verifies that a failing handler sets LastStatus to "failed"
// and increments FailCount.
func TestExecuteTask_Failure(t *testing.T) {
	s := newTestScheduler(t)
	task := &Task{
		ID:       "exec_fail",
		Name:     "Exec Fail",
		Schedule: "* * * * *",
		Enabled:  true,
		Handler:  errHandler,
	}
	if err := s.Register(task); err != nil {
		t.Fatalf("Register: %v", err)
	}

	s.executeTask(task)

	if task.LastStatus != "failed" {
		t.Errorf("LastStatus = %q, want failed", task.LastStatus)
	}
	if task.FailCount != 1 {
		t.Errorf("FailCount = %d, want 1", task.FailCount)
	}
	if task.LastError != "task error" {
		t.Errorf("LastError = %q, want task error", task.LastError)
	}
}

// TestExecuteTask_SetsNextRun verifies that executeTask updates NextRun after completion.
func TestExecuteTask_SetsNextRun(t *testing.T) {
	s := newTestScheduler(t)
	before := time.Now()
	task := &Task{
		ID:       "next_run_task",
		Name:     "Next Run Task",
		Schedule: "*/5 * * * *",
		Enabled:  true,
		Handler:  nopHandler,
	}
	if err := s.Register(task); err != nil {
		t.Fatalf("Register: %v", err)
	}

	s.executeTask(task)

	if !task.NextRun.After(before) {
		t.Errorf("NextRun = %v, expected after %v", task.NextRun, before)
	}
}

// TestSaveTaskState_RoundTrip verifies saveTaskState then loadTaskState restores fields.
func TestSaveTaskState_RoundTrip(t *testing.T) {
	s := newTestScheduler(t)
	now := time.Now().Truncate(time.Second)
	task := &Task{
		ID:         "roundtrip_task",
		Name:       "Round Trip",
		Schedule:   "0 0 * * *",
		LastRun:    now,
		LastStatus: "success",
		LastError:  "",
		NextRun:    now.Add(24 * time.Hour),
		RunCount:   10,
		FailCount:  2,
		Enabled:    true,
	}

	if err := s.saveTaskState(task); err != nil {
		t.Fatalf("saveTaskState: %v", err)
	}

	loaded := &Task{ID: "roundtrip_task"}
	if err := s.loadTaskState(loaded); err != nil {
		t.Fatalf("loadTaskState: %v", err)
	}

	if loaded.RunCount != 10 {
		t.Errorf("RunCount = %d, want 10", loaded.RunCount)
	}
	if loaded.FailCount != 2 {
		t.Errorf("FailCount = %d, want 2", loaded.FailCount)
	}
	if loaded.LastStatus != "success" {
		t.Errorf("LastStatus = %q, want success", loaded.LastStatus)
	}
}

// TestCatchUpMissedTasks_SkipsDisabled verifies that disabled tasks are not caught up.
func TestCatchUpMissedTasks_SkipsDisabled(t *testing.T) {
	s := newTestScheduler(t)
	called := false
	task := &Task{
		ID:       "skip_disabled",
		Name:     "Skip Disabled",
		Schedule: "* * * * *",
		Enabled:  false,
		NextRun:  time.Now().Add(-5 * time.Minute),
		Handler: func(_ context.Context) error {
			called = true
			return nil
		},
	}
	s.tasks["skip_disabled"] = task

	if err := s.catchUpMissedTasks(); err != nil {
		t.Fatalf("catchUpMissedTasks: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	if called {
		t.Error("disabled task handler was called during catch-up")
	}
}

// TestCatchUpMissedTasks_SkipsOutsideWindow verifies that tasks overdue by more
// than the catch-up window are not executed.
func TestCatchUpMissedTasks_SkipsOutsideWindow(t *testing.T) {
	db := openTestDB(t)
	s, _ := New(db, "UTC", 1*time.Minute)
	called := false
	task := &Task{
		ID:       "too_old",
		Name:     "Too Old",
		Schedule: "* * * * *",
		Enabled:  true,
		NextRun:  time.Now().Add(-2 * time.Minute),
		Handler: func(_ context.Context) error {
			called = true
			return nil
		},
	}
	s.tasks["too_old"] = task

	if err := s.catchUpMissedTasks(); err != nil {
		t.Fatalf("catchUpMissedTasks: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	if called {
		t.Error("task outside catch-up window should not have been executed")
	}
}

// TestCatchUpMissedTasks_SkipsZeroNextRun verifies tasks with zero NextRun are skipped.
func TestCatchUpMissedTasks_SkipsZeroNextRun(t *testing.T) {
	s := newTestScheduler(t)
	called := false
	task := &Task{
		ID:       "zero_nextrun",
		Name:     "Zero NextRun",
		Schedule: "* * * * *",
		Enabled:  true,
		Handler: func(_ context.Context) error {
			called = true
			return nil
		},
	}
	s.tasks["zero_nextrun"] = task

	if err := s.catchUpMissedTasks(); err != nil {
		t.Fatalf("catchUpMissedTasks: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	if called {
		t.Error("task with zero NextRun should not have been executed")
	}
}

// TestCheckTasks_OverdueTask verifies checkTasks triggers execution for an overdue task.
func TestCheckTasks_OverdueTask(t *testing.T) {
	s := newTestScheduler(t)
	done := make(chan struct{}, 1)
	task := &Task{
		ID:       "check_overdue",
		Name:     "Check Overdue",
		Schedule: "* * * * *",
		Enabled:  true,
		NextRun:  time.Now().Add(-5 * time.Second),
		Handler: func(_ context.Context) error {
			done <- struct{}{}
			return nil
		},
	}
	if err := s.Register(task); err != nil {
		t.Fatalf("Register: %v", err)
	}

	s.checkTasks()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("checkTasks: handler did not execute within 3 seconds")
	}
}

// TestCheckTasks_DisabledTask verifies checkTasks skips disabled tasks.
func TestCheckTasks_DisabledTask(t *testing.T) {
	s := newTestScheduler(t)
	called := false
	task := &Task{
		ID:       "check_disabled",
		Name:     "Check Disabled",
		Schedule: "* * * * *",
		Enabled:  false,
		NextRun:  time.Now().Add(-5 * time.Second),
		Handler: func(_ context.Context) error {
			called = true
			return nil
		},
	}
	if err := s.Register(task); err != nil {
		t.Fatalf("Register: %v", err)
	}

	s.checkTasks()
	time.Sleep(100 * time.Millisecond)

	if called {
		t.Error("disabled task should not be executed by checkTasks")
	}
}

// TestCheckTasks_ZeroNextRun verifies checkTasks skips tasks with zero NextRun.
func TestCheckTasks_ZeroNextRun(t *testing.T) {
	s := newTestScheduler(t)
	called := false
	task := &Task{
		ID:       "check_zero",
		Name:     "Check Zero",
		Schedule: "* * * * *",
		Enabled:  true,
		Handler: func(_ context.Context) error {
			called = true
			return nil
		},
	}
	if err := s.Register(task); err != nil {
		t.Fatalf("Register: %v", err)
	}

	s.checkTasks()
	time.Sleep(100 * time.Millisecond)

	if called {
		t.Error("task with zero NextRun should not be executed by checkTasks")
	}
}

// TestRetryPolicy_Fields verifies RetryPolicy struct fields are accessible.
func TestRetryPolicy_Fields(t *testing.T) {
	rp := RetryPolicy{
		MaxRetries: 3,
		RetryDelay: 5 * time.Minute,
		Backoff:    "exponential",
	}
	if rp.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", rp.MaxRetries)
	}
	if rp.RetryDelay != 5*time.Minute {
		t.Errorf("RetryDelay = %v, want 5m", rp.RetryDelay)
	}
	if rp.Backoff != "exponential" {
		t.Errorf("Backoff = %q, want exponential", rp.Backoff)
	}
}

// TestStatus_RunCount verifies Status reflects updated RunCount after execution.
func TestStatus_RunCount(t *testing.T) {
	s := newTestScheduler(t)
	task := &Task{
		ID:       "run_count_task",
		Name:     "Run Count Task",
		Schedule: "* * * * *",
		Enabled:  true,
		Handler:  nopHandler,
	}
	if err := s.Register(task); err != nil {
		t.Fatalf("Register: %v", err)
	}

	s.executeTask(task)
	s.executeTask(task)

	statuses := s.Status()
	if len(statuses) != 1 {
		t.Fatalf("Status() len = %d, want 1", len(statuses))
	}
	if statuses[0].RunCount != 2 {
		t.Errorf("Status.RunCount = %d, want 2", statuses[0].RunCount)
	}
}

// TestStop_Idempotent verifies Stop can be called without having called Start first.
func TestStop_Idempotent(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.Stop(); err != nil {
		t.Errorf("Stop (without Start) returned error: %v", err)
	}
}
