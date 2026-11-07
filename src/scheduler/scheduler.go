// Package scheduler provides the built-in task scheduler required by AI.md PART 18.
package scheduler

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"
)

// Scheduler manages persistent scheduled tasks using the built-in scheduler loop.
type Scheduler struct {
	db          *sql.DB
	tasks       map[string]*Task
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	timezone    *time.Location
	catchUpWind time.Duration
	started     bool
	stopping    bool
	running     sync.WaitGroup

	// Hooks let the server inject real implementations for built-in tasks.
	// When nil the task logs a no-op message and returns nil rather than failing.
	SSLRenewHook        func(context.Context) error
	BackupDailyHook     func(context.Context) error
	BackupHourlyHook    func(context.Context) error
	LogRotateHook       func(context.Context) error
	GeoIPUpdateHook     func(context.Context) error
	BlocklistUpdateHook func(context.Context) error
	CVEUpdateHook       func(context.Context) error
	// UpdateCheckHook checks the release channel for a newer version (AI.md PART 22).
	UpdateCheckHook func(context.Context) error
	// TokenCleanupHook removes expired API tokens and sessions from the DB (AI.md PART 18).
	TokenCleanupHook func(context.Context) error
	// HealthCheckSelfHook verifies server health and alerts if degraded (AI.md PART 18).
	HealthCheckSelfHook func(context.Context) error
	TorHealthHook       func(context.Context) error
	// WhoisRefreshHook re-queries the supplied stale queries and upserts fresh records.
	WhoisRefreshHook func(context.Context, []string) error
	// RDAPBootstrapHook fetches latest IANA RDAP bootstrap files.
	RDAPBootstrapHook func(context.Context) error
}

// Task represents a scheduled task
type Task struct {
	ID          string
	Name        string
	Schedule    string
	Handler     func(context.Context) error
	Enabled     bool
	LastRun     time.Time
	LastStatus  string
	LastError   string
	NextRun     time.Time
	RunCount    int64
	FailCount   int64
	RetryPolicy *RetryPolicy
}

// RetryPolicy defines retry behavior
type RetryPolicy struct {
	MaxRetries int
	RetryDelay time.Duration
	Backoff    string
}

// New creates a new scheduler instance using the built-in time-based loop.
// The scheduler uses the scheduler_tasks table created by the main DB schema (PART 10).
func New(db *sql.DB, timezone string, catchUpWindow time.Duration) (*Scheduler, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		log.Printf("WARN: Invalid timezone %s, using America/New_York", timezone)
		loc, _ = time.LoadLocation("America/New_York")
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Scheduler{
		db:          db,
		tasks:       make(map[string]*Task),
		ctx:         ctx,
		cancel:      cancel,
		timezone:    loc,
		catchUpWind: catchUpWindow,
	}

	return s, nil
}

// Register adds a task to the scheduler
// See AI.md PART 18 for built-in required tasks
func (s *Scheduler) Register(task *Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if task.ID == "" {
		return fmt.Errorf("task ID cannot be empty")
	}

	// Load existing state from database
	if err := s.loadTaskState(task); err != nil {
		log.Printf("WARN: Could not load task state for %s: %v", task.ID, err)
	}

	if task.Schedule == "" {
		task.Schedule = "@hourly"
	}
	next, err := nextScheduledTime(task.Schedule, time.Now(), s.timezone)
	if err != nil {
		log.Printf("WARN: Invalid schedule %q for task %s: %v; defaulting to hourly", task.Schedule, task.ID, err)
		task.Schedule = "@hourly"
		next, _ = nextScheduledTime(task.Schedule, time.Now(), s.timezone)
	}
	if task.NextRun.IsZero() {
		task.NextRun = next
	}

	s.tasks[task.ID] = task
	if err := s.saveTaskState(task); err != nil {
		log.Printf("WARN: Could not persist initial task state for %s: %v", task.ID, err)
	}
	return nil
}

// estimateNextRun computes the next run time from a schedule string.
func (s *Scheduler) estimateNextRun(schedule string) time.Time {
	next, err := nextScheduledTime(schedule, time.Now(), s.timezone)
	if err != nil {
		return time.Now().In(s.timezone).Add(time.Hour)
	}
	return next
}

// loadTaskState loads task state from the scheduler_tasks table (PART 10 schema).
func (s *Scheduler) loadTaskState(task *Task) error {
	query := `
	SELECT name, schedule, last_run, last_status, last_error,
	       next_run, run_count, fail_count, enabled
	FROM scheduler_tasks
	WHERE id = ?`

	row := s.db.QueryRow(query, task.ID)

	var lastRun, nextRun sql.NullTime
	err := row.Scan(
		&task.Name,
		&task.Schedule,
		&lastRun,
		&task.LastStatus,
		&task.LastError,
		&nextRun,
		&task.RunCount,
		&task.FailCount,
		&task.Enabled,
	)

	if err == sql.ErrNoRows {
		// Task not in database yet, insert initial state
		return s.saveTaskState(task)
	}

	if err != nil {
		return err
	}

	if lastRun.Valid {
		task.LastRun = lastRun.Time
	}
	if nextRun.Valid {
		task.NextRun = nextRun.Time
	}

	return nil
}

// saveTaskState persists task state to the scheduler_tasks table (PART 10 schema).
func (s *Scheduler) saveTaskState(task *Task) error {
	query := `
	INSERT OR REPLACE INTO scheduler_tasks
	(id, name, schedule, last_run, last_status, last_error,
	 next_run, run_count, fail_count, enabled)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query,
		task.ID,
		task.Name,
		task.Schedule,
		task.LastRun,
		task.LastStatus,
		task.LastError,
		task.NextRun,
		task.RunCount,
		task.FailCount,
		task.Enabled,
	)

	return err
}

// Start begins the scheduler loop
// Checks for missed tasks and starts continuous scheduling
// See AI.md PART 18: Startup Behavior
func (s *Scheduler) Start() error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	if s.stopping {
		s.mu.Unlock()
		return fmt.Errorf("scheduler has stopped")
	}
	s.started = true
	s.running.Add(1)
	s.mu.Unlock()

	// Check for missed tasks within catch-up window
	if err := s.catchUpMissedTasks(); err != nil {
		log.Printf("WARN: Error catching up missed tasks: %v", err)
	}
	go s.runLoop()

	log.Println("INFO: Scheduler started")
	return nil
}

// catchUpMissedTasks runs tasks that were missed during downtime
func (s *Scheduler) catchUpMissedTasks() error {
	now := time.Now().In(s.timezone)
	var due []*Task
	s.mu.Lock()
	for _, task := range s.tasks {
		if !task.Enabled || task.NextRun.IsZero() || task.NextRun.After(now) {
			continue
		}
		missedWithinWindow := now.Sub(task.NextRun) <= s.catchUpWind
		if missedWithinWindow {
			log.Printf("INFO: Catching up missed task: %s", task.Name)
		}
		if next, err := nextScheduledTime(task.Schedule, now, s.timezone); err == nil {
			task.NextRun = next
		}
		if err := s.saveTaskState(task); err != nil {
			log.Printf("WARN: Could not persist catch-up deadline for %s: %v", task.Name, err)
		}
		if missedWithinWindow {
			due = append(due, task)
		}
	}
	s.mu.Unlock()
	for _, task := range due {
		s.launchTask(task)
	}
	return nil
}

// executeTask executes a single task with state tracking, retry, and history
// logging. See AI.md PART 18: Task Execution Flow, Retry Policy.
func (s *Scheduler) executeTask(task *Task) {
	startTime := time.Now()
	log.Printf("INFO: Executing task: %s", task.Name)

	s.mu.RLock()
	policy := task.RetryPolicy
	s.mu.RUnlock()

	var err error
	attempt := 0
retryLoop:
	for {
		attemptStart := time.Now()
		historyID := s.recordHistoryStart(task.ID, attemptStart)
		err = runHandlerSafely(s.ctx, task.Handler)
		s.recordHistoryFinish(historyID, err, time.Since(attemptStart))

		if err == nil {
			break
		}

		if policy == nil || attempt >= policy.MaxRetries {
			break
		}

		delay := retryDelayForAttempt(policy, attempt)
		log.Printf("WARN: Task %s failed (attempt %d/%d): %v — retrying in %v",
			task.Name, attempt+1, policy.MaxRetries, err, delay)

		select {
		case <-s.ctx.Done():
			log.Printf("INFO: Task %s retry aborted: scheduler shutting down", task.Name)
			break retryLoop
		case <-time.After(delay):
		}
		attempt++
	}

	duration := time.Since(startTime)

	// Update task state
	s.mu.Lock()
	task.LastRun = startTime
	if err != nil {
		task.LastStatus = "failed"
		task.LastError = err.Error()
		task.FailCount++
		log.Printf("ERROR: Task %s failed after %v (%d attempt(s)): %v", task.Name, duration, attempt+1, err)
	} else {
		task.LastStatus = "success"
		task.LastError = ""
		task.RunCount++
		log.Printf("INFO: Task %s completed successfully in %v", task.Name, duration)
	}

	if task.NextRun.IsZero() || !task.NextRun.After(startTime) {
		task.NextRun = s.estimateNextRun(task.Schedule)
	}

	// Save state to database
	if err := s.saveTaskState(task); err != nil {
		log.Printf("ERROR: Failed to save task state for %s: %v", task.Name, err)
	}
	s.mu.Unlock()
}

// retryDelayForAttempt computes the delay before the next retry given the
// zero-based attempt number just completed (AI.md PART 18 Retry Policy).
func retryDelayForAttempt(policy *RetryPolicy, attempt int) time.Duration {
	base := policy.RetryDelay
	if base <= 0 {
		base = 5 * time.Minute
	}
	switch policy.Backoff {
	case "linear":
		return base * time.Duration(attempt+1)
	case "none", "constant":
		return base
	default:
		// exponential (default): 5m, 10m, 20m, ...
		return base * time.Duration(uint(1)<<uint(attempt))
	}
}

// recordHistoryStart inserts a "running" row into scheduler_history and
// returns its ID, or 0 if the insert failed (history logging is best-effort
// and never blocks task execution).
func (s *Scheduler) recordHistoryStart(taskID string, startedAt time.Time) int64 {
	res, err := s.db.Exec(
		`INSERT INTO scheduler_history (task_id, started_at, status) VALUES (?, ?, ?)`,
		taskID, startedAt.Unix(), "running",
	)
	if err != nil {
		log.Printf("WARN: Failed to record scheduler_history start for %s: %v", taskID, err)
		return 0
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0
	}
	return id
}

// recordHistoryFinish updates a scheduler_history row with the outcome of
// a completed task attempt.
func (s *Scheduler) recordHistoryFinish(historyID int64, taskErr error, duration time.Duration) {
	if historyID == 0 {
		return
	}
	status := "success"
	var errMsg sql.NullString
	if taskErr != nil {
		status = "failed"
		errMsg = sql.NullString{String: taskErr.Error(), Valid: true}
	}
	_, err := s.db.Exec(
		`UPDATE scheduler_history SET finished_at = ?, status = ?, error = ?, duration_ms = ? WHERE id = ?`,
		time.Now().Unix(), status, errMsg, duration.Milliseconds(), historyID,
	)
	if err != nil {
		log.Printf("WARN: Failed to record scheduler_history finish for id %d: %v", historyID, err)
	}
}

// HistoryEntry is one row from scheduler_history (a single task run attempt).
type HistoryEntry struct {
	ID         int64     `json:"id"`
	TaskID     string    `json:"task_id"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
	DurationMS int64     `json:"duration_ms,omitempty"`
}

// GetTaskHistory returns the most recent execution attempts for a task,
// newest first (AI.md PART 18 — "scheduler history <id>" CLI command).
func (s *Scheduler) GetTaskHistory(taskID string, limit int) ([]HistoryEntry, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := s.db.Query(
		`SELECT id, task_id, started_at, finished_at, status, error, duration_ms
		 FROM scheduler_history WHERE task_id = ? ORDER BY started_at DESC LIMIT ?`,
		taskID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("querying scheduler_history: %w", err)
	}
	defer rows.Close()

	var out []HistoryEntry
	for rows.Next() {
		var e HistoryEntry
		var started int64
		var finished sql.NullInt64
		var errMsg sql.NullString
		var durMS sql.NullInt64

		if err := rows.Scan(&e.ID, &e.TaskID, &started, &finished, &e.Status, &errMsg, &durMS); err != nil {
			return nil, fmt.Errorf("scanning scheduler_history row: %w", err)
		}

		e.StartedAt = time.Unix(started, 0)
		if finished.Valid {
			e.FinishedAt = time.Unix(finished.Int64, 0)
		}
		if errMsg.Valid {
			e.Error = errMsg.String
		}
		if durMS.Valid {
			e.DurationMS = durMS.Int64
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ApplyTaskOverrides applies operator-supplied per-task retry overrides
// (AI.md PART 18 — server.scheduler.tasks.<id>.retry_on_fail/retry_delay)
// to already-registered tasks. Tasks not present in overrides, or whose
// RetryOnFail is nil, keep their built-in RetryPolicy from tasks.go.
// defaultMaxRetries/defaultRetryDelay/defaultBackoff (server.scheduler.*)
// are used to build a new policy for a task that has no built-in one.
func (s *Scheduler) ApplyTaskOverrides(overrides map[string]TaskOverride, defaultMaxRetries int, defaultRetryDelay time.Duration, defaultBackoff string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, ov := range overrides {
		task, ok := s.tasks[id]
		if !ok || ov.RetryOnFail == nil {
			continue
		}

		if !*ov.RetryOnFail {
			task.RetryPolicy = nil
			continue
		}

		policy := &RetryPolicy{
			MaxRetries: defaultMaxRetries,
			RetryDelay: defaultRetryDelay,
			Backoff:    defaultBackoff,
		}
		if task.RetryPolicy != nil {
			policy.MaxRetries = task.RetryPolicy.MaxRetries
			policy.RetryDelay = task.RetryPolicy.RetryDelay
			policy.Backoff = task.RetryPolicy.Backoff
		}
		if ov.RetryDelay > 0 {
			policy.RetryDelay = ov.RetryDelay
		}
		if ov.MaxRetries > 0 {
			policy.MaxRetries = ov.MaxRetries
		}
		if ov.Backoff != "" {
			policy.Backoff = ov.Backoff
		}
		task.RetryPolicy = policy
	}
}

// TaskOverride carries per-task retry overrides parsed from server.yml
// (AI.md PART 18 — server.scheduler.tasks.<id>.*).
type TaskOverride struct {
	// RetryOnFail is nil when the operator did not set retry_on_fail for this
	// task (keep the built-in default), true to force retries, false to
	// disable retries for this task.
	RetryOnFail *bool
	RetryDelay  time.Duration
	MaxRetries  int
	Backoff     string
}

// Stop gracefully stops the scheduler
// Waits for running tasks to complete (max 30 seconds)
// See AI.md PART 18: Shutdown Behavior
func (s *Scheduler) Stop() error {
	log.Println("INFO: Stopping scheduler...")

	s.cancel()
	done := make(chan struct{})
	go func() {
		s.running.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		log.Printf("WARN: Scheduler shutdown timed out with tasks still running")
	}

	log.Println("INFO: Scheduler stopped")
	return nil
}

// GetTasks returns all registered tasks
func (s *Scheduler) GetTasks() []*Task {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tasks := make([]*Task, 0, len(s.tasks))
	for _, task := range s.tasks {
		tasks = append(tasks, task)
	}
	return tasks
}

// GetTask returns a specific task by ID
func (s *Scheduler) GetTask(id string) (*Task, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	task, ok := s.tasks[id]
	if !ok {
		return nil, fmt.Errorf("task not found: %s", id)
	}
	return task, nil
}

// RunTaskNow triggers immediate execution of a task
func (s *Scheduler) RunTaskNow(id string) error {
	task, err := s.GetTask(id)
	if err != nil {
		return err
	}

	s.launchTask(task)
	return nil
}

// checkTasks runs due tasks and advances their deadlines before dispatch so
// slow handlers cannot trigger duplicate runs on subsequent scheduler ticks.
func (s *Scheduler) checkTasks() {
	now := time.Now().In(s.timezone)
	var due []*Task
	s.mu.Lock()
	for _, task := range s.tasks {
		if !task.Enabled || task.NextRun.IsZero() || task.NextRun.After(now) {
			continue
		}
		if next, err := nextScheduledTime(task.Schedule, now, s.timezone); err == nil {
			task.NextRun = next
		}
		due = append(due, task)
		if err := s.saveTaskState(task); err != nil {
			log.Printf("ERROR: Failed to save task deadline for %s: %v", task.Name, err)
		}
	}
	s.mu.Unlock()
	for _, task := range due {
		s.launchTask(task)
	}
}

func (s *Scheduler) launchTask(task *Task) {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return
	}
	tracked := s.started
	if tracked {
		s.running.Add(1)
	}
	s.mu.Unlock()
	go func() {
		if tracked {
			defer s.running.Done()
		}
		s.executeTask(task)
	}()
}

func (s *Scheduler) runLoop() {
	defer s.running.Done()
	for {
		s.checkTasks()
		delay := s.nextDelay()
		timer := time.NewTimer(delay)
		select {
		case <-s.ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (s *Scheduler) nextDelay() time.Duration {
	now := time.Now().In(s.timezone)
	delay := time.Minute
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, task := range s.tasks {
		if !task.Enabled || task.NextRun.IsZero() {
			continue
		}
		if remaining := task.NextRun.Sub(now); remaining < delay {
			delay = remaining
		}
	}
	if delay < time.Second {
		return time.Second
	}
	return delay
}

func runHandlerSafely(ctx context.Context, handler func(context.Context) error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("task panic: %v", recovered)
		}
	}()
	return handler(ctx)
}

// GetTimezone returns the scheduler's configured timezone
func (s *Scheduler) GetTimezone() string {
	return s.timezone.String()
}

// GetCatchUpWindow returns the catch-up window duration
func (s *Scheduler) GetCatchUpWindow() time.Duration {
	return s.catchUpWind
}

// IsRunning returns whether the scheduler is actively running
func (s *Scheduler) IsRunning() bool {
	select {
	case <-s.ctx.Done():
		return false
	default:
		return true
	}
}

// EnableTask enables a task by ID
func (s *Scheduler) EnableTask(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	task, ok := s.tasks[id]
	if !ok {
		return fmt.Errorf("task not found: %s", id)
	}

	task.Enabled = true

	// Persist enabled state to scheduler_tasks
	_, err := s.db.Exec(
		"UPDATE scheduler_tasks SET enabled = 1 WHERE id = ?",
		id,
	)
	return err
}

// DisableTask disables a task by ID
func (s *Scheduler) DisableTask(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	task, ok := s.tasks[id]
	if !ok {
		return fmt.Errorf("task not found: %s", id)
	}

	task.Enabled = false

	// Persist disabled state to scheduler_tasks
	_, err := s.db.Exec(
		"UPDATE scheduler_tasks SET enabled = 0 WHERE id = ?",
		id,
	)
	return err
}

// TaskStatus holds the current status snapshot of a single task.
type TaskStatus struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Schedule   string    `json:"schedule"`
	Enabled    bool      `json:"enabled"`
	LastRun    time.Time `json:"last_run"`
	LastStatus string    `json:"last_status"`
	LastError  string    `json:"last_error,omitempty"`
	NextRun    time.Time `json:"next_run"`
	RunCount   int64     `json:"run_count"`
	FailCount  int64     `json:"fail_count"`
}

// Status returns a snapshot of all registered task statuses.
func (s *Scheduler) Status() []TaskStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]TaskStatus, 0, len(s.tasks))
	for _, t := range s.tasks {
		out = append(out, TaskStatus{
			ID:         t.ID,
			Name:       t.Name,
			Schedule:   t.Schedule,
			Enabled:    t.Enabled,
			LastRun:    t.LastRun,
			LastStatus: t.LastStatus,
			LastError:  t.LastError,
			NextRun:    t.NextRun,
			RunCount:   t.RunCount,
			FailCount:  t.FailCount,
		})
	}
	return out
}
