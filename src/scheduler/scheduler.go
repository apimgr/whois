// Package scheduler provides built-in task scheduling using gocron/v2
// See AI.md PART 18: SCHEDULER
package scheduler

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/go-co-op/gocron/v2"
)

// Scheduler manages scheduled tasks using gocron/v2 (AI.md PART 18).
type Scheduler struct {
	db          *sql.DB
	gocron      gocron.Scheduler
	tasks       map[string]*Task
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	timezone    *time.Location
	catchUpWind time.Duration

	// Hooks let the server inject real implementations for built-in tasks.
	// When nil the task logs a no-op message and returns nil rather than failing.
	SSLRenewHook        func(context.Context) error
	BackupDailyHook     func(context.Context) error
	BackupHourlyHook    func(context.Context) error
	LogRotateHook       func(context.Context) error
	GeoIPUpdateHook     func(context.Context) error
	BlocklistUpdateHook func(context.Context) error
	CVEUpdateHook       func(context.Context) error
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

	// gocronJob holds the gocron job reference for this task
	gocronJob gocron.Job
}

// RetryPolicy defines retry behavior
type RetryPolicy struct {
	MaxRetries int
	RetryDelay time.Duration
	Backoff    string
}

// New creates a new scheduler instance using gocron/v2.
// The scheduler uses the scheduler_tasks table created by the main DB schema (PART 10).
func New(db *sql.DB, timezone string, catchUpWindow time.Duration) (*Scheduler, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		log.Printf("WARN: Invalid timezone %s, using America/New_York", timezone)
		loc, _ = time.LoadLocation("America/New_York")
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create gocron scheduler with timezone
	gs, err := gocron.NewScheduler(gocron.WithLocation(loc))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("creating gocron scheduler: %w", err)
	}

	s := &Scheduler{
		db:          db,
		gocron:      gs,
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

	// Create gocron job definition based on schedule
	var jobDef gocron.JobDefinition
	var err error

	if task.Schedule != "" {
		jobDef, err = parseScheduleToJobDef(task.Schedule)
		if err != nil {
			log.Printf("WARN: Invalid schedule %q for task %s: %v", task.Schedule, task.ID, err)
			// Default to hourly if schedule is invalid
			jobDef = gocron.DurationJob(time.Hour)
		}
	} else {
		// Default to hourly if no schedule
		jobDef = gocron.DurationJob(time.Hour)
	}

	// Create the gocron job
	wrappedHandler := s.wrapHandler(task)
	job, err := s.gocron.NewJob(
		jobDef,
		gocron.NewTask(wrappedHandler),
		gocron.WithName(task.ID),
	)
	if err != nil {
		return fmt.Errorf("creating gocron job for %s: %w", task.ID, err)
	}

	task.gocronJob = job

	// Calculate initial NextRun
	if task.NextRun.IsZero() {
		nextRuns, _ := job.NextRuns(1)
		if len(nextRuns) > 0 {
			task.NextRun = nextRuns[0]
		}
	}

	s.tasks[task.ID] = task
	return nil
}

// parseScheduleToJobDef converts a cron schedule string to a gocron JobDefinition
func parseScheduleToJobDef(schedule string) (gocron.JobDefinition, error) {
	// Handle @every <duration>
	if len(schedule) > 7 && schedule[:7] == "@every " {
		durStr := schedule[7:]
		d, err := time.ParseDuration(durStr)
		if err != nil {
			return nil, fmt.Errorf("invalid @every duration %q: %w", durStr, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("@every duration must be positive, got %v", d)
		}
		return gocron.DurationJob(d), nil
	}

	// Use gocron's cron parser for standard cron expressions and @ shortcuts
	return gocron.CronJob(schedule, false), nil
}

// estimateNextRun computes the next run time from a schedule string.
// Used as fallback when gocronJob.NextRuns is unavailable.
func (s *Scheduler) estimateNextRun(schedule string) time.Time {
	now := time.Now().In(s.timezone)

	// Handle @every <duration>
	if len(schedule) > 7 && schedule[:7] == "@every " {
		d, err := time.ParseDuration(schedule[7:])
		if err == nil && d > 0 {
			return now.Add(d)
		}
	}

	// Handle common shortcuts
	switch schedule {
	case "@hourly":
		return now.Add(time.Hour)
	case "@daily", "@midnight":
		return now.Add(24 * time.Hour)
	case "@weekly":
		return now.Add(7 * 24 * time.Hour)
	case "@monthly":
		return now.AddDate(0, 1, 0)
	case "@yearly", "@annually":
		return now.AddDate(1, 0, 0)
	}

	// For cron expressions, default to 1 minute in the future
	return now.Add(time.Minute)
}

// wrapHandler creates a wrapped handler that tracks execution state
func (s *Scheduler) wrapHandler(task *Task) func() {
	return func() {
		// Skip if task is disabled
		s.mu.RLock()
		enabled := task.Enabled
		s.mu.RUnlock()

		if !enabled {
			return
		}

		s.executeTask(task)
	}
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
	// Check for missed tasks within catch-up window
	if err := s.catchUpMissedTasks(); err != nil {
		log.Printf("WARN: Error catching up missed tasks: %v", err)
	}

	// Start the gocron scheduler
	s.gocron.Start()

	log.Println("INFO: Scheduler started")
	return nil
}

// catchUpMissedTasks runs tasks that were missed during downtime
func (s *Scheduler) catchUpMissedTasks() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	for _, task := range s.tasks {
		if !task.Enabled {
			continue
		}

		// Check if task was supposed to run during downtime
		if !task.NextRun.IsZero() && task.NextRun.Before(now) {
			// Within catch-up window?
			if now.Sub(task.NextRun) <= s.catchUpWind {
				log.Printf("INFO: Catching up missed task: %s", task.Name)
				go s.executeTask(task)
			}
		}
	}

	return nil
}

// executeTask executes a single task with state tracking and error handling.
// See AI.md PART 18: Task Execution Flow
func (s *Scheduler) executeTask(task *Task) {
	startTime := time.Now()
	log.Printf("INFO: Executing task: %s", task.Name)

	// Execute task handler
	err := task.Handler(s.ctx)

	duration := time.Since(startTime)

	// Update task state
	s.mu.Lock()
	task.LastRun = startTime
	if err != nil {
		task.LastStatus = "failed"
		task.LastError = err.Error()
		task.FailCount++
		log.Printf("ERROR: Task %s failed after %v: %v", task.Name, duration, err)
	} else {
		task.LastStatus = "success"
		task.LastError = ""
		task.RunCount++
		log.Printf("INFO: Task %s completed successfully in %v", task.Name, duration)
	}

	// Update NextRun from gocron
	if task.gocronJob != nil {
		nextRuns, _ := task.gocronJob.NextRuns(1)
		if len(nextRuns) > 0 {
			task.NextRun = nextRuns[0]
		}
	}
	// Fallback: if gocronJob didn't provide NextRun, estimate from schedule
	if task.NextRun.IsZero() || !task.NextRun.After(startTime) {
		task.NextRun = s.estimateNextRun(task.Schedule)
	}

	// Save state to database
	if err := s.saveTaskState(task); err != nil {
		log.Printf("ERROR: Failed to save task state for %s: %v", task.Name, err)
	}
	s.mu.Unlock()
}

// Stop gracefully stops the scheduler
// Waits for running tasks to complete (max 30 seconds)
// See AI.md PART 18: Shutdown Behavior
func (s *Scheduler) Stop() error {
	log.Println("INFO: Stopping scheduler...")

	// Cancel context to stop scheduler loop
	s.cancel()

	// Stop gocron scheduler
	if err := s.gocron.Shutdown(); err != nil {
		log.Printf("WARN: Error shutting down gocron: %v", err)
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

	go s.executeTask(task)
	return nil
}

// checkTasks iterates over all tasks and executes any that are due.
// This provides backward compatibility with the tick-based scheduler pattern.
func (s *Scheduler) checkTasks() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	for _, task := range s.tasks {
		if !task.Enabled {
			continue
		}
		if task.NextRun.IsZero() {
			continue
		}
		if now.After(task.NextRun) || now.Equal(task.NextRun) {
			go s.executeTask(task)
		}
	}
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
