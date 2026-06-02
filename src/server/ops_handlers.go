package server

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/casapps/caswhois/src/backup"
)

// runBackup builds the BackupOptions for the current server config and
// invokes backup.Create. It is the shared entry point used by both the
// HTTP handler (handleBackupRun) and the scheduler hooks (backup_daily /
// backup_hourly). prefix controls the filename prefix; pass "backup" for
// daily/full backups and "backup-hourly" for hourly incrementals.
func (s *Server) runBackup(prefix string) (string, error) {
	backupDir := s.config.GetBackupDir()
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}

	filename := prefix + "-" + time.Now().UTC().Format("20060102-150405") + ".tar.gz"
	destPath := filepath.Join(backupDir, filename)

	password := ""
	if s.config.BackupEncryptionEnabled {
		// Server token doubles as the backup encryption key (AI.md PART 21).
		password = s.config.ServerToken
	}

	opts := &backup.BackupOptions{
		ConfigDir:   s.config.ConfigDir,
		DataDir:     s.config.GetDatabaseDir(),
		OutputFile:  destPath,
		Password:    password,
		IncludeData: true,
		AppVersion:  "dev",
	}

	if err := backup.Create(opts); err != nil {
		return filename, fmt.Errorf("backup.Create: %w", err)
	}

	// Apply retention policy after successful creation (AI.md PART 21).
	if err := backup.ApplyRetentionPolicy(
		backupDir,
		s.config.BackupMaxBackups,
		s.config.BackupKeepWeekly,
		s.config.BackupKeepMonthly,
		s.config.BackupKeepYearly,
	); err != nil {
		log.Printf("WARN: backup retention failed: %v", err)
	}
	return filename, nil
}

// ---- Scheduler handlers -------------------------------------------------------

// schedulerTaskInfo is the wire representation of a scheduler task.
type schedulerTaskInfo struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Schedule   string    `json:"schedule"`
	Enabled    bool      `json:"enabled"`
	LastRun    time.Time `json:"last_run,omitempty"`
	LastStatus string    `json:"last_status,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
	NextRun    time.Time `json:"next_run,omitempty"`
	RunCount   int64     `json:"run_count"`
	FailCount  int64     `json:"fail_count"`
}

// handleSchedulerStatus returns the list of registered scheduler tasks.
// GET /api/v1/server/schedulers  (requires server token)
func (s *Server) handleSchedulerStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	if s.scheduler == nil {
		SendSuccess(w, map[string]interface{}{
			"running": false,
			"tasks":   []schedulerTaskInfo{},
		})
		return
	}

	tasks := s.scheduler.GetTasks()
	out := make([]schedulerTaskInfo, 0, len(tasks))
	for _, t := range tasks {
		out = append(out, schedulerTaskInfo{
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

	SendSuccess(w, map[string]interface{}{
		"running":  s.scheduler.IsRunning(),
		"timezone": s.scheduler.GetTimezone(),
		"tasks":    out,
	})
}

// handleSchedulerRun triggers an immediate run of a named task.
// POST /api/v1/server/schedulers/run?task=<id>  (requires server token)
func (s *Server) handleSchedulerRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	if s.scheduler == nil {
		SendError(w, ErrServerError, "Scheduler not initialized")
		return
	}

	taskID := r.URL.Query().Get("task")
	if taskID == "" {
		SendError(w, ErrBadRequest, "task query parameter required")
		return
	}

	if err := s.scheduler.RunTaskNow(taskID); err != nil {
		SendError(w, ErrNotFound, "Task not found or could not be run: "+err.Error())
		return
	}

	SendSuccess(w, map[string]interface{}{
		"task":      taskID,
		"triggered": true,
	})
}

// ---- Backup handlers ----------------------------------------------------------

// backupInfo is the wire representation of a backup entry.
type backupInfo struct {
	Filename  string    `json:"filename"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

// handleBackupStatus lists available backups.
// GET /api/v1/server/backups  (requires server token)
func (s *Server) handleBackupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	backupDir := s.config.GetBackupDir()
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			SendSuccess(w, map[string]interface{}{
				"backup_dir": backupDir,
				"backups":    []backupInfo{},
			})
			return
		}
		SendError(w, ErrServerError, "Failed to list backups: "+err.Error())
		return
	}

	backups := make([]backupInfo, 0)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		backups = append(backups, backupInfo{
			Filename:  e.Name(),
			Size:      info.Size(),
			CreatedAt: info.ModTime().UTC(),
		})
	}

	SendSuccess(w, map[string]interface{}{
		"backup_dir": backupDir,
		"backups":    backups,
	})
}

// handleBackupRun triggers an immediate backup.
// POST /api/v1/server/backups/run  (requires server token)
func (s *Server) handleBackupRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendError(w, ErrMethodNotAllowed, "Method not allowed")
		return
	}

	backupDir := s.config.GetBackupDir()

	// Run backup asynchronously so the HTTP response returns immediately.
	// Errors are logged because no caller is waiting once the response is sent.
	go func() {
		if _, err := s.runBackup("backup"); err != nil {
			log.Printf("ERROR: on-demand backup failed: %v", err)
		}
	}()

	SendSuccess(w, map[string]interface{}{
		"backup_dir": backupDir,
		"started":    true,
	})
}
