package server

import (
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/casapps/caswhois/src/backup"
)

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
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		SendError(w, ErrServerError, "Failed to create backup directory: "+err.Error())
		return
	}

	filename := "backup-" + time.Now().UTC().Format("20060102-150405") + ".tar.gz"
	destPath := filepath.Join(backupDir, filename)

	password := ""
	if s.config.BackupEncryptionEnabled {
		password = s.config.ServerToken // use server token as backup encryption key
	}

	opts := &backup.BackupOptions{
		ConfigDir:   s.config.ConfigDir,
		DataDir:     s.config.GetDatabaseDir(),
		OutputFile:  destPath,
		Password:    password,
		IncludeData: true,
	}

	// Run backup asynchronously so the HTTP response returns immediately
	go func() {
		if err := backup.Create(opts); err != nil {
			// Errors are not surfaced to the caller — logged only
		}
	}()

	SendSuccess(w, map[string]interface{}{
		"backup_dir": backupDir,
		"filename":   filename,
		"started":    true,
	})
}
