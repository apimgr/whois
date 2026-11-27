package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apimgr/whois/src/backup"
	"github.com/apimgr/whois/src/common/constants"
	"github.com/apimgr/whois/src/config"
	caslogger "github.com/apimgr/whois/src/logger"
)

// runBackup builds the BackupOptions for the current server config and
// invokes backup.Create. It is the shared entry point used by both the
// HTTP handler (handleBackupRun) and the scheduler hooks (backup_daily /
// backup_hourly). prefix controls the filename prefix; pass "backup" for
// daily/full backups and "backup-hourly" for hourly incrementals.
func (s *Server) runBackup(prefix string) (resultFilename string, resultErr error) {
	failureAction := "backup.failed"
	defer func() {
		if resultErr == nil {
			return
		}
		if strings.Contains(resultErr.Error(), "backup.skipped_disk_full") {
			failureAction = "backup.skipped_disk_full"
		}
		s.recordBackupEvent(failureAction, fmt.Sprintf("filename=%s error=%s", resultFilename, resultErr), false)
		if failureAction != "backup.skipped_disk_full" {
			s.notifyBackup("backup_failed", resultFilename, 0, resultErr)
		}
	}()
	backupDir := s.config.GetBackupDir()
	if err := backup.EnsureBackupDir(backupDir); err != nil {
		return "", err
	}
	if err := backup.SweepBackupArtifacts(backupDir); err != nil {
		return "", err
	}
	if err := backup.CheckBackupDiskSpace(backupDir, s.config.Maintenance.Cleanup.DiskThreshold); err != nil {
		log.Printf("ERROR: %v", err)
		return "", err
	}

	password, err := config.LoadBackupPassword(s.config.ConfigDir, s.config)
	if err != nil {
		return "", err
	}
	if s.config.Compliance.Enabled && password == "" {
		return "", fmt.Errorf("backups require encryption in compliance mode; set server.backup.encryption_password in secrets.yml")
	}
	if password == "" {
		log.Printf("WARN: backup encryption is not configured; creating an unencrypted backup")
	}
	extension := ".tar.gz"
	if password != "" {
		extension += ".enc"
	}
	now := time.Now().UTC()
	opts := &backup.BackupOptions{
		ConfigDir:          s.config.ConfigDir,
		DataDir:            s.config.GetDatabaseDir(),
		Password:           password,
		IncludeData:        false,
		AppVersion:         "dev",
		BackupDir:          backupDir,
		SnapshotAt:         now,
		ConnectionTLSFiles: []string{s.config.Cache.TLSCA, s.config.Cache.TLSCert, s.config.Cache.TLSKey},
		ExternalTLSFiles:   []backup.ExternalTLSFile{{Name: "cert.pem", Path: s.config.TLS.Cert}, {Name: "key.pem", Path: s.config.TLS.Key}},
	}
	if s.database != nil {
		appSecrets, err := s.database.ExportAppSecrets(context.Background())
		if err != nil {
			return "", fmt.Errorf("export application secrets: %w", err)
		}
		opts.AppSecrets = appSecrets
	}
	if prefix == "backup-hourly" {
		filename := constants.InternalName + "-hourly" + extension
		opts.OutputFile = filepath.Join(backupDir, filename)
		if err := backup.CreateIncremental(opts, "hourly"); err != nil {
			if errors.Is(err, backup.ErrNoFullBackup) {
				return "", nil
			}
			if errors.Is(err, backup.ErrBackupPasswordChanged) || errors.Is(err, backup.ErrCorruptBackupBase) {
				log.Printf("WARN: hourly incremental skipped: %v", err)
				return "", nil
			}
			return filename, fmt.Errorf("create hourly incremental: %w", err)
		}
		if err := backup.VerifyBackup(opts.OutputFile, password); err != nil {
			_ = os.Remove(opts.OutputFile)
			failureAction = "backup.verification_failed"
			return filename, fmt.Errorf("hourly incremental verification failed: %w", err)
		}
		s.recordCreatedBackup(filename, opts.OutputFile, password != "")
		return filename, nil
	}
	if prefix == "backup-daily" {
		filename := constants.InternalName + "-daily" + extension
		opts.OutputFile = filepath.Join(backupDir, filename)
		if err := backup.CreateIncremental(opts, "daily"); err != nil {
			switch {
			case errors.Is(err, backup.ErrNoFullBackup):
			case errors.Is(err, backup.ErrBackupPasswordChanged):
				log.Printf("INFO: backup encryption password changed; skipping daily incremental")
			case errors.Is(err, backup.ErrCorruptBackupBase):
				log.Printf("WARN: corrupt incremental base; skipping daily incremental: %v", err)
			default:
				return filename, fmt.Errorf("create daily incremental: %w", err)
			}
		} else {
			if err := backup.VerifyBackup(opts.OutputFile, password); err != nil {
				_ = os.Remove(opts.OutputFile)
				failureAction = "backup.verification_failed"
				return filename, fmt.Errorf("daily incremental verification failed: %w", err)
			}
			s.recordBackupEvent("backup.daily_updated", fmt.Sprintf("filename=%s", filename), true)
		}
	}
	dateFormat := "2006-01-02_150405"
	if prefix == "backup-daily" {
		dateFormat = "2006-01-02"
		dailyPath := filepath.Join(backupDir, fmt.Sprintf("%s_backup_%s%s", constants.InternalName, now.Format(dateFormat), extension))
		if _, err := os.Stat(dailyPath); err == nil {
			dateFormat = "2006-01-02_150405"
		}
	}
	filename := fmt.Sprintf("%s_backup_%s%s", constants.InternalName, now.Format(dateFormat), extension)
	destPath := filepath.Join(backupDir, filename)
	opts.OutputFile = destPath
	if err := backup.Create(opts); err != nil {
		return filename, fmt.Errorf("backup.Create: %w", err)
	}
	if err := backup.VerifyBackup(destPath, password); err != nil {
		_ = os.Remove(destPath)
		failureAction = "backup.verification_failed"
		return filename, fmt.Errorf("backup verification failed: %w", err)
	}

	// Apply retention policy after successful creation (AI.md PART 21).
	beforeRetention := backupArchiveNames(backupDir)
	if err := backup.ApplyRetentionPolicy(
		backupDir,
		s.config.Backup.Retention.MaxBackups,
		s.config.Backup.Retention.KeepWeekly,
		s.config.Backup.Retention.KeepMonthly,
		s.config.Backup.Retention.KeepYearly,
		s.config.Backup.Retention.MaxTotalSize,
	); err != nil {
		log.Printf("WARN: backup retention failed: %v", err)
		s.recordBackupEvent("backup.retention_cleanup", fmt.Sprintf("error=%s", err), false)
	} else {
		remaining := backupArchiveNames(backupDir)
		var deleted []string
		for name := range beforeRetention {
			if !remaining[name] {
				deleted = append(deleted, name)
			}
		}
		if len(deleted) > 0 {
			s.recordBackupEvent("backup.retention_cleanup", fmt.Sprintf("deleted=%s remaining_count=%d reason=retention_policy", strings.Join(deleted, ","), len(remaining)), true)
		}
	}
	s.recordCreatedBackup(filename, destPath, password != "")
	return filename, nil
}

func (s *Server) recordCreatedBackup(filename, path string, encrypted bool) {
	size := int64(0)
	if info, err := os.Stat(path); err == nil {
		size = info.Size()
	}
	s.recordBackupEvent("backup.created", fmt.Sprintf("filename=%s size=%d encrypted=%t verification=passed", filename, size, encrypted), true)
	s.notifyBackup("backup_complete", filename, size, nil)
}

func (s *Server) recordBackupEvent(action, details string, success bool) {
	if s.logger == nil {
		return
	}
	level := "INFO"
	if !success {
		level = "ERROR"
	}
	s.logger.WriteAudit(caslogger.AuditEntry{Level: level, Category: "backup", Action: action, Source: "system", Details: details, Success: success})
	severity := "info"
	if !success {
		severity = "critical"
	}
	s.dispatchAdminWebhooks(action, "Backup event: "+action, details, severity)
}

func (s *Server) notifyBackup(template, filename string, size int64, failure error) {
	if s.email == nil || s.config == nil || strings.TrimSpace(s.config.Contact.Admin.Email) == "" {
		return
	}
	fqdn := s.config.FQDN
	appURL := ""
	if fqdn != "" {
		appURL = "https://" + fqdn
	}
	errorText := ""
	if failure != nil {
		errorText = failure.Error()
	}
	if err := s.email.SendEmail(s.config.Contact.Admin.Email, template, map[string]string{
		"app_name":  constants.InternalName,
		"fqdn":      fqdn,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"filename":  filename,
		"size":      fmt.Sprintf("%d bytes", size),
		"error":     errorText,
		"app_url":   appURL,
	}); err != nil {
		log.Printf("WARN: backup notification delivery failed: %v", err)
	}
}

func backupArchiveNames(dir string) map[string]bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := make(map[string]bool)
	for _, entry := range entries {
		if !entry.IsDir() && strings.Contains(entry.Name(), ".tar.gz") {
			names[entry.Name()] = true
		}
	}
	return names
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
// GET /api/{api_version}/server/schedulers  (requires server token)
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
// POST /api/{api_version}/server/schedulers/run?task=<id>  (requires server token)
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
// GET /api/{api_version}/server/backups  (requires server token)
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
// POST /api/{api_version}/server/backups/run  (requires server token)
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
