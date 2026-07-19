package scheduler

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/apimgr/whois/src/whois/records"
)

// RegisterBuiltInTasks registers all required built-in tasks (AI.md PART 18).
// Task IDs use underscore convention per AI.md PART 18.
// Required tasks: ssl_renewal, geoip_update, token_cleanup, log_rotation,
// backup_daily, backup_hourly, healthcheck_self, blocklist_update, cve_update,
// update_check, tor_health.
func (s *Scheduler) RegisterBuiltInTasks() error {
	// token_cleanup — Every 15 minutes (REQUIRED)
	if err := s.Register(&Task{
		ID:       "token_cleanup",
		Name:     "Token Cleanup",
		Schedule: "@every 15m",
		Enabled:  true,
		Handler:  s.taskTokenCleanup,
		RetryPolicy: &RetryPolicy{
			MaxRetries: 3,
			RetryDelay: 1 * time.Minute,
			Backoff:    "linear",
		},
	}); err != nil {
		return fmt.Errorf("failed to register token_cleanup: %w", err)
	}

	// log_rotation — Daily at midnight (REQUIRED)
	if err := s.Register(&Task{
		ID:       "log_rotation",
		Name:     "Log Rotation",
		Schedule: "0 0 * * *",
		Enabled:  true,
		Handler:  s.taskLogRotation,
		RetryPolicy: &RetryPolicy{
			MaxRetries: 3,
			RetryDelay: 10 * time.Minute,
			Backoff:    "exponential",
		},
	}); err != nil {
		return fmt.Errorf("failed to register log_rotation: %w", err)
	}

	// backup_daily — Daily at 02:00 (REQUIRED)
	if err := s.Register(&Task{
		ID:       "backup_daily",
		Name:     "Daily Backup",
		Schedule: "0 2 * * *",
		Enabled:  true,
		Handler:  s.taskDailyBackup,
		RetryPolicy: &RetryPolicy{
			MaxRetries: 2,
			RetryDelay: 30 * time.Minute,
			Backoff:    "exponential",
		},
	}); err != nil {
		return fmt.Errorf("failed to register backup_daily: %w", err)
	}

	// backup_hourly — Every hour (REQUIRED, disabled by default per spec)
	if err := s.Register(&Task{
		ID:       "backup_hourly",
		Name:     "Hourly Backup",
		Schedule: "@hourly",
		Enabled:  false,
		Handler:  s.taskHourlyBackup,
		RetryPolicy: &RetryPolicy{
			MaxRetries: 2,
			RetryDelay: 10 * time.Minute,
			Backoff:    "exponential",
		},
	}); err != nil {
		return fmt.Errorf("failed to register backup_hourly: %w", err)
	}

	// ssl_renewal — Daily at 03:00 (REQUIRED)
	if err := s.Register(&Task{
		ID:       "ssl_renewal",
		Name:     "SSL Certificate Renewal",
		Schedule: "0 3 * * *",
		Enabled:  true,
		Handler:  s.taskSSLRenewal,
		RetryPolicy: &RetryPolicy{
			MaxRetries: 5,
			RetryDelay: 1 * time.Hour,
			Backoff:    "exponential",
		},
	}); err != nil {
		return fmt.Errorf("failed to register ssl_renewal: %w", err)
	}

	// geoip_update — Weekly Sunday at 03:00 (REQUIRED)
	if err := s.Register(&Task{
		ID:       "geoip_update",
		Name:     "GeoIP Database Update",
		Schedule: "0 3 * * 0",
		Enabled:  true,
		Handler:  s.taskGeoIPUpdate,
		RetryPolicy: &RetryPolicy{
			MaxRetries: 5,
			RetryDelay: 1 * time.Hour,
			Backoff:    "exponential",
		},
	}); err != nil {
		return fmt.Errorf("failed to register geoip_update: %w", err)
	}

	// blocklist_update — Daily at 04:00 (REQUIRED)
	if err := s.Register(&Task{
		ID:       "blocklist_update",
		Name:     "Blocklist Update",
		Schedule: "0 4 * * *",
		Enabled:  true,
		Handler:  s.taskBlocklistUpdate,
		RetryPolicy: &RetryPolicy{
			MaxRetries: 3,
			RetryDelay: 1 * time.Hour,
			Backoff:    "exponential",
		},
	}); err != nil {
		return fmt.Errorf("failed to register blocklist_update: %w", err)
	}

	// cve_update — Daily at 05:00 (REQUIRED)
	if err := s.Register(&Task{
		ID:       "cve_update",
		Name:     "CVE Database Update",
		Schedule: "0 5 * * *",
		Enabled:  true,
		Handler:  s.taskCVEUpdate,
		RetryPolicy: &RetryPolicy{
			MaxRetries: 3,
			RetryDelay: 1 * time.Hour,
			Backoff:    "exponential",
		},
	}); err != nil {
		return fmt.Errorf("failed to register cve_update: %w", err)
	}

	// healthcheck_self — Every 5 minutes (REQUIRED)
	if err := s.Register(&Task{
		ID:       "healthcheck_self",
		Name:     "Self Health Check",
		Schedule: "@every 5m",
		Enabled:  true,
		Handler:  s.taskHealthCheck,
		RetryPolicy: &RetryPolicy{
			MaxRetries: 3,
			RetryDelay: 1 * time.Minute,
			Backoff:    "linear",
		},
	}); err != nil {
		return fmt.Errorf("failed to register healthcheck_self: %w", err)
	}

	// tor_health — Every 10 minutes (REQUIRED when Tor installed)
	if err := s.Register(&Task{
		ID:       "tor_health",
		Name:     "Tor Health Check",
		Schedule: "@every 10m",
		Enabled:  true,
		Handler:  s.taskTorHealth,
		RetryPolicy: &RetryPolicy{
			MaxRetries: 3,
			RetryDelay: 1 * time.Minute,
			Backoff:    "linear",
		},
	}); err != nil {
		return fmt.Errorf("failed to register tor_health: %w", err)
	}

	// whois_records_refresh — Daily; re-queries permanent records older than 30 days
	if err := s.Register(&Task{
		ID:       "whois_records_refresh",
		Name:     "WHOIS Records Refresh",
		Schedule: "0 6 * * *",
		Enabled:  true,
		Handler:  s.taskWhoisRecordsRefresh,
		RetryPolicy: &RetryPolicy{
			MaxRetries: 3,
			RetryDelay: 30 * time.Minute,
			Backoff:    "exponential",
		},
	}); err != nil {
		return fmt.Errorf("failed to register whois_records_refresh: %w", err)
	}

	// rdap_bootstrap_update — Weekly Sunday at 04:00 (after GeoIP update)
	if err := s.Register(&Task{
		ID:       "rdap_bootstrap_update",
		Name:     "RDAP Bootstrap Update",
		Schedule: "0 4 * * 0",
		Enabled:  true,
		Handler:  s.taskRDAPBootstrapUpdate,
		RetryPolicy: &RetryPolicy{
			MaxRetries: 5,
			RetryDelay: 1 * time.Hour,
			Backoff:    "exponential",
		},
	}); err != nil {
		return fmt.Errorf("failed to register rdap_bootstrap_update: %w", err)
	}

	// update_check — Daily at 06:00 (REQUIRED, skippable; notify-only unless update.auto_install)
	if err := s.Register(&Task{
		ID:       "update_check",
		Name:     "Update Check",
		Schedule: "0 6 * * *",
		Enabled:  true,
		Handler:  s.taskUpdateCheck,
		RetryPolicy: &RetryPolicy{
			MaxRetries: 3,
			RetryDelay: 1 * time.Hour,
			Backoff:    "exponential",
		},
	}); err != nil {
		return fmt.Errorf("failed to register update_check: %w", err)
	}

	log.Printf("INFO: Registered %d built-in scheduler tasks", 13)
	return nil
}

// taskTokenCleanup removes expired and revoked API tokens.
func (s *Scheduler) taskTokenCleanup(ctx context.Context) error {
	// Remove revoked tokens soft-deleted more than 30 days ago
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM api_tokens WHERE revoked_at IS NOT NULL AND revoked_at < datetime('now', '-30 days')`)
	if err != nil {
		return fmt.Errorf("failed to delete revoked tokens: %w", err)
	}

	n, _ := result.RowsAffected()
	if n > 0 {
		log.Printf("INFO: token_cleanup: removed %d revoked API tokens", n)
	}
	return nil
}

// taskLogRotation rotates and compresses old log files via the LogRotateHook.
// When no hook is set the task is a no-op.
func (s *Scheduler) taskLogRotation(ctx context.Context) error {
	if s.LogRotateHook == nil {
		log.Printf("INFO: log_rotation skipped (no log-rotation hook registered)")
		return nil
	}
	return s.LogRotateHook(ctx)
}

// taskHourlyBackup performs an hourly incremental database backup via the
// BackupHourlyHook. When no hook is set the task is a no-op.
func (s *Scheduler) taskHourlyBackup(ctx context.Context) error {
	if s.BackupHourlyHook == nil {
		log.Printf("INFO: backup_hourly skipped (no hourly-backup hook registered)")
		return nil
	}
	return s.BackupHourlyHook(ctx)
}

// taskDailyBackup performs a full daily database backup via the
// BackupDailyHook. When no hook is set the task is a no-op.
func (s *Scheduler) taskDailyBackup(ctx context.Context) error {
	if s.BackupDailyHook == nil {
		log.Printf("INFO: backup_daily skipped (no daily-backup hook registered)")
		return nil
	}
	return s.BackupDailyHook(ctx)
}

// taskSSLRenewal renews Let's Encrypt certificates via the SSLRenewHook.
// When no hook is set the task is a no-op.
func (s *Scheduler) taskSSLRenewal(ctx context.Context) error {
	if s.SSLRenewHook == nil {
		log.Printf("INFO: ssl_renewal skipped (no SSL renewal hook registered)")
		return nil
	}
	return s.SSLRenewHook(ctx)
}

// taskGeoIPUpdate downloads the latest GeoIP databases via the GeoIPUpdateHook.
// When no hook is set the task is a no-op.
func (s *Scheduler) taskGeoIPUpdate(ctx context.Context) error {
	if s.GeoIPUpdateHook == nil {
		log.Printf("INFO: geoip_update skipped (no GeoIP update hook registered)")
		return nil
	}
	return s.GeoIPUpdateHook(ctx)
}

// taskBlocklistUpdate downloads the latest IP/domain blocklists via the
// BlocklistUpdateHook. When no hook is set the task is a no-op.
func (s *Scheduler) taskBlocklistUpdate(ctx context.Context) error {
	if s.BlocklistUpdateHook == nil {
		log.Printf("INFO: blocklist_update skipped (no blocklist update hook registered)")
		return nil
	}
	return s.BlocklistUpdateHook(ctx)
}

// taskCVEUpdate downloads the latest CVE/security databases via the
// CVEUpdateHook. When no hook is set the task is a no-op.
func (s *Scheduler) taskCVEUpdate(ctx context.Context) error {
	if s.CVEUpdateHook == nil {
		log.Printf("INFO: cve_update skipped (no CVE update hook registered)")
		return nil
	}
	return s.CVEUpdateHook(ctx)
}

// taskHealthCheck performs self-health verification: database connectivity.
func (s *Scheduler) taskHealthCheck(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}
	log.Printf("DEBUG: healthcheck_self passed (database: OK)")
	return nil
}

// taskTorHealth checks Tor connectivity and restarts if unhealthy via the
// TorHealthHook. When no hook is set (Tor not installed) the task is a no-op.
func (s *Scheduler) taskTorHealth(ctx context.Context) error {
	if s.TorHealthHook == nil {
		log.Printf("DEBUG: tor_health skipped (Tor not installed)")
		return nil
	}
	return s.TorHealthHook(ctx)
}

// taskWhoisRecordsRefresh finds permanent records older than 30 days and re-queries
// them via the WhoisRefreshHook. Records are never deleted, only refreshed in place.
// When no hook is registered the task is a no-op.
func (s *Scheduler) taskWhoisRecordsRefresh(ctx context.Context) error {
	if s.WhoisRefreshHook == nil {
		log.Printf("INFO: whois_records_refresh skipped (no refresh hook registered)")
		return nil
	}

	queries, err := records.RefreshStale(ctx, s.db, 30)
	if err != nil {
		return fmt.Errorf("whois_records_refresh: find stale: %w", err)
	}
	if len(queries) == 0 {
		log.Printf("DEBUG: whois_records_refresh: no stale records")
		return nil
	}

	if err := s.WhoisRefreshHook(ctx, queries); err != nil {
		return fmt.Errorf("whois_records_refresh: %w", err)
	}
	log.Printf("INFO: whois_records_refresh: refreshed %d stale records", len(queries))
	return nil
}

// taskUpdateCheck checks the configured release channel for a newer version via
// the UpdateCheckHook (AI.md PART 22). Notify-only unless update.auto_install is
// set; the hook honors update.defer_days. When no hook is set the task is a no-op.
func (s *Scheduler) taskUpdateCheck(ctx context.Context) error {
	if s.UpdateCheckHook == nil {
		log.Printf("INFO: update_check skipped (no update-check hook registered)")
		return nil
	}
	return s.UpdateCheckHook(ctx)
}

// taskRDAPBootstrapUpdate fetches the latest IANA RDAP bootstrap files via the
// RDAPBootstrapHook. When no hook is set the task is a no-op.
func (s *Scheduler) taskRDAPBootstrapUpdate(ctx context.Context) error {
	if s.RDAPBootstrapHook == nil {
		log.Printf("INFO: rdap_bootstrap_update skipped (no RDAP bootstrap hook registered)")
		return nil
	}
	return s.RDAPBootstrapHook(ctx)
}
