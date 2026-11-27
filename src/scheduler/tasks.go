package scheduler

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/apimgr/whois/src/whois/records"
)

// RegisterBuiltInTasks registers all required built-in tasks (AI.md PART 18).
// Task IDs use underscore convention per AI.md PART 18.
// Required tasks: ssl_renewal, geoip_update, token_cleanup, log_rotation,
// backup_daily, backup_hourly, healthcheck_self, blocklist_update, cve_update,
// update_check, tor_health, i2p_health.
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

	if err := s.Register(&Task{
		ID:          "security_cleanup",
		Name:        "Security Report Cleanup",
		Schedule:    "30 3 * * *",
		Enabled:     true,
		Handler:     s.taskSecurityCleanup,
		RetryPolicy: &RetryPolicy{MaxRetries: 3, RetryDelay: 10 * time.Minute, Backoff: "exponential"},
	}); err != nil {
		return fmt.Errorf("failed to register security_cleanup: %w", err)
	}
	if err := s.Register(&Task{
		ID:          "secret_rotation",
		Name:        "Generated Secret Rotation",
		Schedule:    "15 1 * * *",
		Enabled:     true,
		Handler:     s.taskSecretRotation,
		RetryPolicy: &RetryPolicy{MaxRetries: 3, RetryDelay: 10 * time.Minute, Backoff: "exponential"},
	}); err != nil {
		return fmt.Errorf("failed to register secret_rotation: %w", err)
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
	if err := s.Register(&Task{ID: "i2p_health", Name: "I2P Health Check", Schedule: "@every 10m", Enabled: false, Handler: s.taskI2PHealth}); err != nil {
		return fmt.Errorf("failed to register i2p_health: %w", err)
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

	log.Printf("INFO: Registered %d built-in scheduler tasks", 16)
	return nil
}

func (s *Scheduler) taskSecurityCleanup(ctx context.Context) error {
	days, _ := s.securityCleanupSettings()
	result, err := s.execWrite(ctx, "DELETE FROM security_reports WHERE tracking_id IN (SELECT tracking_id FROM security_reports WHERE closed_at IS NOT NULL AND closed_at <= datetime('now', ?) LIMIT 500)", fmt.Sprintf("-%d days", days))
	if err != nil {
		return fmt.Errorf("delete expired security reports: %w", err)
	}
	if removed, _ := result.RowsAffected(); removed > 0 {
		log.Printf("INFO: security_cleanup: removed %d expired security reports", removed)
	}
	if err := s.cleanupRetiredPGPKey(); err != nil {
		return fmt.Errorf("remove retired PGP key: %w", err)
	}
	for _, name := range []string{"installation_secret", "encryption_key", "cookie_signing_key", "csrf_token_secret"} {
		var until string
		err := s.store.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name=?`, name+"_previous_until").Scan(&until)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s grace deadline: %w", name, err)
		}
		deadline, err := time.Parse(time.RFC3339, until)
		if err != nil {
			return fmt.Errorf("parse %s grace deadline: %w", name, err)
		}
		if !time.Now().UTC().Before(deadline) {
			if _, err := s.execWrite(ctx, `DELETE FROM app_secrets WHERE name IN (?,?)`, name+"_previous", name+"_previous_until"); err != nil {
				return fmt.Errorf("retire previous %s: %w", name, err)
			}
		}
	}
	return nil
}

func (s *Scheduler) taskSecretRotation(ctx context.Context) error {
	for _, rotation := range []struct {
		name   string
		period time.Duration
		grace  time.Duration
	}{
		{name: "cookie_signing_key", period: 90 * 24 * time.Hour, grace: 7 * 24 * time.Hour},
		{name: "csrf_token_secret", period: 180 * 24 * time.Hour, grace: 7 * 24 * time.Hour},
	} {
		if err := s.rotateAppSecretIfDue(ctx, rotation.name, rotation.period, rotation.grace); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scheduler) rotateAppSecretIfDue(ctx context.Context, name string, period, grace time.Duration) error {
	if s.store == nil {
		return fmt.Errorf("secret rotation requires the application database")
	}
	now := time.Now().UTC()
	return s.store.Write(ctx, func(tx *sql.Tx) error {
		var oldValue, updatedAt string
		if err := tx.QueryRowContext(ctx, `SELECT value,updated_at FROM app_secrets WHERE name=?`, name).Scan(&oldValue, &updatedAt); err != nil {
			return fmt.Errorf("read %s rotation state: %w", name, err)
		}
		lastRotation, err := time.Parse(time.RFC3339, updatedAt)
		if err != nil {
			return fmt.Errorf("parse %s rotation time: %w", name, err)
		}
		if now.Sub(lastRotation) < period {
			return nil
		}
		oldSecret, err := base64.StdEncoding.DecodeString(oldValue)
		if err != nil || len(oldSecret) != 32 {
			return fmt.Errorf("current %s is invalid", name)
		}
		newSecret := make([]byte, 32)
		if _, err := rand.Read(newSecret); err != nil {
			return fmt.Errorf("generate %s: %w", name, err)
		}
		previousValue := base64.StdEncoding.EncodeToString(oldSecret)
		currentValue := base64.StdEncoding.EncodeToString(newSecret)
		values := map[string]string{name + "_previous": previousValue, name + "_previous_until": now.Add(grace).Format(time.RFC3339), name: currentValue}
		for key, value := range values {
			if _, err := tx.ExecContext(ctx, `INSERT INTO app_secrets(name,value,updated_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, key, value, now.Format(time.RFC3339)); err != nil {
				return fmt.Errorf("save %s rotation state: %w", name, err)
			}
		}
		log.Printf("INFO: secret_rotation rotated %s", name)
		return nil
	})
}

func (s *Scheduler) taskI2PHealth(ctx context.Context) error {
	if s.I2PHealthHook == nil {
		return nil
	}
	return s.I2PHealthHook(ctx)
}

// taskTokenCleanup removes expired and revoked API tokens.
func (s *Scheduler) taskTokenCleanup(ctx context.Context) error {
	// Remove revoked tokens soft-deleted more than 30 days ago
	result, err := s.execWrite(ctx,
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
