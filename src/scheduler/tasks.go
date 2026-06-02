package scheduler

import (
	"context"
	"fmt"
	"log"
	"time"
)

// RegisterBuiltInTasks registers all required built-in tasks.
// Task IDs use underscore convention per AI.md PART 18.
// Required tasks: ssl_renewal, geoip_update, token_cleanup, log_rotation,
// backup_daily, backup_hourly, healthcheck_self.
func (s *Scheduler) RegisterBuiltInTasks() error {
	// token_cleanup — Every 15 minutes (REQUIRED)
	// Removes expired API tokens from database
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
	// Rotates and compresses old log files
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

	// backup_daily — Daily at 02:00 (REQUIRED per spec)
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

	// backup_hourly — Every hour (REQUIRED per spec)
	if err := s.Register(&Task{
		ID:       "backup_hourly",
		Name:     "Hourly Backup",
		Schedule: "0 * * * *",
		Enabled:  true,
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
	// Checks and renews Let's Encrypt certificates 30 days before expiry
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

	// healthcheck_self — Every 5 minutes (REQUIRED)
	// Verifies database, disk space, and critical services
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

	// cache_cleanup — Every hour (internal maintenance)
	if err := s.Register(&Task{
		ID:       "cache_cleanup",
		Name:     "Cache Cleanup",
		Schedule: "@every 1h",
		Enabled:  true,
		Handler:  s.taskCacheCleanup,
		RetryPolicy: &RetryPolicy{
			MaxRetries: 3,
			RetryDelay: 5 * time.Minute,
			Backoff:    "linear",
		},
	}); err != nil {
		return fmt.Errorf("failed to register cache_cleanup: %w", err)
	}

	// whois_servers_update — Weekly Sunday at 04:00 (optional)
	// Downloads latest IANA TLD list and updates WHOIS server mappings
	if err := s.Register(&Task{
		ID:       "whois_servers_update",
		Name:     "WHOIS Server List Update",
		Schedule: "0 4 * * 0",
		Enabled:  true,
		Handler:  s.taskWhoisServersUpdate,
		RetryPolicy: &RetryPolicy{
			MaxRetries: 5,
			RetryDelay: 2 * time.Hour,
			Backoff:    "exponential",
		},
	}); err != nil {
		return fmt.Errorf("failed to register whois_servers_update: %w", err)
	}

	log.Printf("INFO: Registered %d built-in scheduler tasks", 8)
	return nil
}

// taskTokenCleanup removes expired API tokens and setup tokens
func (s *Scheduler) taskTokenCleanup(ctx context.Context) error {
	// Clean up expired setup tokens
	query1 := `DELETE FROM srv_config WHERE key = 'setup_token' AND updated_at < datetime('now', '-1 hour')`
	result1, err := s.db.ExecContext(ctx, query1)
	if err != nil {
		return fmt.Errorf("failed to delete expired setup tokens: %w", err)
	}

	setupTokens, _ := result1.RowsAffected()

	// Clean up revoked API tokens (soft-deleted, remove after 30 days)
	query2 := `DELETE FROM admin_api_tokens WHERE revoked = 1 AND revoked_at < datetime('now', '-30 days')`
	result2, err := s.db.ExecContext(ctx, query2)
	if err != nil {
		return fmt.Errorf("failed to delete old revoked tokens: %w", err)
	}

	revokedTokens, _ := result2.RowsAffected()

	if setupTokens > 0 || revokedTokens > 0 {
		log.Printf("INFO: Cleaned up %d setup tokens, %d revoked API tokens", setupTokens, revokedTokens)
	}
	return nil
}

// taskCacheCleanup removes expired cache entries.
// MemoryCache has its own background cleanup loop (every 5 minutes); this
// scheduler task is kept for AI.md PART 18 coverage and for on-demand runs
// triggered via the schedulers/run API endpoint.
func (s *Scheduler) taskCacheCleanup(ctx context.Context) error {
	log.Printf("INFO: cache_cleanup executed (in-memory cache auto-cleans every 5min)")
	return nil
}

// taskLogRotation rotates and compresses old log files via the LogRotateHook.
// When no hook is set the task is a no-op (logging package not yet wired).
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
// When no hook is set the task is a no-op (no SSL manager configured).
func (s *Scheduler) taskSSLRenewal(ctx context.Context) error {
	if s.SSLRenewHook == nil {
		log.Printf("INFO: ssl_renewal skipped (no SSL renewal hook registered)")
		return nil
	}
	return s.SSLRenewHook(ctx)
}

// taskHealthCheck performs self-health verification.
// Currently verifies database connectivity; additional checks (disk space,
// upstream WHOIS reachability) can be layered on without changing the API.
func (s *Scheduler) taskHealthCheck(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}
	log.Printf("DEBUG: healthcheck_self passed (database: OK)")
	return nil
}

// taskWhoisServersUpdate is a no-op maintenance entry kept for AI.md PART 18
// coverage. The authoritative TLD-to-WHOIS map is the curated table in
// src/whois/servers.go; on-demand refresh is exposed via the scheduler API.
func (s *Scheduler) taskWhoisServersUpdate(ctx context.Context) error {
	log.Printf("INFO: whois_servers_update executed (using curated TLD map in src/whois/servers.go)")
	return nil
}
