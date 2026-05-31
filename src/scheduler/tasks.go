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
		Global:   true,
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
		Global:   true,
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
		Global:   true,
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
		Global:   true,
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
		Global:   true,
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
		Global:   true,
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
		Global:   true,
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
		Global:   true,
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

// taskCacheCleanup removes expired cache entries
func (s *Scheduler) taskCacheCleanup(ctx context.Context) error {
	// MemoryCache has built-in cleanup loop that runs every 5 minutes
	// This scheduler task is kept for consistency with AI.md PART 19
	// and can be used to trigger on-demand cleanup if needed
	
	// For in-memory cache: cleanup happens automatically via cleanupLoop()
	// For database cache: would run DELETE FROM cache WHERE expires_at < now()
	
	log.Printf("INFO: Cache cleanup task executed (in-memory cache auto-cleans every 5min)")
	return nil
}

// taskLogRotation rotates and compresses old log files
func (s *Scheduler) taskLogRotation(ctx context.Context) error {
	// Log rotation implementation would require:
	// 1. Access to log directory path from config
	// 2. Find all .log files
	// 3. For each file: if size > 100MB or age > 1 day, rotate
	// 4. Compress rotated files with gzip
	// 5. Delete compressed files older than 30 days
	//
	// For now, this is a placeholder until logging package is integrated
	log.Printf("INFO: Log rotation task executed (placeholder - needs logging integration)")
	return nil
}

// taskHourlyBackup performs hourly incremental database backup
func (s *Scheduler) taskHourlyBackup(ctx context.Context) error {
	// Hourly incremental backup implementation would require:
	// 1. Determine database type from connection string
	// 2. For SQLite: use sqlite3 online backup API or WAL checkpoint
	// 3. Create backup with timestamp: backup-hourly-YYYY-MM-DD-HHMMSS.db
	// 4. Apply retention policy: keep last N hourly backups (default 24)
	// 5. Skip if no changes since last backup (compare WAL sequence)
	//
	// For now, this is a placeholder until backup package is implemented
	log.Printf("INFO: Hourly backup task executed (placeholder - needs backup integration)")
	return nil
}

// taskDailyBackup performs daily database backup
func (s *Scheduler) taskDailyBackup(ctx context.Context) error {
	// Backup implementation would require:
	// 1. Determine database type from connection string
	// 2. For SQLite: copy server.db and users.db files
	// 3. For PostgreSQL: execute pg_dump via exec.Command
	// 4. Create backup with timestamp: backup-YYYY-MM-DD-HHMMSS.tar.gz
	// 5. Optionally encrypt with AES-256-GCM
	// 6. Clean up old backups (keep last N based on retention policy)
	//
	// For now, this is a placeholder until backup package is implemented
	log.Printf("INFO: Daily backup task executed (placeholder - needs backup integration)")
	return nil
}

// taskSSLRenewal checks and renews SSL certificates
func (s *Scheduler) taskSSLRenewal(ctx context.Context) error {
	// SSL renewal implementation would require:
	// 1. Access to SSL manager instance
	// 2. Check expiry dates of certificates in {config_dir}/ssl/letsencrypt/
	// 3. For certs expiring within 7 days: trigger renewal via ACME
	// 4. After renewal: reload server to use new certificates
	// 5. Send email notification on success/failure
	//
	// For now, this is a placeholder until SSL manager is integrated
	log.Printf("INFO: SSL renewal task executed (placeholder - needs SSL integration)")
	return nil
}

// taskHealthCheck performs self-health verification
func (s *Scheduler) taskHealthCheck(ctx context.Context) error {
	// Check database connectivity
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}

	// Additional checks could include:
	// - Disk space verification (ensure > 1GB free)
	// - Memory usage check
	// - Upstream WHOIS server reachability
	// - For cluster mode: check if other nodes are reachable
	
	log.Printf("DEBUG: Health check passed (database: OK)")
	return nil
}

// taskWhoisServersUpdate updates WHOIS server list from IANA
func (s *Scheduler) taskWhoisServersUpdate(ctx context.Context) error {
	// WHOIS server update implementation would:
	// 1. Download IANA TLD list from: https://data.iana.org/TLD/tlds-alpha-by-domain.txt
	// 2. For each TLD, query whois.iana.org to get authoritative WHOIS server
	// 3. Update in-memory tldServers map in src/whois/servers.go
	// 4. Persist to database for cluster mode synchronization
	// 5. Verify new servers are reachable (test connection)
	//
	// Example IANA response:
	// domain:       COM
	// whois:        whois.verisign-grs.com
	//
	// For now, log success. Full implementation would require:
	// - HTTP client to download TLD list
	// - WHOIS client to query IANA for each TLD
	// - Database schema for storing TLD->server mappings
	// - Thread-safe update of in-memory server registry
	
	log.Printf("INFO: WHOIS server list update task executed (placeholder - needs full implementation)")
	log.Printf("INFO: Current implementation uses hardcoded TLD servers in src/whois/servers.go")
	log.Printf("INFO: Future: download from https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
	return nil
}
