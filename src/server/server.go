package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/casapps/caswhois/src/cache"
	"github.com/casapps/caswhois/src/config"
	"github.com/casapps/caswhois/src/db"
	"github.com/casapps/caswhois/src/geoip"
	"github.com/casapps/caswhois/src/metrics"
	"github.com/casapps/caswhois/src/ratelimit"
	runtimeinfo "github.com/casapps/caswhois/src/runtime"
	"github.com/casapps/caswhois/src/scheduler"
	"github.com/casapps/caswhois/src/whois"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server represents the HTTP server
type Server struct {
	config    *config.ServerConfig
	server    *http.Server
	info      *runtimeinfo.Info
	cache     cache.Cache
	ratelimit *ratelimit.Limiter
	database  *db.DB
	scheduler *scheduler.Scheduler
	geoip     *geoip.GeoIPManager
	metrics   *metrics.Collector
	startTime time.Time // Server start time for uptime calculation
}

// New creates a new Server instance
func New(cfg *config.ServerConfig, database *db.DB) *Server {
	memCache := cache.NewMemoryCache(100*1024*1024, 5*time.Minute)
	rateLimiter := ratelimit.New(60, 1*time.Minute)

	// Initialize scheduler with database
	// Timezone defaults to America/New_York per AI.md PART 19
	// Catch-up window is 1 hour
	sched, err := scheduler.New(database.Server, "America/New_York", 1*time.Hour)
	if err != nil {
		log.Printf("WARN: Failed to initialize scheduler: %v", err)
		sched = nil
	}

	// Initialize GeoIP (PART 20)
	var geoipMgr *geoip.GeoIPManager
	if cfg.GeoIPDir == "" {
		cfg.GeoIPDir = filepath.Join(cfg.ConfigDir, "security", "geoip")
	}
	geoipCfg := geoip.GeoIPConfig{
		Enabled: cfg.GeoIPEnabled,
		Dir:     cfg.GeoIPDir,
		Databases: geoip.DatabaseConfig{
			ASN:     cfg.GeoIPDatabaseASN,
			Country: cfg.GeoIPDatabaseCountry,
			City:    cfg.GeoIPDatabaseCity,
			WHOIS:   cfg.GeoIPDatabaseWHOIS,
		},
	}
	geoipMgr, err = geoip.NewGeoIPManager(geoipCfg)
	if err != nil {
		log.Printf("WARN: Failed to initialize GeoIP: %v", err)
		geoipMgr = nil
	}

	// Initialize Metrics (PART 21)
	metricsCfg := metrics.MetricsConfig{
		Enabled:        cfg.MetricsEnabled,
		Endpoint:       cfg.MetricsEndpoint,
		IncludeSystem:  cfg.MetricsIncludeSystem,
		IncludeRuntime: cfg.MetricsIncludeRuntime,
		Token:          cfg.MetricsToken,
	}
	metricsCollector := metrics.New("caswhois", metricsCfg)
	if metricsCollector != nil {
		// Set application info from build variables (will be set by main.go)
		metricsCollector.SetAppInfo("0.1.0", "dev", "unknown", "go1.21")
		log.Println("[Metrics] Initialized")
	}

	srv := &Server{
		config:    cfg,
		info:      runtimeinfo.Detect(),
		cache:     memCache,
		ratelimit: rateLimiter,
		database:  database,
		scheduler: sched,
		geoip:     geoipMgr,
		metrics:   metricsCollector,
		startTime: time.Now(),
	}

	// Register built-in tasks if scheduler initialized
	if sched != nil {
		if err := sched.RegisterBuiltInTasks(); err != nil {
			log.Printf("WARN: Failed to register built-in tasks: %v", err)
		}

		// Register GeoIP update task if GeoIP is enabled
		if geoipMgr != nil && geoipMgr.Enabled() {
			if err := srv.registerGeoIPTask(); err != nil {
				log.Printf("WARN: Failed to register GeoIP task: %v", err)
			}
		}
	}

	return srv
}

// Start starts the HTTP server
func (s *Server) Start() error {
	// Get PID file path
	pidPath := s.getPIDFilePath()

	// Check for existing running instance
	running, existingPID, err := CheckPIDFile(pidPath)
	if err != nil {
		return fmt.Errorf("error checking pid file: %w", err)
	}
	if running {
		return fmt.Errorf("server already running (pid %d)", existingPID)
	}

	// Write PID file with port
	if err := WritePIDFile(pidPath, s.config.Port); err != nil {
		return fmt.Errorf("failed to write pid file: %w", err)
	}

	// Ensure PID file is removed on exit
	defer RemovePIDFile(pidPath)

	// Setup routes and middleware
	handler := s.setupRoutes()
	handler = s.setupMiddleware(handler)

	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)
	s.server = &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Log runtime information
	log.Printf("=== Runtime Information ===")
	log.Printf("Hostname: %s", s.info.Hostname)
	log.Printf("FQDN: %s", s.info.FQDN)
	log.Printf("CPU Cores: %d", s.info.CPUCores)
	if s.info.PrimaryIPv4 != "" {
		log.Printf("Primary IPv4: %s", s.info.PrimaryIPv4)
	}
	if s.info.PrimaryIPv6 != "" {
		log.Printf("Primary IPv6: %s", s.info.PrimaryIPv6)
	}
	log.Printf("===========================")

	// Start scheduler if initialized (AI.md PART 19 - ALWAYS RUNNING)
	if s.scheduler != nil {
		if err := s.scheduler.Start(); err != nil {
			log.Printf("ERROR: Failed to start scheduler: %v", err)
		} else {
			log.Printf("Scheduler started with 8 built-in tasks")
		}
	}

	// Channel for server errors
	serverErrors := make(chan error, 1)

	// Start server in goroutine
	go func() {
		log.Printf("Server starting on %s", addr)
		serverErrors <- s.server.ListenAndServe()
	}()

	// Channel for OS signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal or server error
	select {
	case err := <-serverErrors:
		return fmt.Errorf("server error: %w", err)
	case sig := <-shutdown:
		log.Printf("Received signal %v, shutting down gracefully...", sig)

		// Stop scheduler first (AI.md PART 19)
		if s.scheduler != nil {
			log.Printf("Stopping scheduler...")
			if err := s.scheduler.Stop(); err != nil {
				log.Printf("ERROR: Failed to stop scheduler: %v", err)
			} else {
				log.Printf("Scheduler stopped")
			}
		}

		// Give outstanding requests a deadline for completion
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Graceful shutdown
		if err := s.server.Shutdown(ctx); err != nil {
			// Force close
			s.server.Close()
			return fmt.Errorf("could not stop server gracefully: %w", err)
		}
	}

	return nil
}

// setupRoutes configures HTTP routes
func (s *Server) setupRoutes() http.Handler {
	mux := http.NewServeMux()

	// Metrics endpoint (AI.md PART 21) - INTERNAL ONLY
	// Should be protected by firewall or bearer token
	if s.metrics != nil && s.config.MetricsEnabled {
		endpoint := s.config.MetricsEndpoint
		if endpoint == "" {
			endpoint = "/metrics"
		}
		mux.Handle(endpoint, s.handleMetrics())
		log.Printf("[Metrics] Endpoint enabled at %s", endpoint)
	}

	// Health check endpoints (AI.md PART 13)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/api/v1/healthz", s.handleHealth)

	// Legacy health endpoint (keep for backward compatibility)
	mux.HandleFunc("/health", s.handleHealth)

	// SEO & Security files (AI.md PART 14, PART 16) - REQUIRED
	mux.HandleFunc("/.well-known/security.txt", s.handleSecurityTxt)
	mux.HandleFunc("/sitemap.xml", s.handleSitemap)
	mux.HandleFunc("/robots.txt", s.handleRobotsTxt)

	// Public web interface - WHOIS lookup page at root
	mux.HandleFunc("/", s.handlePublicWHOISPage)

	// Public content pages
	mux.HandleFunc("/about", s.handleAboutPage)
	mux.HandleFunc("/docs", s.handleDocsPage)

	// API v1 endpoints - WHOIS (general)
	mux.HandleFunc("/api/v1/whois/", s.handleWHOIS)

	// API v1 endpoints - WHOIS (specific)
	mux.HandleFunc("/api/v1/whois/domain/", s.handleWHOISDomainLookup)
	mux.HandleFunc("/api/v1/whois/ip/", s.handleWHOISIPLookup)
	mux.HandleFunc("/api/v1/whois/asn/", s.handleWHOISASNLookup)
	mux.HandleFunc("/api/v1/whois/validate/", s.handleWHOISValidate)

	// API v1 endpoints - WHOIS (bulk)
	// Note: Bulk lookup should require authentication in production
	mux.HandleFunc("/api/v1/whois/bulk", s.handleWHOISBulkLookup)

	// API v1 endpoints - Utility
	mux.HandleFunc("/api/v1/whois-servers", s.handleWhoisServers)
	mux.HandleFunc("/api/v1/stats", s.handleStats)

	// Auth endpoints (AI.md PART 17)
	mux.HandleFunc("/auth/login", s.handleAuthLogin)
	mux.HandleFunc("/auth/logout", s.handleAuthLogout)

	// Admin setup endpoints (AI.md PART 17)
	adminPath := s.config.AdminPath
	if adminPath == "" {
		adminPath = "admin"
	}
	
	// Setup wizard page (no auth required)
	mux.HandleFunc(fmt.Sprintf("/%s/server/setup", adminPath), s.handleAdminSetupPage)
	
	// Setup wizard API endpoints (no auth required)
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/server/setup", adminPath), s.handleAdminSetupStatus)
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/server/setup/verify", adminPath), s.handleAdminSetupVerify)
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/server/setup/account", adminPath), s.handleAdminSetupAccount)
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/server/setup/complete", adminPath), s.handleAdminSetupComplete)

	// Admin dashboard (requires authentication)
	mux.HandleFunc(fmt.Sprintf("/%s/dashboard", adminPath), s.RequireAdminSession(s.handleAdminDashboard))
	mux.HandleFunc(fmt.Sprintf("/%s", adminPath), s.RequireAdminSession(s.handleAdminDashboard))

	// Admin profile routes (PART 17: /{admin_path}/profile for admin's OWN settings)
	mux.HandleFunc(fmt.Sprintf("/%s/profile", adminPath), s.RequireAdminSession(s.handleAdminProfile))
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/profile", adminPath), s.RequireAdminSession(s.handleAdminProfileAPI))
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/profile/update", adminPath), s.RequireAdminSession(s.handleAdminProfileUpdate))
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/profile/password", adminPath), s.RequireAdminSession(s.handleAdminPasswordChange))
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/profile/token", adminPath), s.RequireAdminSession(s.handleAdminAPIToken))
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/profile/token/regenerate", adminPath), s.RequireAdminSession(s.handleAdminAPITokenRegenerate))

	// Server settings (requires authentication)
	mux.HandleFunc(fmt.Sprintf("/%s/server/settings", adminPath), s.RequireAdminSession(s.handleServerSettings))
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/server/settings", adminPath), s.RequireAdminSession(s.handleServerSettingsAPI))

	// SSL configuration (requires authentication)
	mux.HandleFunc(fmt.Sprintf("/%s/server/ssl", adminPath), s.RequireAdminSession(s.handleServerSSLSettings))
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/server/ssl", adminPath), s.RequireAdminSession(s.handleServerSSLSettingsAPI))

	// Email/SMTP configuration (requires authentication)
	mux.HandleFunc(fmt.Sprintf("/%s/server/email", adminPath), s.RequireAdminSession(s.handleServerEmailSettings))
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/server/email", adminPath), s.RequireAdminSession(s.handleServerEmailSettingsAPI))
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/server/email/test", adminPath), s.RequireAdminSession(s.handleServerEmailTest))

	// Backup configuration (requires authentication)
	mux.HandleFunc(fmt.Sprintf("/%s/server/backup", adminPath), s.RequireAdminSession(s.handleServerBackupSettings))
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/server/backup", adminPath), s.RequireAdminSession(s.handleServerBackupSettingsAPI))
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/server/backup/now", adminPath), s.RequireAdminSession(s.handleServerBackupNow))

	// Scheduler management (requires authentication)
	mux.HandleFunc(fmt.Sprintf("/%s/server/scheduler", adminPath), s.RequireAdminSession(s.handleServerSchedulerSettings))
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/server/scheduler", adminPath), s.RequireAdminSession(s.handleServerSchedulerStatusAPI))
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/server/scheduler/task", adminPath), s.RequireAdminSession(s.handleServerSchedulerTaskUpdate))
	mux.HandleFunc(fmt.Sprintf("/api/v1/%s/server/scheduler/task/run", adminPath), s.RequireAdminSession(s.handleServerSchedulerTaskRun))

	return mux
}

// setupMiddleware configures middleware chain
// Order matters - security first!
func (s *Server) setupMiddleware(handler http.Handler) http.Handler {
	// Wrap with metrics middleware first (outermost) to capture all requests
	if s.metrics != nil {
		handler = s.metrics.HTTPMiddleware(handler)        // 7. Metrics collection
	}
	handler = LoggingMiddleware(handler)               // 6. Log requests
	handler = AuthMiddleware(handler)                  // 5. Check auth
	handler = RateLimitMiddleware(s.ratelimit)(handler) // 4. Rate limiting
	handler = SecurityHeadersMiddleware(handler)       // 3. Add security headers
	handler = PathSecurityMiddleware(handler)          // 2. Validate paths, block traversal
	handler = URLNormalizeMiddleware(handler)          // 1. FIRST - normalize URLs
	return handler
}

// handleHealth handles health check requests
// handleRoot handles root requests
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"service":     "caswhois",
		"description": "WHOIS lookup service",
		"version":     "0.1.0",
		"endpoints": []string{
			"/healthz - Health check",
			"/api/v1/healthz - API health check",
			"/api/v1/whois/{query} - WHOIS lookup",
			"/api/v1/whois-servers - List WHOIS servers",
			"/api/v1/stats - Service statistics",
		},
	}

	SendSuccess(w, data)
}

// handleWHOIS handles WHOIS lookup requests
func (s *Server) handleWHOIS(w http.ResponseWriter, r *http.Request) {
	// Extract query from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/whois/")
	query := strings.TrimSpace(path)

	if query == "" {
		SendError(w, ErrBadRequest, "Query parameter required")
		return
	}

	// Validate query
	if err := whois.ValidateQuery(query); err != nil {
		SendError(w, ErrValidationFailed, fmt.Sprintf("Invalid query: %v", err))
		return
	}

	// Perform WHOIS lookup with cache
	result, err := whois.QueryWHOISWithCache(r.Context(), query, s.cache)
	if err != nil {
		SendError(w, ErrServerError, fmt.Sprintf("WHOIS lookup failed: %v", err))
		return
	}

	// Build response
	data := map[string]interface{}{
		"query":     result.Query,
		"type":      result.Type.String(),
		"server":    result.Server,
		"timestamp": result.Timestamp.Format(time.RFC3339),
		"raw":       result.Raw,
	}

	// Add parsed data if available
	if result.Domain != nil {
		data["domain"] = result.Domain
	}
	if result.IP != nil {
		data["ip"] = result.IP
	}
	if result.ASN != nil {
		data["asn"] = result.ASN
	}

	SendSuccess(w, data)
}

// getPIDFilePath returns the PID file path based on privilege level
func (s *Server) getPIDFilePath() string {
// Check if running as root
if os.Geteuid() == 0 {
// System-wide PID file
return "/var/run/casapps/caswhois.pid"
}

// User-specific PID file
homeDir, _ := os.UserHomeDir()
return filepath.Join(homeDir, ".local", "share", "casapps", "caswhois", "caswhois.pid")
}

// registerGeoIPTask registers the GeoIP database update task
// PART 20: Weekly on Sunday 03:00
func (s *Server) registerGeoIPTask() error {
	cfg := geoip.DatabaseConfig{
		ASN:     s.config.GeoIPDatabaseASN,
		Country: s.config.GeoIPDatabaseCountry,
		City:    s.config.GeoIPDatabaseCity,
		WHOIS:   s.config.GeoIPDatabaseWHOIS,
	}

	return s.scheduler.Register(&scheduler.Task{
		ID:       "geoip.update",
		Name:     "GeoIP Database Update",
		Schedule: "0 3 * * 0", // Weekly on Sunday at 03:00 (cron format)
		Enabled:  true,
		Global:   true,
		Handler: func(ctx context.Context) error {
			return s.geoip.UpdateDatabases(ctx, cfg)
		},
		RetryPolicy: &scheduler.RetryPolicy{
			MaxRetries: 3,
			RetryDelay: 30 * time.Minute,
			Backoff:    "exponential",
		},
	})
}

// handleMetrics returns the Prometheus metrics handler
// PART 21: /metrics endpoint (INTERNAL ONLY)
func (s *Server) handleMetrics() http.Handler {
	handler := promhttp.Handler()

	// If token is configured, require bearer authentication
	if s.config.MetricsToken != "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check Authorization header
			authHeader := r.Header.Get("Authorization")
			expectedAuth := "Bearer " + s.config.MetricsToken

			if authHeader != expectedAuth {
				w.Header().Set("WWW-Authenticate", `Bearer realm="Metrics"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Update system metrics before serving
			if s.metrics != nil {
				s.metrics.UpdateSystemMetrics()
			}

			handler.ServeHTTP(w, r)
		})
	}

	// No authentication - update system metrics and serve
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.metrics != nil {
			s.metrics.UpdateSystemMetrics()
		}
		handler.ServeHTTP(w, r)
	})
}

// handleSecurityTxt serves security.txt file (AI.md PART 14)
// REQUIRED: ALL projects MUST serve a valid security.txt file
func (s *Server) handleSecurityTxt(w http.ResponseWriter, r *http.Request) {
	// Default contact email
	contact := "security@" + s.config.FQDN
	if contact == "security@" {
		contact = "security@localhost"
	}

	// Expiry date: 1 year from now
	expiryDate := time.Now().AddDate(1, 0, 0).Format("2006-01-02T15:04:05Z")

	// Generate security.txt content
	content := fmt.Sprintf(`# Security Contact Information
Contact: mailto:%s
Expires: %s
Preferred-Languages: en
`, contact, expiryDate)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, content)
}

// handleSitemap serves dynamically generated sitemap.xml (AI.md PART 16)
// REQUIRED: ALL projects MUST serve a dynamically generated sitemap
func (s *Server) handleSitemap(w http.ResponseWriter, r *http.Request) {
	// Base URL
	baseURL := "http://localhost:" + fmt.Sprintf("%d", s.config.Port)
	if s.config.FQDN != "" {
		baseURL = "https://" + s.config.FQDN
	}

	// Last modified date
	lastMod := time.Now().Format("2006-01-02")

	// Generate sitemap XML
	content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>%s/</loc>
    <lastmod>%s</lastmod>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>%s/about</loc>
    <lastmod>%s</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>%s/docs</loc>
    <lastmod>%s</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>
`, baseURL, lastMod, baseURL, lastMod, baseURL, lastMod)

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, content)
}

// handleRobotsTxt serves robots.txt file (AI.md PART 14)
func (s *Server) handleRobotsTxt(w http.ResponseWriter, r *http.Request) {
	adminPath := s.config.AdminPath
	if adminPath == "" {
		adminPath = "admin"
	}

	// Generate robots.txt content
	content := fmt.Sprintf(`User-agent: *
Allow: /
Disallow: /%s/
Disallow: /auth/
Disallow: /api/

Sitemap: http://localhost:%d/sitemap.xml
`, adminPath, s.config.Port)

	// Use FQDN if available
	if s.config.FQDN != "" {
		content = fmt.Sprintf(`User-agent: *
Allow: /
Disallow: /%s/
Disallow: /auth/
Disallow: /api/

Sitemap: https://%s/sitemap.xml
`, adminPath, s.config.FQDN)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, content)
}

