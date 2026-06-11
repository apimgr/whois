package server

import (
	"context"
	"crypto/subtle"
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
	"github.com/casapps/caswhois/src/email"
	"github.com/casapps/caswhois/src/geoip"
	caslogger "github.com/casapps/caswhois/src/logger"
	"github.com/casapps/caswhois/src/metrics"
	"github.com/casapps/caswhois/src/ratelimit"
	runtimeinfo "github.com/casapps/caswhois/src/runtime"
	"github.com/casapps/caswhois/src/scheduler"
	castor "github.com/casapps/caswhois/src/tor"
	"github.com/casapps/caswhois/src/whois"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server represents the HTTP server
type Server struct {
	config     *config.ServerConfig
	server     *http.Server
	info       *runtimeinfo.RuntimeInfo
	cache      cache.Cache
	ratelimit  *ratelimit.Limiter
	database   *db.DB
	scheduler  *scheduler.Scheduler
	geoip      *geoip.GeoIPManager
	email      *email.EmailManager
	metrics    *metrics.Collector
	torService *castor.TorService
	// logger manages the four required log files (PART 11).
	logger *caslogger.Logger
	// startTime is the server start time, used for uptime calculation.
	startTime time.Time
	// stats holds atomic runtime counters surfaced via /server/stats.
	stats serverStats
}

// New creates a new Server instance.
// lgr may be nil; logging is silently disabled in that case.
func New(cfg *config.ServerConfig, database *db.DB, lgr *caslogger.Logger) *Server {
	memCache := cache.NewMemoryCache(100*1024*1024, 5*time.Minute)
	rateLimiter := ratelimit.New(60, 1*time.Minute)

	// Initialize scheduler with configurable timezone and catch-up window (AI.md PART 18).
	schedTimezone := cfg.Scheduler.Timezone
	if schedTimezone == "" {
		schedTimezone = "America/New_York"
	}
	schedCatchUp := 1 * time.Hour
	if cfg.Scheduler.CatchUpWindow != "" {
		if d, parseErr := time.ParseDuration(cfg.Scheduler.CatchUpWindow); parseErr == nil {
			schedCatchUp = d
		}
	}
	sched, err := scheduler.New(database.Server, schedTimezone, schedCatchUp)
	if err != nil {
		log.Printf("WARN: Failed to initialize scheduler: %v", err)
		sched = nil
	}

	// Initialize GeoIP (PART 19) — security DBs live under data_dir, not config_dir (AI.md PART 4)
	var geoipMgr *geoip.GeoIPManager
	if cfg.GeoIPDir == "" {
		cfg.GeoIPDir = filepath.Join(cfg.DataDir, "security", "geoip")
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

	// Initialize Metrics (PART 20)
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

	// Initialize Email manager (PART 17)
	emailMgr := email.NewEmailManager(cfg.ConfigDir)
	if cfg.SMTPHost != "" {
		// Explicit SMTP configured — apply settings and test connection
		emailMgr.Configure(
			cfg.SMTPHost,
			cfg.SMTPPort,
			cfg.SMTPUsername,
			cfg.SMTPPassword,
			cfg.SMTPTLSMode,
			cfg.EmailFromName,
			cfg.EmailFromEmail,
		)
		if err := emailMgr.TestConnection(); err != nil {
			log.Printf("[Email] SMTP connection test failed: %v — email features disabled", err)
			emailMgr.Disable()
		} else {
			emailMgr.Enable()
			log.Printf("[Email] SMTP configured and reachable at %s:%d", cfg.SMTPHost, cfg.SMTPPort)
		}
	} else {
		// No explicit SMTP — attempt auto-detection in background
		go func() {
			info := runtimeinfo.Detect()
			detected := emailMgr.AutoDetectSMTP(info.FQDN, info.PrimaryIPv4)
			if detected {
				log.Printf("[Email] SMTP auto-detected at %s — email features enabled", emailMgr.GetSMTPInfo()["host"])
				emailMgr.Enable()
			} else {
				log.Printf("[Email] No local SMTP found — email features disabled")
			}
		}()
	}

	srv := &Server{
		config:    cfg,
		info:      runtimeinfo.Detect(),
		cache:     memCache,
		ratelimit: rateLimiter,
		database:  database,
		scheduler: sched,
		geoip:     geoipMgr,
		email:     emailMgr,
		metrics:   metricsCollector,
		logger:    lgr,
		startTime: time.Now(),
	}

	// Register built-in tasks if scheduler initialized.
	if sched != nil {
		// Wire real implementations for the placeholder built-in tasks
		// (AI.md PART 18) before registering them.
		sched.BackupDailyHook = func(ctx context.Context) error {
			_, err := srv.runBackup("backup")
			return err
		}
		sched.BackupHourlyHook = func(ctx context.Context) error {
			_, err := srv.runBackup("backup-hourly")
			return err
		}
		// Wire GeoIP update hook if GeoIP is enabled (PART 19).
		if geoipMgr != nil && geoipMgr.Enabled() {
			geoCfg := geoip.DatabaseConfig{
				ASN:     cfg.GeoIPDatabaseASN,
				Country: cfg.GeoIPDatabaseCountry,
				City:    cfg.GeoIPDatabaseCity,
				WHOIS:   cfg.GeoIPDatabaseWHOIS,
			}
			sched.GeoIPUpdateHook = func(ctx context.Context) error {
				return geoipMgr.UpdateDatabases(ctx, geoCfg)
			}
		}
		// Wire Tor health hook if Tor is running (PART 31).
		if srv.torService != nil {
			sched.TorHealthHook = func(ctx context.Context) error {
				return srv.torService.Health(ctx)
			}
		}
		// Wire log-rotation hook if the logger is available (PART 11 / PART 18).
		if lgr != nil {
			sched.LogRotateHook = func(_ context.Context) error {
				return lgr.Rotate()
			}
		}
		// SSLRenewHook stays nil until the SSL manager is integrated.

		if err := sched.RegisterBuiltInTasks(); err != nil {
			log.Printf("WARN: Failed to register built-in tasks: %v", err)
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

	// Create HTTP server with configurable timeouts from server.limits (AI.md PART 12).
	addr := fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)
	readTimeout := parseDurationDefault(s.config.Limits.ReadTimeout, 30*time.Second)
	writeTimeout := parseDurationDefault(s.config.Limits.WriteTimeout, 30*time.Second)
	idleTimeout := parseDurationDefault(s.config.Limits.IdleTimeout, 120*time.Second)
	s.server = &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
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

	// Start Tor hidden service (PART 31) — non-blocking, optional
	// Tor starts after the HTTP listener is already running so ADD_ONION can forward to it.
	torCtx, torCancel := context.WithCancel(context.Background())
	defer torCancel()
	go func() {
		torCfg := castor.TorConfig{
			Binary:                    s.config.TorBinary,
			UseNetwork:                s.config.TorUseNetwork,
			MaxCircuits:               s.config.TorMaxCircuits,
			CircuitTimeout:            s.config.TorCircuitTimeout,
			BootstrapTimeout:          s.config.TorBootstrapTimeout,
			SafeLogging:               s.config.TorSafeLogging,
			MaxStreamsPerCircuit:       s.config.TorMaxStreamsPerCircuit,
			CloseCircuitOnStreamLimit: s.config.TorCloseCircuitOnStreamLimit,
			BandwidthRate:             s.config.TorBandwidthRate,
			BandwidthBurst:            s.config.TorBandwidthBurst,
			MaxMonthlyBandwidth:       s.config.TorMaxMonthlyBandwidth,
			NumIntroPoints:            s.config.TorNumIntroPoints,
			VirtualPort:               s.config.TorVirtualPort,
		}
		svc, err := castor.Start(torCtx, s.config.Port, &torCfg, s.config.ConfigDir, s.config.DataDir)
		if err != nil {
			log.Printf("[Tor] bootstrap failed: %v", err)
			return
		}
		if svc != nil {
			s.torService = svc
		}
	}()

	// Channel for OS signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	// SIGUSR1 reopens log files so external rotation tools (logrotate) can work.
	rotateSig := make(chan os.Signal, 1)
	signal.Notify(rotateSig, syscall.SIGUSR1)
	go func() {
		for range rotateSig {
			if s.logger != nil {
				if err := s.logger.Rotate(); err != nil {
					log.Printf("ERROR: log rotation failed: %v", err)
				} else {
					log.Printf("Log files reopened (SIGUSR1)")
				}
			}
		}
	}()

	// Wait for shutdown signal or server error
	select {
	case err := <-serverErrors:
		return fmt.Errorf("server error: %w", err)
	case sig := <-shutdown:
		log.Printf("Received signal %v, shutting down gracefully...", sig)

		// Stop Tor first (PART 31)
		torCancel()
		if s.torService != nil {
			if err := s.torService.Close(); err != nil {
				log.Printf("[Tor] shutdown error: %v", err)
			}
		}

		// Stop scheduler (AI.md PART 19)
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

	// Metrics endpoint (PART 20) - INTERNAL ONLY, token-protected
	if s.metrics != nil && s.config.MetricsEnabled {
		endpoint := s.config.MetricsEndpoint
		if endpoint == "" {
			endpoint = "/metrics"
		}
		mux.Handle(endpoint, s.handleMetrics())
		log.Printf("[Metrics] Endpoint enabled at %s", endpoint)
	}

	// Health check endpoints (PART 13)
	mux.HandleFunc("/server/healthz", s.handleHealth)
	mux.HandleFunc("/api/v1/server/healthz", s.handleHealth)
	// Root alias when enabled
	mux.HandleFunc("/healthz", s.handleHealth)

	// Static assets — CSS, JS (embedded at compile time, served under /static/)
	mux.Handle("/static/", staticFileServer())

	// SEO & Security files (PART 14, PART 16) - REQUIRED
	mux.HandleFunc("/.well-known/security.txt", s.handleSecurityTxt)
	mux.HandleFunc("/sitemap.xml", s.handleSitemap)
	mux.HandleFunc("/robots.txt", s.handleRobotsTxt)

	// PWA support (PART 16) — manifest, service worker, offline fallback
	mux.HandleFunc("/manifest.json", s.handleManifest)
	mux.HandleFunc("/sw.js", s.handleServiceWorker)
	mux.HandleFunc("/offline.html", s.handleOfflinePage)

	// Public web interface — exact root only (Go 1.22+ /{$} syntax)
	mux.HandleFunc("/{$}", s.handlePublicWHOISPage)

	// Catch-all 404 for all unmatched paths (must be last)
	mux.HandleFunc("/", s.handleNotFound)

	// Public content pages
	mux.HandleFunc("/server/about", s.handleAboutPage)
	mux.HandleFunc("/about", s.handleAboutPage)
	mux.HandleFunc("/server/docs", s.handleDocsPage)
	mux.HandleFunc("/docs", s.handleDocsPage)

	// WHOIS lookup form-submission fallback (no-JS browsers, curl, wget)
	mux.HandleFunc("/whois", s.handleWHOISPage)

	// API v1 - WHOIS lookups (public, rate-limited)
	mux.HandleFunc("/api/v1/whois/", s.handleWHOIS)
	mux.HandleFunc("/api/v1/whois/domain/", s.handleWHOISDomainLookup)
	mux.HandleFunc("/api/v1/whois/ip/", s.handleWHOISIPLookup)
	mux.HandleFunc("/api/v1/whois/asn/", s.handleWHOISASNLookup)
	mux.HandleFunc("/api/v1/whois/validate/", s.handleWHOISValidate)

	// API v1 - Bulk lookup (requires server token)
	mux.HandleFunc("/api/v1/whois/bulk", s.requireToken(s.handleWHOISBulkLookup))

	// Autodiscover endpoint (PART 32) — non-versioned, public
	mux.HandleFunc("/api/autodiscover", s.handleAutodiscover)

	// CLI binary download (PART 32) — public by default; streams prebuilt binaries
	mux.HandleFunc("/cli/binaries/", s.handleCLIBinaryDownload)

	// Locale JSON files (PART 30) — served for JS consumers; content from embedded i18n files
	mux.HandleFunc("/locales/", s.handleLocaleJSON)

	// API v1 - Utility (public)
	mux.HandleFunc("/api/v1/whois-servers", s.handleWhoisServers)
	mux.HandleFunc("/api/v1/server/stats", s.handleStats)

	// API v1 - Server operations (requires server token)
	mux.HandleFunc("/api/v1/server/schedulers", s.requireToken(s.handleSchedulerStatus))
	mux.HandleFunc("/api/v1/server/schedulers/run", s.requireToken(s.handleSchedulerRun))
	mux.HandleFunc("/api/v1/server/backups", s.requireToken(s.handleBackupStatus))
	mux.HandleFunc("/api/v1/server/backups/run", s.requireToken(s.handleBackupRun))

	// Debug endpoints (PART 6) — registered only when --debug / DEBUG=true
	s.registerDebugRoutes(mux)

	return mux
}

// setupMiddleware configures middleware chain
// Order matters - security first!
func (s *Server) setupMiddleware(handler http.Handler) http.Handler {
	// Middleware is applied innermost-first; the outermost wrapper (last line)
	// runs first on the request and last on the response. Order matters —
	// see comments above each wrapper for the layer they implement.
	if s.metrics != nil {
		// 7. Metrics collection — outermost so it sees every request.
		handler = s.metrics.HTTPMiddleware(handler)
	}
	// 7. Access log.
	handler = s.LoggingMiddleware(handler)
	// 6. Authentication.
	handler = AuthMiddleware(handler)
	// 5. Rate limiting.
	handler = RateLimitMiddleware(s.ratelimit)(handler)
	// 4. Request-language detection.
	handler = LanguageMiddleware(handler)
	// 3. Security response headers.
	handler = SecurityHeadersMiddleware(handler)
	// 2. Path validation / traversal block.
	handler = PathSecurityMiddleware(handler)
	// 1a. CORS headers for API paths — before URL normalization so preflight
	//     OPTIONS returns correct headers without entering route handlers.
	handler = CORSMiddleware(s.config.Web.CORS)(handler)
	// 1. URL normalization — runs first.
	handler = URLNormalizeMiddleware(handler)
	return handler
}

// handleWHOIS handles WHOIS lookup requests.
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

// getPIDFilePath returns the PID file path based on privilege level (AI.md PART 23).
func (s *Server) getPIDFilePath() string {
	// System-wide PID file when running as root.
	if os.Geteuid() == 0 {
		return "/var/run/casapps/caswhois.pid"
	}
	// User-specific PID file otherwise.
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".local", "share", "casapps", "caswhois", "caswhois.pid")
}


// handleMetrics returns the Prometheus metrics handler.
// PART 20: /metrics endpoint (INTERNAL ONLY — never proxy to public).
// When metrics.token is set the Authorization header is validated with
// constant-time comparison (AI.md PART 11) to prevent timing attacks.
func (s *Server) handleMetrics() http.Handler {
	handler := promhttp.Handler()

	// If token is configured, require bearer authentication.
	if s.config.MetricsToken != "" {
		expected := []byte("Bearer " + s.config.MetricsToken)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Constant-time comparison prevents timing oracle on the token.
			got := []byte(r.Header.Get("Authorization"))
			if subtle.ConstantTimeCompare(got, expected) != 1 {
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
	sitemapURL := fmt.Sprintf("http://localhost:%d/sitemap.xml", s.config.Port)
	if s.config.FQDN != "" {
		sitemapURL = "https://" + s.config.FQDN + "/sitemap.xml"
	}

	content := fmt.Sprintf("User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: %s\n", sitemapURL)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, content)
}


// parseDurationDefault parses a duration string (e.g. "30s", "2m") and returns
// fallback if the string is empty or invalid.
func parseDurationDefault(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}
