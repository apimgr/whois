package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/apimgr/whois/src/cache"
	"github.com/apimgr/whois/src/common/constants"
	"github.com/apimgr/whois/src/config"
	"github.com/apimgr/whois/src/db"
	"github.com/apimgr/whois/src/email"
	"github.com/apimgr/whois/src/geoip"
	caslogger "github.com/apimgr/whois/src/logger"
	"github.com/apimgr/whois/src/metrics"
	"github.com/apimgr/whois/src/ratelimit"
	runtimeinfo "github.com/apimgr/whois/src/runtime"
	"github.com/apimgr/whois/src/scheduler"
	casssl "github.com/apimgr/whois/src/ssl"
	castor "github.com/apimgr/whois/src/tor"
	"github.com/apimgr/whois/src/whois"
	"github.com/apimgr/whois/src/whois/records"
	"github.com/go-chi/chi/v5"
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
	// lookupService handles RDAP-first lookups with WHOIS fallback
	lookupService *whois.LookupService
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

	// Initialize GeoIP (AI.md PART 19 — server.geoip.*).
	// Security DBs live under data_dir, not config_dir (AI.md PART 4).
	var geoipMgr *geoip.GeoIPManager
	if cfg.GeoIP.Dir == "" {
		cfg.GeoIP.Dir = filepath.Join(cfg.DataDir, "security", "geoip")
	}
	geoipCfg := geoip.GeoIPConfig{
		Enabled: cfg.GeoIP.Enabled,
		Dir:     cfg.GeoIP.Dir,
		Databases: geoip.DatabaseConfig{
			ASN:     cfg.GeoIP.Databases.ASN,
			Country: cfg.GeoIP.Databases.Country,
			City:    cfg.GeoIP.Databases.City,
			WHOIS:   cfg.GeoIP.Databases.WHOIS,
		},
	}
	geoipMgr, err = geoip.NewGeoIPManager(geoipCfg)
	if err != nil {
		log.Printf("WARN: Failed to initialize GeoIP: %v", err)
		geoipMgr = nil
	}

	// Initialize Metrics (PART 20)
	metricsCfg := metrics.MetricsConfig{
		Enabled:        cfg.Metrics.Enabled,
		Endpoint:       cfg.Metrics.Endpoint,
		IncludeSystem:  cfg.Metrics.IncludeSystem,
		IncludeRuntime: cfg.Metrics.IncludeRuntime,
		Token:          cfg.Metrics.Token,
	}
	metricsCollector := metrics.New(constants.InternalName, metricsCfg)
	if metricsCollector != nil {
		// Set application info from build variables (will be set by main.go)
		metricsCollector.SetAppInfo("0.1.0", "dev", "unknown", "go1.21")
		log.Println("[Metrics] Initialized")
	}

	// Initialize Email manager (AI.md PART 17 — server.notifications.email.smtp.*).
	emailMgr := email.NewEmailManager(cfg.ConfigDir)
	smtp := cfg.Notifications.Email.SMTP
	from := cfg.Notifications.Email.From
	if smtp.Host != "" {
		// Explicit SMTP configured — apply settings and test connection.
		emailMgr.Configure(
			smtp.Host,
			smtp.Port,
			smtp.Username,
			smtp.Password,
			smtp.TLS,
			from.Name,
			from.Email,
		)
		if err := emailMgr.TestConnection(); err != nil {
			log.Printf("[Email] SMTP connection test failed: %v — email features disabled", err)
			emailMgr.Disable()
		} else {
			emailMgr.Enable()
			log.Printf("[Email] SMTP configured and reachable at %s:%d", smtp.Host, smtp.Port)
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

	// Initialize WHOIS/RDAP lookup service (AI.md IDEA.md — RDAP support).
	lookupSvc := whois.NewLookupService(cfg.DataDir, memCache)
	if err := lookupSvc.LoadBootstrap(); err != nil {
		log.Printf("INFO: RDAP bootstrap not available: %v — will use WHOIS only until bootstrap is fetched", err)
	} else if lookupSvc.HasRDAPData() {
		log.Println("[WHOIS] RDAP bootstrap loaded — using RDAP-first strategy")
	}

	srv := &Server{
		config:        cfg,
		info:          runtimeinfo.Detect(),
		cache:         memCache,
		ratelimit:     rateLimiter,
		database:      database,
		scheduler:     sched,
		geoip:         geoipMgr,
		email:         emailMgr,
		metrics:       metricsCollector,
		logger:        lgr,
		startTime:     time.Now(),
		lookupService: lookupSvc,
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
				ASN:     cfg.GeoIP.Databases.ASN,
				Country: cfg.GeoIP.Databases.Country,
				City:    cfg.GeoIP.Databases.City,
				WHOIS:   cfg.GeoIP.Databases.WHOIS,
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

		// Wire WHOIS records refresh hook — re-queries stale permanent records (PART 14).
		if srv.database != nil {
			sched.WhoisRefreshHook = func(ctx context.Context, queries []string) error {
				for _, q := range queries {
					result, qErr := whois.QueryWHOISWithCache(ctx, q, srv.cache)
					if qErr != nil {
						continue
					}
					if result.Domain == nil {
						continue
					}
					if upErr := records.UpsertRecord(ctx, srv.database.Server, q, result.Type.String(), result.Domain); upErr != nil {
						return upErr
					}
				}
				return nil
			}
		}

		// Wire RDAP bootstrap update hook (IDEA.md — RDAP support).
		sched.RDAPBootstrapHook = func(ctx context.Context) error {
			return srv.lookupService.UpdateBootstrap(ctx)
		}

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

	// Bind the listener while still privileged so ports below 1024 can be
	// claimed, then drop to the unprivileged service account before serving
	// any request (AI.md PART 23 — bind privileged port, then drop privileges).
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind %s: %w", addr, err)
	}

	// When SSL is enabled, wrap the listener with TLS (AI.md PART 15).
	// TLS 1.2 is the minimum version; 1.3 is preferred.
	if s.config.TLS.Enabled {
		fqdn := s.config.TLS.Domain
		if fqdn == "" {
			fqdn = s.config.FQDN
		}
		certMgr := casssl.NewCertManager(s.config.ConfigDir, fqdn)
		if loadErr := certMgr.LoadCertificate(); loadErr != nil {
			log.Printf("WARN: TLS cert not found (%v); requesting from Let's Encrypt", loadErr)
			if reqErr := certMgr.RequestNewCertificate(); reqErr != nil {
				listener.Close()
				return fmt.Errorf("TLS certificate unavailable: %w", reqErr)
			}
		}
		minTLS := uint16(tls.VersionTLS12)
		if s.config.TLS.MinVersion == "1.3" {
			minTLS = tls.VersionTLS13
		}
		tlsCfg := &tls.Config{
			GetCertificate: certMgr.GetCertificate,
			MinVersion:     minTLS,
		}
		listener = tls.NewListener(listener, tlsCfg)

		// Start HTTP→HTTPS redirect server on port 80 (AI.md PART 15).
		redirectMux := http.NewServeMux()
		redirectMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})
		redirectSrv := &http.Server{
			Addr:         s.config.Address + ":80",
			Handler:      redirectMux,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
		}
		go func() {
			log.Printf("HTTP→HTTPS redirect listening on %s:80", s.config.Address)
			if listenErr := redirectSrv.ListenAndServe(); listenErr != nil && listenErr != http.ErrServerClosed {
				log.Printf("WARN: HTTP redirect server error: %v", listenErr)
			}
		}()
	}

	if err := dropPrivileges(s.config.User, s.config.Group); err != nil {
		listener.Close()
		return fmt.Errorf("failed to drop privileges: %w", err)
	}

	// Channel for server errors
	serverErrors := make(chan error, 1)

	// Start server in goroutine
	go func() {
		log.Printf("Server starting on %s", addr)
		serverErrors <- s.server.Serve(listener)
	}()

	// Start Tor hidden service (PART 31) — non-blocking, optional
	// Tor starts after the HTTP listener is already running so ADD_ONION can forward to it.
	torCtx, torCancel := context.WithCancel(context.Background())
	defer torCancel()
	go func() {
		torCfg := castor.TorConfig{
			Binary:                    s.config.Tor.Binary,
			UseNetwork:                s.config.Tor.UseNetwork,
			MaxCircuits:               s.config.Tor.MaxCircuits,
			CircuitTimeout:            s.config.Tor.CircuitTimeout,
			BootstrapTimeout:          s.config.Tor.BootstrapTimeout,
			SafeLogging:               s.config.Tor.SafeLogging,
			MaxStreamsPerCircuit:       s.config.Tor.MaxStreamsPerCircuit,
			CloseCircuitOnStreamLimit: s.config.Tor.CloseCircuitOnStreamLimit,
			BandwidthRate:             s.config.Tor.BandwidthRate,
			BandwidthBurst:            s.config.Tor.BandwidthBurst,
			MaxMonthlyBandwidth:       s.config.Tor.MaxMonthlyBandwidth,
			NumIntroPoints:            s.config.Tor.NumIntroPoints,
			VirtualPort:               s.config.Tor.VirtualPort,
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

	// SIGUSR1 (log rotation) and SIGHUP (config reload) — Unix only.
	setupExtraSignals(s)

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

// setupRoutes configures HTTP routes using chi (PART 13 — every web page has a corresponding API endpoint).
func (s *Server) setupRoutes() http.Handler {
	r := chi.NewRouter()

	// Metrics endpoint (PART 20) — internal only, token-protected
	if s.metrics != nil && s.config.Metrics.Enabled {
		endpoint := s.config.Metrics.Endpoint
		if endpoint == "" {
			endpoint = "/metrics"
		}
		r.Handle(endpoint, s.handleMetrics())
		log.Printf("[Metrics] Endpoint enabled at %s", endpoint)
	}

	// API base path from config (AI.md PART 14 — never hardcode v1)
	apiBase := s.config.APIBasePath()

	// Health check endpoints (PART 13)
	r.Get("/server/healthz", s.handleHealth)
	r.Get(apiBase+"/server/healthz", s.handleHealth)
	// Root alias for load-balancer probes — only when server.healthz.root.enabled: true
	if s.config.Healthz.Root.Enabled {
		r.Get("/healthz", s.handleHealth)
	}

	// Static assets — CSS, JS (embedded at compile time, served under /static/)
	r.Handle("/static/*", staticFileServer())

	// SEO & Security files (PART 14, PART 16) — required
	r.Get("/sitemap.xml", s.handleSitemap)
	r.Get("/robots.txt", s.handleRobotsTxt)

	// Well-known namespace (AI.md PART 14) — strict allowlist with method enforcement
	// Only GET/HEAD allowed; unknown entries return 404; no directory listing.
	r.Route("/.well-known", func(wk chi.Router) {
		wk.Use(wellKnownMethodCheck)
		wk.Get("/security.txt", s.handleSecurityTxt)
		wk.Get("/llms.txt", s.handleLLMsTxt)
		// Catch-all for unsupported well-known entries — returns 404
		wk.Get("/*", s.handleWellKnownNotFound)
		// Directory listing disabled — /.well-known/ itself returns 404
		wk.Get("/", s.handleWellKnownNotFound)
	})
	// Also serve llms.txt at root per spec
	r.Get("/llms.txt", s.handleLLMsTxt)

	// PWA support (PART 16) — manifest, service worker, offline fallback
	r.Get("/manifest.json", s.handleManifest)
	r.Get("/sw.js", s.handleServiceWorker)
	r.Get("/offline.html", s.handleOfflinePage)

	// Public content pages
	r.Get("/server/about", s.handleAboutPage)
	r.Get("/about", s.handleAboutPage)
	r.Get("/server/docs", s.handleDocsPage)
	r.Get("/docs", s.handleDocsPage)

	// Swagger/OpenAPI endpoints (AI.md PART 14)
	r.Get("/server/docs/swagger", s.handleSwaggerUI)
	r.Get("/api/swagger", s.handleSwaggerJSON)
	r.Get(apiBase+"/server/swagger", s.handleSwaggerJSON)

	// GraphQL endpoints (AI.md PART 14)
	r.Get("/server/docs/graphql", s.handleGraphiQL)
	r.Post("/api/graphql", s.handleGraphQL)
	r.Post(apiBase+"/server/graphql", s.handleGraphQL)

	// WHOIS lookup form-submission fallback (no-JS browsers, curl, wget)
	r.Get("/whois", s.handleWHOISPage)

	// Owner/registrant search — web and API (public, rate-limited)
	r.Get("/whois/search", s.handleWHOISOwnerSearch)
	r.Get(apiBase+"/whois/search", s.handleWHOISOwnerSearch)

	// API — specific typed lookups (registered before generic wildcard)
	r.Get(apiBase+"/whois/domain/*", s.handleWHOISDomainLookup)
	r.Get(apiBase+"/whois/ip/*", s.handleWHOISIPLookup)
	r.Get(apiBase+"/whois/asn/*", s.handleWHOISASNLookup)
	r.Get(apiBase+"/whois/validate/*", s.handleWHOISValidate)

	// API — generic WHOIS lookup (catch-all, after specific routes)
	r.Get(apiBase+"/whois/*", s.handleWHOIS)

	// API — Bulk lookup (requires server token)
	r.Post(apiBase+"/whois/bulk", s.requireToken(s.handleWHOISBulkLookup))

	// Autodiscover endpoint (PART 32) — non-versioned, public
	r.Get("/api/autodiscover", s.handleAutodiscover)

	// CLI binary download (PART 32) — public by default; streams prebuilt binaries
	r.Get("/cli/binaries/*", s.handleCLIBinaryDownload)

	// Locale JSON files (PART 30) — served for JS consumers; content from embedded i18n files
	r.Get("/locales/*", s.handleLocaleJSON)

	// API — utility (public)
	r.Get(apiBase+"/whois-servers", s.handleWhoisServers)
	r.Get(apiBase+"/server/stats", s.handleStats)

	// API — server operations (requires server token)
	r.Get(apiBase+"/server/schedulers", s.requireToken(s.handleSchedulerStatus))
	r.Post(apiBase+"/server/schedulers/run", s.requireToken(s.handleSchedulerRun))
	r.Get(apiBase+"/server/backups", s.requireToken(s.handleBackupStatus))
	r.Post(apiBase+"/server/backups/run", s.requireToken(s.handleBackupRun))

	// Debug endpoints (PART 6) — registered only when --debug / DEBUG=true
	s.registerDebugRoutes(r)

	// Public web interface — root only; must come after all other routes
	r.Get("/", s.handlePublicWHOISPage)

	// Catch-all 404 for all unmatched paths
	r.NotFound(s.handleNotFound)

	return r
}

// setupMiddleware configures the middleware chain per AI.md PART 5.
// The last handler applied is the outermost wrapper and therefore runs FIRST on each request.
// Execution order (first → last): URLNormalize → RequestID → PathSecurity →
// SecurityHeaders → Language → Allowlist → Blocklist → RateLimit → GeoIP → Auth → Logging → Metrics
func (s *Server) setupMiddleware(handler http.Handler) http.Handler {
	if s.metrics != nil {
		// Innermost (applied first) — outermost layer after Logging; sees every request after auth.
		handler = s.metrics.HTTPMiddleware(handler)
	}
	// 10. Logging — records every request; last layer to execute on ingress.
	handler = s.LoggingMiddleware(handler)
	// 9. Authentication — annotates context with bearer-token status.
	handler = AuthMiddleware(handler)
	// 8. GeoIP country block/allow enforcement.
	handler = GeoIPMiddleware(s.geoip, s.config.GeoIP.DenyCountries, s.config.GeoIP.AllowCountries, s.config.TrustedProxies.Additional)(handler)
	// 7. Rate limiting — use configured read limit as the global header default.
	handler = RateLimitMiddleware(s.ratelimit, s.config.RateLimit.Read.Requests, s.config.RateLimit.Read.Window)(handler)
	// 6. Blocklist — blocks denied IPs before rate-limit accounting.
	handler = BlocklistMiddleware(handler)
	// 5. Allowlist — enforces IP allowlist before blocklist.
	handler = AllowlistMiddleware(handler)
	// 4a. Request-language detection (project-specific, between security headers and allowlist).
	handler = LanguageMiddleware(handler)
	// 4. Security response headers + Sec-Fetch validation (AI.md PART 11).
	handler = SecFetchValidationMiddleware(handler)
	handler = SecurityHeadersMiddleware(s.config.FQDN, s.config.APIVersion, s.config.TLS.Enabled, s.config.Debug)(handler)
	// 3. CORS headers for API paths — handles OPTIONS preflight before route handlers.
	handler = CORSMiddleware(s.config.Web.CORS)(handler)
	// 2. Path traversal check and normalization.
	handler = PathSecurityMiddleware(handler)
	// 1b. Request ID assignment — before PathSecurity so the ID is always set.
	handler = RequestIDMiddleware(handler)
	// 1. URL normalization — outermost, runs first on every request.
	handler = URLNormalizeMiddleware(handler)
	return handler
}

// handleWHOIS handles WHOIS lookup requests.
func (s *Server) handleWHOIS(w http.ResponseWriter, r *http.Request) {
	// Extract query from path — use config-driven API base path
	prefix := s.config.APIBasePath() + "/whois/"
	path := strings.TrimPrefix(r.URL.Path, prefix)
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
		return "/var/run/" + constants.InternalOrg + "/" + constants.InternalName + ".pid"
	}
	// User-specific PID file otherwise.
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".local", "share", constants.InternalOrg, constants.InternalName, constants.InternalName+".pid")
}


// handleMetrics returns the Prometheus metrics handler.
// PART 20: /metrics endpoint (INTERNAL ONLY — never proxy to public).
// When metrics.token is set the Authorization header is validated with
// constant-time comparison (AI.md PART 11) to prevent timing attacks.
func (s *Server) handleMetrics() http.Handler {
	handler := promhttp.Handler()

	// If token is configured, require bearer authentication.
	if s.config.Metrics.Token != "" {
		expected := []byte("Bearer " + s.config.Metrics.Token)
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

// handleLLMsTxt serves llms.txt for AI agent discovery (AI.md PART 14).
// Required for ALL projects. Tells AI agents what the application does and
// what API endpoints are available.
func (s *Server) handleLLMsTxt(w http.ResponseWriter, r *http.Request) {
	baseURL := fmt.Sprintf("http://localhost:%d", s.config.Port)
	if s.config.FQDN != "" {
		baseURL = "https://" + s.config.FQDN
	}

	// Security contact
	securityContact := "security@" + s.config.FQDN
	if s.config.FQDN == "" {
		securityContact = "security@localhost"
	}

	// Rate limit info
	rateLimit := s.config.RateLimit.Read.Requests
	if rateLimit == 0 {
		rateLimit = 100
	}

	content := fmt.Sprintf(`# caswhois
> WHOIS lookup service with domain, IP, and ASN queries

## API
Base URL: %s/api/v1
Authentication: Bearer token (optional for public endpoints)
Rate limit: %d requests/minute

## Endpoints
- GET /api/v1/server/healthz - Health check (no auth)
- GET /api/v1/whois/{query} - Auto-detect lookup (domain/IP/ASN)
- GET /api/v1/whois/domain/{domain} - Domain WHOIS lookup
- GET /api/v1/whois/ip/{ip} - IP WHOIS lookup
- GET /api/v1/whois/asn/{asn} - ASN WHOIS lookup
- GET /api/v1/whois/validate/{query} - Validate query without lookup
- GET /api/v1/whois/search?q={owner} - Search by owner/registrant
- POST /api/v1/whois/bulk - Bulk lookup (requires token)

## Capabilities
- Domain WHOIS lookups with parsed fields
- IP address geolocation and WHOIS
- ASN ownership information
- RDAP protocol support
- Bulk lookups for authenticated users
- Rate limiting and caching

## Output Formats
- JSON (Accept: application/json)
- Plain text (Accept: text/plain)

## Contact
API issues: %s
Security: %s
`, baseURL, rateLimit, securityContact, securityContact)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, content)
}

// handleWellKnownNotFound returns 404 for unknown /.well-known/* entries.
// Per AI.md PART 14: unsupported well-known entries MUST return 404.
func (s *Server) handleWellKnownNotFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, "404 Not Found\n")
}

// wellKnownMethodCheck is middleware that enforces GET/HEAD only for /.well-known/*.
// Per AI.md PART 14: other methods MUST return 405 Method Not Allowed.
func wellKnownMethodCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, "405 Method Not Allowed\n")
			return
		}
		next.ServeHTTP(w, r)
	})
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
