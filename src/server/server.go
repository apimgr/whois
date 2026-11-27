package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/apimgr/whois/src/cache"
	"github.com/apimgr/whois/src/common/constants"
	"github.com/apimgr/whois/src/config"
	"github.com/apimgr/whois/src/db"
	"github.com/apimgr/whois/src/email"
	"github.com/apimgr/whois/src/geoip"
	"github.com/apimgr/whois/src/health"
	"github.com/apimgr/whois/src/i2p"
	caslogger "github.com/apimgr/whois/src/logger"
	"github.com/apimgr/whois/src/metrics"
	"github.com/apimgr/whois/src/ratelimit"
	runtimeinfo "github.com/apimgr/whois/src/runtime"
	"github.com/apimgr/whois/src/scheduler"
	casssl "github.com/apimgr/whois/src/ssl"
	"github.com/apimgr/whois/src/swagger"
	castor "github.com/apimgr/whois/src/tor"
	"github.com/apimgr/whois/src/update"
	"github.com/apimgr/whois/src/whois"
	"github.com/apimgr/whois/src/whois/records"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server represents the HTTP server
type torRuntime interface {
	OnionAddress() string
	OutboundEnabled() bool
	GetHTTPClient(bool) *http.Client
	Health(context.Context) error
	Serve(http.Handler, time.Duration, time.Duration, time.Duration) error
	Close() error
}

type Server struct {
	config             *config.ServerConfig
	pidFileOverride    string
	server             *http.Server
	httpsServer        *http.Server
	apiRouter          chi.Router
	routeRegistry      *swagger.Registry
	info               *runtimeinfo.RuntimeInfo
	cache              cache.Cache
	ratelimit          *ratelimit.Limiter
	writeLimiter       *ratelimit.Limiter
	healthLimiter      *ratelimit.Limiter
	globalBurstLimiter *ratelimit.Limiter
	strictLimiter      *ratelimit.Limiter
	authFailureLimiter *ratelimit.Limiter
	database           *db.DB
	scheduler          *scheduler.Scheduler
	geoip              *geoip.GeoIPManager
	email              *email.EmailManager
	metrics            *metrics.Collector
	torService         torRuntime
	torMu              sync.RWMutex
	torStatus          string
	torActions         chan torActionRequest
	torMaintenance     *castor.Maintenance
	i2pService         *i2p.Service
	i2pMu              sync.RWMutex
	i2pUpdateMu        sync.Mutex
	i2pStatus          string
	i2pProvider        i2p.Provider
	i2pListener        net.Listener
	i2pServer          *http.Server
	// logger manages the four required log files (PART 11).
	logger *caslogger.Logger
	// startTime is the server start time, used for uptime calculation.
	startTime time.Time
	// stats holds atomic runtime counters surfaced via /server/stats.
	stats       serverStats
	hotCounters hotCounterBuffer
	// lookupService handles RDAP-first lookups with WHOIS fallback
	lookupService       *whois.LookupService
	serverTokenHashOnce sync.Once
	serverTokenHash     [32]byte
	// configManager polls server.yml for external edits and applies
	// hot-reloadable settings in place, flagging restart-required ones
	// (AI.md PART 8 — Smart Config Reload).
	configManager *config.ConfigManager
	shuttingDown  atomic.Bool
}

type torRequestContextKey struct{}

func torRequestHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := torCircuitIdentity(r.RemoteAddr)
		r = r.WithContext(context.WithValue(r.Context(), torRequestContextKey{}, identity))
		r.RemoteAddr = identity
		next.ServeHTTP(w, r)
	})
}

func torRequestIdentity(r *http.Request) (string, bool) {
	identity, ok := r.Context().Value(torRequestContextKey{}).(string)
	return identity, ok
}

func torCircuitIdentity(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]")).To16()
	if ip == nil {
		return "tor"
	}
	return "tor:" + strconv.FormatUint(uint64(binary.BigEndian.Uint32(ip[12:16])), 10)
}

func ipv6Unavailable(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "address family not supported") ||
		strings.Contains(message, "family not supported by protocol") ||
		strings.Contains(message, "protocol not supported")
}

// New creates a new Server instance.
// lgr may be nil; logging is silently disabled in that case.
func New(cfg *config.ServerConfig, database *db.DB, lgr *caslogger.Logger) *Server {
	if strings.TrimSpace(cfg.Web.UI.Accent) != "" && !accentStylesheetURL(cfg.Web.UI.Accent) {
		log.Printf("WARN: invalid web.ui.accent; using the built-in theme palette")
	}
	memCache, err := cache.New(context.Background(), cache.Config{
		Type:          cfg.Cache.Type,
		URL:           cfg.Cache.URL,
		Host:          cfg.Cache.Host,
		Port:          cfg.Cache.Port,
		Username:      cfg.Cache.Username,
		Password:      cfg.Cache.Password,
		DB:            cfg.Cache.DB,
		TLS:           cfg.Cache.TLS,
		TLSSkipVerify: cfg.Cache.TLSSkipVerify,
		PoolSize:      cfg.Cache.PoolSize,
		MinIdle:       cfg.Cache.MinIdle,
		Timeout:       cfg.Cache.Timeout,
		Prefix:        cfg.Cache.Prefix,
	})
	if err != nil {
		log.Printf("WARN: Failed to initialize %q cache backend, falling back to in-process memory: %v", cfg.Cache.Type, err)
		memCache = cache.NewMemoryCache(100*1024*1024, 5*time.Minute)
	}
	readLimit := cfg.RateLimit.Read
	if readLimit.Requests <= 0 || readLimit.Window <= 0 {
		readLimit = config.RateLimitEndpointConfig{Requests: 120, Window: 60}
	}
	writeLimit := cfg.RateLimit.Write
	if writeLimit.Requests <= 0 || writeLimit.Window <= 0 {
		writeLimit = config.RateLimitEndpointConfig{Requests: 10, Window: 60}
	}
	healthLimit := cfg.RateLimit.Health
	if healthLimit.Requests <= 0 || healthLimit.Window <= 0 {
		healthLimit = config.RateLimitEndpointConfig{Requests: 120, Window: 60}
	}
	globalBurst := cfg.RateLimit.GlobalBurst
	if globalBurst <= 0 {
		globalBurst = 240
	}
	cfg.RateLimit.Read = readLimit
	cfg.RateLimit.Write = writeLimit
	cfg.RateLimit.Health = healthLimit
	cfg.RateLimit.GlobalBurst = globalBurst
	rateLimiter := ratelimit.New(readLimit.Requests, time.Duration(readLimit.Window)*time.Second)
	writeLimiter := ratelimit.New(writeLimit.Requests, time.Duration(writeLimit.Window)*time.Second)
	healthLimiter := ratelimit.New(healthLimit.Requests, time.Duration(healthLimit.Window)*time.Second)
	globalBurstLimiter := ratelimit.New(globalBurst, time.Minute)
	strictLimit := cfg.RateLimit.Strict
	if strictLimit.Requests <= 0 || strictLimit.Window <= 0 {
		strictLimit = config.RateLimitEndpointConfig{Requests: 10, Window: 900}
	}
	authFailureLimit := cfg.RateLimit.AuthFailures
	if authFailureLimit.Requests <= 0 || authFailureLimit.Window <= 0 {
		authFailureLimit = config.RateLimitEndpointConfig{Requests: 5, Window: 900}
	}
	cfg.RateLimit.Strict = strictLimit
	cfg.RateLimit.AuthFailures = authFailureLimit
	strictLimiter := ratelimit.New(strictLimit.Requests, time.Duration(strictLimit.Window)*time.Second)
	authFailureLimiter := ratelimit.New(authFailureLimit.Requests, time.Duration(authFailureLimit.Window)*time.Second)

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
	sched, err := scheduler.NewWithStore(database, schedTimezone, schedCatchUp)
	if err != nil {
		log.Printf("WARN: Failed to initialize scheduler: %v", err)
		sched = nil
	}
	if sched != nil {
		sched.SetSecurityCleanup(cfg.Security.Reports.RetentionDays, filepath.Join(cfg.ConfigDir, "security", "pgp.priv.old.asc.enc"))
	}

	// Initialize GeoIP (AI.md PART 19 — server.geoip.*).
	// Security DBs live under data_dir, not config_dir (AI.md PART 4).
	var geoipMgr *geoip.GeoIPManager
	if cfg.GeoIP.Dir == "" {
		cfg.GeoIP.Dir = filepath.Join(cfg.DataDir, "security", "geoip")
	}
	geoipCfg := geoip.GeoIPConfig{
		Enabled:   cfg.GeoIP.Enabled,
		Dir:       cfg.GeoIP.Dir,
		UserAgent: constants.InternalName + "/" + Version,
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
	if cfg.GeoIP.Enabled {
		for _, database := range []struct {
			name    string
			enabled bool
		}{
			{name: "asn", enabled: cfg.GeoIP.Databases.ASN},
			{name: "country", enabled: cfg.GeoIP.Databases.Country},
			{name: "city_ipv4", enabled: cfg.GeoIP.Databases.City},
			{name: "city_ipv6", enabled: cfg.GeoIP.Databases.City},
		} {
			if !database.enabled {
				continue
			}
			name := database.name
			health.Register("geoip_"+name, false, func() string {
				if geoipMgr == nil {
					return "error"
				}
				return geoipMgr.DatasetStatus(name)
			})
		}
	}

	// Initialize Metrics (PART 20)
	metricsCfg := metrics.MetricsConfig{
		Enabled:         cfg.Metrics.Enabled,
		Endpoint:        cfg.Metrics.Endpoint,
		IncludeSystem:   cfg.Metrics.IncludeSystem,
		IncludeRuntime:  cfg.Metrics.IncludeRuntime,
		Token:           cfg.Metrics.Token,
		DurationBuckets: cfg.Metrics.DurationBuckets,
		SizeBuckets:     cfg.Metrics.SizeBuckets,
	}
	metricsCollector := metrics.New(constants.InternalName, metricsCfg)
	if database != nil {
		database.SetWriteMetrics(metricsCollector)
	}
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
		config:             cfg,
		info:               runtimeinfo.Detect(),
		cache:              memCache,
		ratelimit:          rateLimiter,
		writeLimiter:       writeLimiter,
		healthLimiter:      healthLimiter,
		globalBurstLimiter: globalBurstLimiter,
		strictLimiter:      strictLimiter,
		authFailureLimiter: authFailureLimiter,
		database:           database,
		scheduler:          sched,
		geoip:              geoipMgr,
		email:              emailMgr,
		metrics:            metricsCollector,
		logger:             lgr,
		startTime:          time.Now(),
		lookupService:      lookupSvc,
	}
	srv.getServerTokenHash()

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
		sched.I2PHealthHook = func(ctx context.Context) error {
			srv.i2pMu.RLock()
			svc := srv.i2pService
			srv.i2pMu.RUnlock()
			if svc == nil {
				return nil
			}
			return svc.Health(ctx)
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
				if err := geoipMgr.UpdateDatabases(ctx, geoCfg); err != nil {
					return err
				}
				health.Refresh()
				return nil
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
					if upErr := records.UpsertRecordInStore(ctx, srv.database, q, result.Type.String(), result.Domain); upErr != nil {
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

		// Wire the update_check hook (AI.md PART 22). Notify-only by default;
		// only installs when server.update.auto_install is true, and only
		// once the release has cleared server.update.defer_days.
		sched.UpdateCheckHook = func(ctx context.Context) error {
			var channel update.UpdateChannel
			switch cfg.Update.Branch {
			case "beta":
				channel = update.ChannelBeta
			case "daily":
				channel = update.ChannelDaily
			default:
				channel = update.ChannelStable
			}

			info, err := update.CheckForUpdatesScheduled(Version, channel, cfg.Update.DeferDays)
			if err != nil {
				return err
			}
			if !info.Available {
				return nil
			}

			if !cfg.Update.AutoInstall {
				log.Printf("INFO: update available: %s -> %s (server.update.auto_install is false; not installing)", info.CurrentVersion, info.LatestVersion)
				return nil
			}

			log.Printf("INFO: update available: %s -> %s; installing (server.update.auto_install is true)", info.CurrentVersion, info.LatestVersion)
			return update.InstallUpdate(info)
		}

		if err := sched.RegisterBuiltInTasks(); err != nil {
			log.Printf("WARN: Failed to register built-in tasks: %v", err)
		}
		_ = sched.DisableTask("i2p_health")

		// Apply per-task retry overrides from server.yml (AI.md PART 18).
		if len(cfg.Scheduler.Tasks) > 0 {
			defaultRetryDelay := 5 * time.Minute
			if cfg.Scheduler.RetryDelay != "" {
				if d, parseErr := time.ParseDuration(cfg.Scheduler.RetryDelay); parseErr == nil {
					defaultRetryDelay = d
				}
			}

			overrides := make(map[string]scheduler.TaskOverride, len(cfg.Scheduler.Tasks))
			for id, tc := range cfg.Scheduler.Tasks {
				ov := scheduler.TaskOverride{RetryOnFail: tc.RetryOnFail}
				if tc.RetryDelay != "" {
					if d, parseErr := time.ParseDuration(tc.RetryDelay); parseErr == nil {
						ov.RetryDelay = d
					}
				}
				overrides[id] = ov
			}
			sched.ApplyTaskOverrides(overrides, cfg.Scheduler.MaxRetries, defaultRetryDelay, cfg.Scheduler.Backoff)
		}
	}

	return srv
}

func (s *Server) currentTor() torRuntime {
	s.torMu.RLock()
	defer s.torMu.RUnlock()
	return s.torService
}

// SetPIDFilePath applies the --pid/PID_FILE override before Start.
func (s *Server) SetPIDFilePath(path string) {
	s.pidFileOverride = strings.TrimSpace(path)
}

// Start starts the HTTP server and waits for an operating-system shutdown signal.
func (s *Server) Start() error {
	return s.Run(context.Background(), nil)
}

// Run serves on listener until ctx is canceled or the operating system asks
// the process to shut down. A nil listener binds the configured TCP address.
func (s *Server) Run(ctx context.Context, listener net.Listener) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	var configManagerDone <-chan struct{}
	var extraSignalsDone <-chan struct{}
	defer func() {
		cancelRun()
		if configManagerDone != nil {
			<-configManagerDone
		}
		if extraSignalsDone != nil {
			<-extraSignalsDone
		}
	}()
	defer func() {
		if s.ratelimit != nil {
			s.ratelimit.Close()
		}
		if s.writeLimiter != nil {
			s.writeLimiter.Close()
		}
		if s.healthLimiter != nil {
			s.healthLimiter.Close()
		}
		if s.globalBurstLimiter != nil {
			s.globalBurstLimiter.Close()
		}
		if s.strictLimiter != nil {
			s.strictLimiter.Close()
		}
		if s.authFailureLimiter != nil {
			s.authFailureLimiter.Close()
		}
	}()
	writePIDFile := pidFileSupported() && !config.IsContainer() && (s.config.PIDFile || s.pidFileOverride != "")
	pidPath := ""
	if writePIDFile {
		pidPath = s.getPIDFilePath()
	}
	if err := prepareRuntimeOwnership(*s.config, pidPath); err != nil {
		return fmt.Errorf("prepare service runtime directories: %w", err)
	}
	if writePIDFile {
		// Check for an existing instance, then write the PID before dropping
		// privileges so the service-owned runtime directory stays writable.
		running, existingPID, err := CheckPIDFile(pidPath)
		if err != nil {
			return fmt.Errorf("error checking pid file: %w", err)
		}
		if running {
			return fmt.Errorf("server already running (pid %d)", existingPID)
		}
		if err := WritePIDFile(pidPath, s.config.Port); err != nil {
			return fmt.Errorf("failed to write pid file: %w", err)
		}
		defer func() { _ = RemovePIDFile(pidPath) }()
	}

	hotCounterCtx, stopHotCounters := context.WithCancel(context.Background())
	hotCounterDone := make(chan struct{})
	go func() {
		defer close(hotCounterDone)
		s.runHotCounterFlush(hotCounterCtx)
	}()
	defer func() {
		stopHotCounters()
		<-hotCounterDone
	}()

	// Setup routes and middleware
	s.torMaintenance = &castor.Maintenance{DataDir: s.config.DataDir}
	s.torActions = make(chan torActionRequest, 16)
	handler := s.setupRoutes()
	handler = s.setupMiddleware(handler)

	// Create HTTP server with configurable timeouts from server.limits (AI.md PART 12).
	bindAddress := strings.Trim(s.config.Address, "[]")
	addr := net.JoinHostPort(bindAddress, fmt.Sprint(s.config.Port))
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
			defer func() {
				log.Printf("Stopping scheduler...")
				if err := s.scheduler.Stop(); err != nil {
					log.Printf("ERROR: Failed to stop scheduler: %v", err)
				}
			}()
			log.Printf("Scheduler started with 8 built-in tasks")
		}
	}

	// Bind the listener while still privileged so ports below 1024 can be
	// claimed, then drop to the unprivileged service account before serving
	// any request (AI.md PART 23 — bind privileged port, then drop privileges).
	var err error
	if listener == nil {
		listener, err = net.Listen("tcp", addr)
		if err != nil && bindAddress == "::" && ipv6Unavailable(err) {
			bindAddress = "0.0.0.0"
			addr = net.JoinHostPort(bindAddress, fmt.Sprint(s.config.Port))
			log.Printf("WARN: IPv6 wildcard listener is unavailable; falling back to %s", bindAddress)
			listener, err = net.Listen("tcp", addr)
			if err == nil {
				s.server.Addr = addr
			}
		}
		if err != nil {
			return fmt.Errorf("failed to bind %s: %w", addr, err)
		}
	} else {
		addr = listener.Addr().String()
		s.server.Addr = addr
		if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
			bindAddress = strings.Trim(host, "[]")
		}
	}

	var httpsListener net.Listener
	dualPort := s.config.HTTPPort > 0 && s.config.HTTPSPort > 0
	// A configured HTTPS port enables TLS even when the single-port SSL switch
	// is off. TLS 1.2 is the minimum version; 1.3 is preferred.
	if s.config.TLS.Enabled || s.config.HTTPSPort > 0 {
		fqdn := s.config.TLS.Domain
		if fqdn == "" {
			fqdn = s.config.FQDN
		}
		certMgr := casssl.NewCertManager(s.config.ConfigDir, fqdn)
		if loadErr := certMgr.LoadCertificate(); loadErr != nil {
			log.Printf("WARN: TLS cert not found (%v); requesting from Let's Encrypt", loadErr)
			if reqErr := certMgr.RequestNewCertificate(); reqErr != nil {
				_ = listener.Close()
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
		if dualPort {
			httpsAddr := net.JoinHostPort(bindAddress, fmt.Sprint(s.config.HTTPSPort))
			httpsListener, err = net.Listen("tcp", httpsAddr)
			if err != nil {
				_ = listener.Close()
				return fmt.Errorf("failed to bind HTTPS listener %s: %w", httpsAddr, err)
			}
			httpsListener = tls.NewListener(httpsListener, tlsCfg)
		} else {
			listener = tls.NewListener(listener, tlsCfg)
		}

		// Start HTTP→HTTPS redirect server on port 80 (AI.md PART 15).
		redirectMux := http.NewServeMux()
		redirectMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})
		redirectAddr := net.JoinHostPort(bindAddress, "80")
		redirectSrv := &http.Server{
			Addr:         redirectAddr,
			Handler:      redirectMux,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
		}
		if !dualPort && s.config.Port != 80 {
			go func() {
				log.Printf("HTTP→HTTPS redirect listening on %s", redirectAddr)
				if listenErr := redirectSrv.ListenAndServe(); listenErr != nil && listenErr != http.ErrServerClosed {
					log.Printf("WARN: HTTP redirect server error: %v", listenErr)
				}
			}()
		}
	}

	if err := dropPrivileges(s.config.User, s.config.Group); err != nil {
		_ = listener.Close()
		if httpsListener != nil {
			_ = httpsListener.Close()
		}
		return fmt.Errorf("failed to drop privileges: %w", err)
	}

	// Channel for server errors
	serverErrors := make(chan error, 1)

	// Start server in goroutine
	go func() {
		log.Printf("Server starting on %s", addr)
		serverErrors <- s.server.Serve(listener)
	}()
	if httpsListener != nil {
		s.httpsServer = &http.Server{Addr: net.JoinHostPort(bindAddress, fmt.Sprint(s.config.HTTPSPort)), Handler: handler, ReadTimeout: readTimeout, WriteTimeout: writeTimeout, IdleTimeout: idleTimeout}
		go func() {
			log.Printf("HTTPS server starting on %s", s.httpsServer.Addr)
			serverErrors <- s.httpsServer.Serve(httpsListener)
		}()
	}

	i2pCtx, i2pCancel := context.WithCancel(context.Background())
	i2pUpdates := make(chan i2p.Config, 1)
	i2pDone := make(chan struct{})
	go func() {
		defer close(i2pDone)
		s.runI2PManager(i2pCtx, s.makeI2PConfig(s.config.I2P), handler, readTimeout, writeTimeout, idleTimeout, i2pUpdates)
	}()
	defer func() {
		i2pCancel()
		<-i2pDone
	}()

	// Start the dedicated Tor hidden service asynchronously after the clearnet listener is live.
	torCtx, torCancel := context.WithCancel(context.Background())
	torDone := make(chan struct{})
	defer func() { torCancel(); <-torDone }()
	torActions := s.torActions
	torUpdates := make(chan config.TorConfig, 1)
	torBinary := castor.FindBinary(s.config.Tor.Binary)
	s.torMu.Lock()
	if torBinary == "" {
		s.torStatus = "disabled"
	} else {
		s.torStatus = "starting"
	}
	s.torMu.Unlock()
	go func() {
		defer close(torDone)
		if torBinary == "" {
			return
		}
		s.runTorManager(torCtx, torConfigFromServer(s.config.Tor), handler, readTimeout, writeTimeout, idleTimeout, torActions, torUpdates)
	}()

	// Start polling server.yml for external edits and hot-reload what we
	// can in place (AI.md PART 8 — Smart Config Reload; polling, not fsnotify).
	s.configManager = config.NewConfigManager(s.config.ConfigDir, s.config)
	s.configManager.I2PConfigHook = func(next config.I2PConfig) {
		updated := s.makeI2PConfig(next)
		if s.scheduler != nil && !next.Enabled {
			_ = s.scheduler.DisableTask("i2p_health")
		}
		s.i2pUpdateMu.Lock()
		select {
		case i2pUpdates <- updated:
		default:
			select {
			case <-i2pUpdates:
			default:
			}
			i2pUpdates <- updated
		}
		s.i2pUpdateMu.Unlock()
	}
	s.configManager.TorConfigHook = func(next config.TorConfig) {
		select {
		case torUpdates <- next:
		default:
			select {
			case <-torUpdates:
			default:
			}
			torUpdates <- next
		}
	}
	configManagerDone = s.configManager.Start(runCtx)

	// Channel for OS signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(shutdown)

	// SIGUSR1 (log rotation) and SIGHUP (config reload) — Unix only.
	extraSignalsDone = setupExtraSignals(runCtx, s)

	// Wait for shutdown signal or server error
	select {
	case err := <-serverErrors:
		return fmt.Errorf("server error: %w", err)
	case sig := <-shutdown:
		log.Printf("Received signal %v, shutting down gracefully...", sig)
	case <-runCtx.Done():
		log.Printf("Run context canceled; shutting down gracefully...")
	}
	cancelRun()
	s.shuttingDown.Store(true)
	if configManagerDone != nil {
		<-configManagerDone
		configManagerDone = nil
	}
	if extraSignalsDone != nil {
		<-extraSignalsDone
		extraSignalsDone = nil
	}

	// Stop Tor and I2P before draining HTTP requests.
	torCancel()
	<-torDone
	i2pCancel()
	<-i2pDone
	if torService := s.currentTor(); torService != nil {
		if err := torService.Close(); err != nil {
			log.Printf("[Tor] shutdown error: %v", err)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.server.Shutdown(shutdownCtx); err != nil {
		_ = s.server.Close()
		return fmt.Errorf("could not stop server gracefully: %w", err)
	}
	if s.httpsServer != nil {
		if err := s.httpsServer.Shutdown(shutdownCtx); err != nil {
			_ = s.httpsServer.Close()
			return fmt.Errorf("could not stop HTTPS server gracefully: %w", err)
		}
	}

	return nil
}

func (s *Server) setI2PStatus(status string) {
	s.i2pMu.Lock()
	s.i2pStatus = status
	s.i2pMu.Unlock()
}

func i2pRequestHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.Clone(context.WithValue(r.Context(), i2pRequestContextKey{}, true))
		r.Header = r.Header.Clone()
		for key := range r.Header {
			lower := strings.ToLower(key)
			if strings.HasPrefix(lower, "x-i2p-") || strings.HasPrefix(lower, "x-forwarded-") || lower == "x-real-ip" || lower == "x-real-host" || lower == "x-original-host" || lower == "x-url-scheme" || lower == "x-script-name" || lower == "forwarded" {
				r.Header.Del(key)
			}
		}
		r.RemoteAddr = "127.0.0.2:1"
		next.ServeHTTP(w, r)
	})
}

type i2pRequestContextKey struct{}

func (s *Server) makeI2PConfig(c config.I2PConfig) i2p.Config {
	return i2p.Config{Enabled: c.Enabled, Binary: c.Binary, SAMAddress: c.SAMAddress, ConfigDir: s.config.ConfigDir, DataDir: s.config.DataDir, LogDir: s.config.LogDir, VirtualPort: c.VirtualPort, InboundLength: c.InboundLength, OutboundLength: c.OutboundLength, InboundQuantity: c.InboundQuantity, OutboundQuantity: c.OutboundQuantity, SignatureType: c.SignatureType, BootstrapTimeout: c.BootstrapTimeout, StateHook: func(state string) {
		if state != "running" {
			s.setI2PStatus(state)
		}
	}}
}

func (s *Server) runI2PManager(ctx context.Context, cfg i2p.Config, handler http.Handler, readTimeout, writeTimeout, idleTimeout time.Duration, updates <-chan i2p.Config) {
	backoff := 5 * time.Second
	wait := func(delay time.Duration) (i2p.Config, bool, bool) {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return cfg, false, false
		case next := <-updates:
			return next, true, true
		case <-timer.C:
			return cfg, true, false
		}
	}
	closeBackend := func(server *http.Server, listener net.Listener) {
		if server != nil {
			_ = server.Close()
		}
		if listener != nil {
			_ = listener.Close()
		}
		s.i2pMu.Lock()
		if s.i2pServer == server {
			s.i2pServer = nil
			s.i2pListener = nil
		}
		s.i2pMu.Unlock()
	}
	for ctx.Err() == nil {
		if !cfg.Enabled {
			s.setI2PStatus("disabled")
			s.i2pMu.Lock()
			s.i2pProvider = ""
			s.i2pMu.Unlock()
			next, ok, _ := wait(24 * time.Hour)
			if !ok {
				return
			}
			cfg = next
			continue
		}
		s.setI2PStatus("starting")
		provider, _, _ := i2p.Resolve(cfg)
		s.i2pMu.Lock()
		s.i2pProvider = provider
		s.i2pMu.Unlock()
		if provider == "" {
			s.setI2PStatus("no_provider")
			if s.scheduler != nil {
				_ = s.scheduler.DisableTask("i2p_health")
			}
			next, ok, _ := wait(30 * time.Second)
			if !ok {
				return
			}
			cfg = next
			continue
		}
		if s.scheduler != nil {
			_ = s.scheduler.EnableTask("i2p_health")
		}
		listener, err := i2p.ListenBackend()
		if err != nil {
			s.setI2PStatus("error")
			log.Printf("WARN: I2P backend listener unavailable")
			next, ok, updated := wait(backoff)
			if !ok {
				return
			}
			cfg = next
			if updated {
				backoff = 5 * time.Second
			} else {
				backoff = min(backoff*2, 300*time.Second)
			}
			continue
		}
		backend := &http.Server{Handler: i2pRequestHandler(handler), ReadTimeout: readTimeout, WriteTimeout: writeTimeout, IdleTimeout: idleTimeout}
		serveErrors := make(chan error, 1)
		go func() { serveErrors <- backend.Serve(listener) }()
		s.i2pMu.Lock()
		s.i2pServer = backend
		s.i2pListener = listener
		s.i2pMu.Unlock()
		cfg.StateHook = func(state string) {
			if state != "running" {
				s.setI2PStatus(state)
			}
		}
		startCtx, cancelStart := context.WithCancel(ctx)
		started := make(chan struct {
			service *i2p.Service
			err     error
		}, 1)
		go func() {
			svc, startErr := i2p.Start(startCtx, cfg, listener.Addr().(*net.TCPAddr).Port)
			started <- struct {
				service *i2p.Service
				err     error
			}{svc, startErr}
		}()
		var svc *i2p.Service
		select {
		case <-ctx.Done():
			cancelStart()
			result := <-started
			if result.service != nil {
				_ = result.service.Close()
			}
			closeBackend(backend, listener)
			return
		case next := <-updates:
			cancelStart()
			result := <-started
			if result.service != nil {
				_ = result.service.Close()
			}
			closeBackend(backend, listener)
			cfg = next
			backoff = 5 * time.Second
			continue
		case result := <-started:
			cancelStart()
			svc, err = result.service, result.err
		}
		if err != nil {
			closeBackend(backend, listener)
			if !errors.Is(err, context.Canceled) {
				s.setI2PStatus("error")
				log.Printf("WARN: I2P startup failed: %v", err)
			}
			if delay := i2p.RetryDelay(err); delay > 0 {
				backoff = delay
			}
			next, ok, updated := wait(backoff)
			if !ok {
				return
			}
			cfg = next
			if updated {
				backoff = 5 * time.Second
			} else if backoff < 300*time.Second {
				backoff = min(backoff*2, 300*time.Second)
			}
			continue
		}
		s.i2pMu.Lock()
		s.i2pService = svc
		s.i2pMu.Unlock()
		s.setI2PStatus("running")
		backoff = 5 * time.Second
		ticker := time.NewTicker(30 * time.Second)
		restart := false
		for !restart {
			select {
			case <-ctx.Done():
				ticker.Stop()
				_ = svc.Close()
				s.i2pMu.Lock()
				s.i2pService = nil
				s.i2pMu.Unlock()
				closeBackend(backend, listener)
				return
			case next := <-updates:
				ticker.Stop()
				_ = svc.Close()
				s.i2pMu.Lock()
				s.i2pService = nil
				s.i2pMu.Unlock()
				closeBackend(backend, listener)
				cfg = next
				backoff = 5 * time.Second
				restart = true
			case serveErr := <-serveErrors:
				ticker.Stop()
				_ = svc.Close()
				s.i2pMu.Lock()
				s.i2pService = nil
				s.i2pMu.Unlock()
				closeBackend(backend, listener)
				if serveErr != http.ErrServerClosed {
					s.setI2PStatus("error")
					log.Printf("WARN: I2P backend listener stopped")
				}
				restart = true
			case <-ticker.C:
				if healthErr := svc.Health(ctx); healthErr != nil {
					ticker.Stop()
					_ = svc.Close()
					s.i2pMu.Lock()
					s.i2pService = nil
					s.i2pMu.Unlock()
					closeBackend(backend, listener)
					s.setI2PStatus("error")
					log.Printf("WARN: I2P provider failed; retrying with backoff")
					restart = true
				}
			}
		}
		if ctx.Err() != nil {
			return
		}
		if cfg.Enabled {
			next, ok, updated := wait(backoff)
			if !ok {
				return
			}
			cfg = next
			if updated {
				backoff = 5 * time.Second
			} else if backoff < 300*time.Second {
				backoff = min(backoff*2, 300*time.Second)
			}
		}
	}
}

// setupRoutes configures HTTP routes using chi (PART 13 — every web page has a corresponding API endpoint).
func (s *Server) setupRoutes() http.Handler {
	r := chi.NewRouter()
	s.routeRegistry = swagger.NewRegistry()
	for _, control := range []struct {
		method, path, operationID string
	}{{http.MethodGet, "/server/tor/status", "torStatus"}, {http.MethodPost, "/server/tor/validate", "torValidate"}, {http.MethodPost, "/server/tor/restart", "torRestart"}, {http.MethodPost, "/server/tor/regenerate", "torRegenerate"}, {http.MethodPost, "/server/tor/vanity/start", "torVanityStart"}, {http.MethodPost, "/server/tor/vanity/stop", "torVanityStop"}, {http.MethodPost, "/server/tor/vanity/apply", "torVanityApply"}, {http.MethodPost, "/server/tor/import-keys", "torImportKeys"}} {
		s.addAPIRoute(r, control.method, control.path, control.operationID, "Local Tor control operation", "none", false, true, http.HandlerFunc(s.handleTorControl))
	}

	// Metrics endpoint (PART 20) — internal only, token-protected
	if s.metrics != nil && s.config.Metrics.Enabled {
		endpoint := s.config.Metrics.Endpoint
		if endpoint == "" {
			endpoint = "/metrics"
		}
		s.addAPIRoute(r, http.MethodGet, endpoint, "metricsScrape", "Prometheus metrics scrape", "service", false, true, s.handleMetrics())
		log.Printf("[Metrics] Endpoint enabled at %s", endpoint)
	}

	// API base path from config (AI.md PART 14 — never hardcode v1)
	apiBase := s.config.APIBasePath()
	s.addAPIRoute(r, http.MethodPost, apiBase+"/server/mcp", "mcpEndpoint", "Model Context Protocol endpoint", "token", false, true, http.HandlerFunc(s.handleMCP))
	s.addAPIRoute(r, http.MethodPost, "/api/mcp", "mcpAlias", "Model Context Protocol endpoint alias", "token", false, true, http.HandlerFunc(s.handleMCP))
	s.addAPIRoute(r, http.MethodPost, "/mcp", "mcpRootAlias", "Model Context Protocol endpoint alias", "token", false, true, http.HandlerFunc(s.handleMCP))

	// Health check endpoints (PART 13)
	r.Get("/server/healthz", s.handleHealth)
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/healthz", "getHealth", "Health check", "none", true, false, http.HandlerFunc(s.handleHealth))
	// Unversioned API alias — always enabled, machine-friendly versionless probing (AI.md PART 13/14)
	s.addAPIRoute(r, http.MethodGet, "/api/healthz", "getHealthAlias", "Unversioned health check", "none", false, false, http.HandlerFunc(s.handleHealth))
	// Root alias for load-balancer probes — only when server.healthz.root.enabled: true
	if s.config.Healthz.Root.Enabled {
		r.Get("/healthz", s.handleHealth)
	}

	// Static assets — CSS, JS (embedded at compile time, served under /static/)
	r.Get("/static/css/accent.css", s.handleAccentCSS)
	r.Get("/static/css/notifications.css", s.handleNotificationsCSS)
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

	// PWA support (PART 16) — manifest, versioned service worker, translated fallback strings
	r.Get("/manifest.json", s.handleManifest)
	r.Get("/sw.js", s.handleServiceWorker)
	r.Get("/offline-strings.json", s.handleOfflineStrings)

	// Public content pages
	r.Get("/server", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/server/about", http.StatusMovedPermanently)
	})
	r.Get("/server/about", s.handleAboutPage)
	r.Get("/about", s.handleAboutPage)
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/about", "getAbout", "About this server", "none", true, false, http.HandlerFunc(s.handleAboutAPI))
	r.Get("/server/docs", s.handleDocsPage)
	r.Get("/docs", s.handleDocsPage)

	// Privacy, Contact, Help, Terms pages (AI.md PART 16) — dual web/API routes
	r.Get("/server/privacy", s.handlePrivacyPage)
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/privacy", "getPrivacy", "Privacy policy", "none", true, false, http.HandlerFunc(s.handlePrivacyAPI))
	r.Get("/server/contact", s.handleContactPage)
	r.Post("/server/contact", s.requireCSRF(s.handleContactPage))
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/contact", "getContact", "Contact information", "none", true, false, http.HandlerFunc(s.handleContactAPI))
	s.addAPIRoute(r, http.MethodPost, apiBase+"/server/contact", "submitContact", "Submit a contact request", "none", true, false, http.HandlerFunc(s.handleContactAPI))
	r.Get("/server/security/report/{tracking_id}", s.handleSecurityReportStatus)
	// Anonymous owner tokens (AI.md PART 12 — Owner Token Management).
	r.Get("/server/preferences", s.handlePreferencesPage)
	r.Post("/server/preferences", s.requireCSRF(s.handlePreferencesPage))
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/preferences", "getPreferences", "Read browser preferences", "none", true, false, http.HandlerFunc(s.handlePreferencesAPI))
	s.addAPIRoute(r, http.MethodPost, apiBase+"/server/preferences", "updatePreferences", "Update browser preferences", "none", true, false, http.HandlerFunc(s.handlePreferencesAPI))
	r.Get("/server/preferences/sync", s.handlePreferencesSyncPage)
	r.Post("/server/preferences/sync", s.requireCSRF(s.handlePreferencesSyncPage))
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/preferences/sync", "getPreferenceSync", "Export browser preferences", "none", true, false, http.HandlerFunc(s.handlePreferencesSyncAPI))
	r.Get("/server/preferences/sync/import", s.handlePreferencesSyncImportPage)
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/preferences/sync/import", "importPreferenceSync", "Import browser preferences", "none", true, false, http.HandlerFunc(s.handlePreferencesSyncImportAPI))
	r.Method(http.MethodGet, "/server/preferences/tokens", s.refreshOwnerCookie(http.HandlerFunc(s.handleOwnerTokensPage)))
	r.Method(http.MethodPost, "/server/preferences/token/create", s.refreshOwnerCookie(s.strictRateLimit(s.requireCSRF(s.handleIssuePrimaryTokenPage))))
	r.Method(http.MethodPost, "/server/preferences/token/restore", s.refreshOwnerCookie(s.strictRateLimit(s.requireCSRF(s.handleRestoreOwnerTokenPage))))
	r.Method(http.MethodPost, "/server/preferences/token/reveal", s.refreshOwnerCookie(s.strictRateLimit(s.requireCSRF(s.handleRevealPrimaryTokenPage))))
	r.Method(http.MethodPost, "/server/preferences/token/rotate", s.refreshOwnerCookie(s.strictRateLimit(s.requireCSRF(s.handleRotateTokenPage))))
	r.Method(http.MethodPost, "/server/preferences/token/revoke", s.refreshOwnerCookie(s.strictRateLimit(s.requireCSRF(s.handleRevokePrimaryTokenPage))))
	r.Method(http.MethodPost, "/server/preferences/tokens", s.refreshOwnerCookie(s.requireCSRF(s.handleCreateLinkedTokenPage)))
	r.Method(http.MethodPost, "/server/preferences/tokens/{id}/reveal", s.refreshOwnerCookie(s.strictRateLimit(s.requireCSRF(s.handleRevealLinkedTokenPage))))
	r.Method(http.MethodPost, "/server/preferences/tokens/{id}/rotate", s.refreshOwnerCookie(s.strictRateLimit(s.requireCSRF(s.handleRotateTokenPage))))
	r.Method(http.MethodPost, "/server/preferences/tokens/{id}/update", s.refreshOwnerCookie(s.requireCSRF(s.handleUpdateLinkedTokenPage)))
	r.Method(http.MethodPost, "/server/preferences/tokens/{id}/revoke", s.refreshOwnerCookie(s.requireCSRF(s.handleRevokeLinkedTokenPage)))
	r.Method(http.MethodPost, "/server/preferences/token/forget", s.refreshOwnerCookie(s.requireCSRF(s.handleForgetOwnerTokenPage)))
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/preferences/tokens", "listOwnerTokens", "List owner tokens", "owner", true, false, http.HandlerFunc(s.handleListOwnerTokensAPI))
	s.addAPIRouteStatus(r, http.MethodPost, apiBase+"/server/preferences/tokens/primary", "issuePrimaryToken", "Issue the primary token", "none", true, false, http.StatusCreated, s.strictRateLimit(s.handleIssuePrimaryTokenAPI))
	s.addAPIRoute(r, http.MethodPost, apiBase+"/server/preferences/tokens/primary/reveal", "revealPrimaryToken", "Reveal the primary token", "owner", true, false, s.strictRateLimit(s.handleRevealPrimaryTokenAPI))
	s.addAPIRoute(r, http.MethodPost, apiBase+"/server/preferences/tokens/primary/rotate", "rotatePrimaryToken", "Rotate the primary token", "owner", true, false, s.strictRateLimit(s.handleRotatePrimaryTokenAPI))
	s.addAPIRoute(r, http.MethodDelete, apiBase+"/server/preferences/tokens/primary", "revokePrimaryToken", "Revoke the primary token", "owner", true, false, s.strictRateLimit(s.handleRevokePrimaryTokenAPI))
	s.addAPIRouteStatus(r, http.MethodPost, apiBase+"/server/preferences/tokens", "createLinkedToken", "Create a linked token", "owner", true, false, http.StatusCreated, http.HandlerFunc(s.handleCreateLinkedTokenAPI))
	s.addAPIRoute(r, http.MethodPost, apiBase+"/server/preferences/tokens/{id}/reveal", "revealLinkedToken", "Reveal a linked token", "owner", true, false, s.strictRateLimit(s.handleRevealLinkedTokenAPI))
	s.addAPIRoute(r, http.MethodPost, apiBase+"/server/preferences/tokens/{id}/rotate", "rotateLinkedToken", "Rotate a linked token", "owner", true, false, s.strictRateLimit(s.handleRotateLinkedTokenAPI))
	s.addAPIRoute(r, http.MethodPatch, apiBase+"/server/preferences/tokens/{id}", "updateLinkedToken", "Update a linked token", "owner", true, false, http.HandlerFunc(s.handleUpdateLinkedTokenAPI))
	s.addAPIRoute(r, http.MethodDelete, apiBase+"/server/preferences/tokens/{id}", "revokeLinkedToken", "Revoke a linked token", "owner", true, false, http.HandlerFunc(s.handleRevokeLinkedTokenAPI))
	r.Get("/server/help", s.handleHelpPage)
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/help", "getHelp", "Server help", "none", true, false, http.HandlerFunc(s.handleHelpAPI))
	r.Get("/server/help/mcp", s.handleMCPHelpPage)
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/help/mcp", "getMCPHelp", "MCP integration help", "none", true, false, http.HandlerFunc(s.handleMCPHelpAPI))
	r.Get("/server/terms", s.handleTermsPage)
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/terms", "getTerms", "Terms of service", "none", true, false, http.HandlerFunc(s.handleTermsAPI))
	r.Get("/server/dpo", s.handleDPOPage)
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/dpo", "getDPO", "Data protection officer contact", "none", true, false, http.HandlerFunc(s.handleDPOAPI))
	r.Get("/server/security", s.handleSecurityPage)
	r.Get("/server/security/policy", s.handleSecurityPolicyPage)
	r.Get("/server/security/thanks", s.handleSecurityThanksPage)
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/security", "getSecurity", "Security policy information", "none", true, false, http.HandlerFunc(s.handleSecurityAPI))
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/security/policy", "getSecurityPolicy", "Security disclosure policy", "none", true, false, http.HandlerFunc(s.handleSecurityPolicyAPI))
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/security/thanks", "getSecurityThanks", "Security acknowledgments", "none", true, false, http.HandlerFunc(s.handleSecurityThanksAPI))

	// Cookie consent / CCPA opt-out (AI.md PART 16)
	r.Post("/server/consent", s.requireCSRF(s.handleConsent))
	r.Post("/server/ccpa", s.requireCSRF(s.handleCCPA))

	// Site banner / announcements dismissal (AI.md PART 16)
	r.Post("/announcements/dismiss", s.requireCSRF(s.handleAnnouncementDismiss))

	// Swagger/OpenAPI endpoints (AI.md PART 14)
	r.Get("/server/docs/swagger", s.handleSwaggerUI)
	s.addAPIRoute(r, http.MethodGet, "/api/swagger", "getOpenAPIAlias", "OpenAPI specification", "none", false, true, http.HandlerFunc(s.handleSwaggerJSON))
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/swagger", "getOpenAPI", "OpenAPI specification", "none", false, true, http.HandlerFunc(s.handleSwaggerJSON))

	// GraphQL endpoints (AI.md PART 14)
	r.Get("/server/docs/graphql", s.handleGraphiQL)
	r.Post("/server/docs/graphql", s.requireCSRF(s.handleGraphiQL))
	s.addAPIRoute(r, http.MethodPost, "/api/graphql", "executeGraphQLAlias", "Execute a GraphQL query", "none", false, true, http.HandlerFunc(s.handleGraphQL))
	s.addAPIRoute(r, http.MethodPost, apiBase+"/server/graphql", "executeGraphQL", "Execute a GraphQL query", "none", false, true, http.HandlerFunc(s.handleGraphQL))

	// WHOIS lookup form-submission fallback (no-JS browsers, curl, wget)
	r.Get("/whois", s.handleWHOISPage)

	// Owner/registrant search — web and API (public, rate-limited)
	r.Get("/whois/search", s.handleWHOISOwnerSearch)
	s.addAPIRouteModel(r, swagger.Route{Method: http.MethodGet, Path: apiBase + "/whois/search", OperationID: "ownerSearch", Summary: "Search local lookup history by owner", Auth: "none", Listed: true, Request: struct {
		Owner string `json:"owner"`
		Page  int    `json:"page,omitempty"`
		Limit int    `json:"limit,omitempty"`
	}{}, Response: swagger.APIResponseModel{}, Handler: http.HandlerFunc(s.handleWHOISOwnerSearch)})

	// API — specific typed lookups (registered before generic wildcard)
	s.addAPIRoute(r, http.MethodGet, apiBase+"/whois/domain/{domain}", "domainLookup", "Domain WHOIS lookup", "none", true, false, http.HandlerFunc(s.handleWHOISDomainLookup))
	s.addAPIRoute(r, http.MethodGet, apiBase+"/whois/ip/{ip}", "ipLookup", "IP WHOIS lookup", "none", true, false, http.HandlerFunc(s.handleWHOISIPLookup))
	s.addAPIRoute(r, http.MethodGet, apiBase+"/whois/asn/{asn}", "asnLookup", "ASN WHOIS lookup", "none", true, false, http.HandlerFunc(s.handleWHOISASNLookup))
	s.addAPIRoute(r, http.MethodGet, apiBase+"/whois/validate/{query}", "validateQuery", "Validate a lookup query", "none", true, false, http.HandlerFunc(s.handleWHOISValidate))

	// API — generic WHOIS lookup (catch-all, after specific routes)
	s.addAPIRoute(r, http.MethodGet, apiBase+"/whois/{query}", "whoisLookup", "Automatic WHOIS lookup", "none", true, false, http.HandlerFunc(s.handleWHOIS))

	// API — Bulk lookup (requires server token)
	s.addAPIRouteModel(r, swagger.Route{Method: http.MethodPost, Path: apiBase + "/whois/bulk", OperationID: "bulkLookup", Summary: "Bulk WHOIS lookup", Auth: "operator", Listed: false, Request: struct {
		Queries []string `json:"queries"`
	}{}, Response: swagger.APIResponseModel{}, Handler: s.requireToken(s.handleWHOISBulkLookup)})

	// Autodiscover endpoint (PART 32) — non-versioned, public
	s.addAPIRoute(r, http.MethodGet, "/api/autodiscover", "autodiscover", "Server autodiscovery", "none", true, false, http.HandlerFunc(s.handleAutodiscover))

	// CLI binary download (PART 32) — public by default; streams prebuilt binaries
	r.Get("/cli/binaries/*", s.handleCLIBinaryDownload)

	// Locale JSON files (PART 30) — served for JS consumers; content from embedded i18n files
	r.Get("/locales/*", s.handleLocaleJSON)

	// API — utility (public)
	s.addAPIRoute(r, http.MethodGet, apiBase+"/whois-servers", "listWhoisServers", "List WHOIS servers", "none", true, false, http.HandlerFunc(s.handleWhoisServers))
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/stats", "getStats", "Server statistics", "none", true, false, http.HandlerFunc(s.handleStats))

	// API — server operations (requires server token)
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/schedulers", "listSchedulerTasks", "List scheduler tasks", "operator", false, false, s.requireToken(s.handleSchedulerStatus))
	s.addAPIRoute(r, http.MethodPost, apiBase+"/server/schedulers/run", "runSchedulerTask", "Run a scheduler task", "operator", false, false, s.requireToken(s.handleSchedulerRun))
	s.addAPIRoute(r, http.MethodGet, apiBase+"/server/backups", "listBackups", "List backups", "operator", false, false, s.requireToken(s.handleBackupStatus))
	s.addAPIRoute(r, http.MethodPost, apiBase+"/server/backups/run", "createBackup", "Create a backup", "operator", false, false, s.requireToken(s.handleBackupRun))

	// Debug endpoints (PART 6) — registered only when --debug / DEBUG=true
	s.registerDebugRoutes(r)

	// Public web interface — root only; must come after all other routes
	r.Get("/", s.handlePublicWHOISPage)

	// Catch-all 404 for all unmatched paths
	r.NotFound(s.handleNotFound)

	s.apiRouter = r
	return s.offlineCacheSignal(s.baseURLRouter(apiContentNegotiation(r, s.apiRoutes)))
}

// setupMiddleware configures the middleware chain per AI.md PART 5.
// The last handler applied is the outermost wrapper and therefore runs FIRST on each request.
// Recovery wraps the complete chain; request context is attached before it runs.
// Execution order (first → last): recovery → URLNormalize → RequestID → PathSecurity →
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
	// 7. Rate limiting — configured endpoint class plus global burst ceiling.
	handler = s.configuredRateLimitMiddleware(handler)
	// 6. Blocklist — blocks denied IPs before rate-limit accounting.
	handler = BlocklistMiddleware(handler)
	// 5. Allowlist — enforces IP allowlist before blocklist.
	handler = AllowlistMiddleware(handler)
	// 4a. Request-language detection (project-specific, between security headers and allowlist).
	handler = s.languageMiddleware(handler)
	// 4. Security response headers + Sec-Fetch validation (AI.md PART 11).
	handler = SecFetchValidationMiddleware(handler)
	handler = SecurityHeadersMiddleware(s.config.FQDN, s.config.APIVersion, s.config.TLS.Enabled, s.config.Debug)(handler)
	// 3. CORS headers for API paths — handles OPTIONS preflight before route handlers.
	handler = CORSMiddleware(s.config.Cors, s.config.TrustedProxies.Additional)(handler)
	// 2. Path traversal check and normalization.
	handler = PathSecurityMiddleware(handler)
	// 1b. Request ID assignment — before PathSecurity so the ID is always set.
	handler = RequestIDMiddleware(handler)
	// 1. URL normalization — outermost, runs first on every request.
	handler = URLNormalizeMiddleware(handler)
	return withServerContext(s, s.recoveryMiddleware(handler))
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
	if s.pidFileOverride != "" {
		return filepath.Clean(s.pidFileOverride)
	}
	// System-wide PID file when running as root.
	if os.Geteuid() == 0 {
		return filepath.Join("/var/run", constants.InternalOrg, constants.InternalName, constants.InternalName+".pid")
	}
	// User-specific PID files live inside the resolved data directory so --data
	// and DATA_DIR continue to work after startup has resolved the paths.
	if s.config != nil && strings.TrimSpace(s.config.DataDir) != "" {
		return filepath.Join(s.config.DataDir, constants.InternalName+".pid")
	}
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
				writeRequestError(w, r, http.StatusUnauthorized)
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
	now := time.Now().UTC()
	reportURL := s.config.Web.Security.ReportURL
	if reportURL == "" {
		reportURL = constants.RepoURL + "/security/advisories/new"
	}
	content := fmt.Sprintf("Contact: %s\n", reportURL)
	if reportURL := s.securityReportURL(r.Context(), r, now); reportURL != "" {
		content += fmt.Sprintf("Contact: %s\n", reportURL)
	}
	if contact := s.securityEmail(); contact != "" {
		content += "Contact: mailto:" + contact + "\n"
	}
	content += fmt.Sprintf("Policy: %s\nExpires: %s\nPreferred-Languages: en\n", s.BuildURL(r, "/server/security/policy"), s.securityExpires(now))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, content)
}

// handleSitemap serves dynamically generated sitemap.xml (AI.md PART 16)
// REQUIRED: ALL projects MUST serve a dynamically generated sitemap
func (s *Server) handleSitemap(w http.ResponseWriter, r *http.Request) {
	lastMod := time.Now().UTC().Format("2006-01-02")
	type sitemapPage struct {
		path, frequency, priority string
	}
	pages := []sitemapPage{
		{path: "/", frequency: "daily", priority: "1.0"},
		{path: "/about", frequency: "weekly", priority: "0.8"},
		{path: "/docs", frequency: "weekly", priority: "0.8"},
		{path: "/server/docs/swagger", frequency: "weekly", priority: "0.7"},
		{path: "/server/docs/graphql", frequency: "weekly", priority: "0.7"},
		{path: "/server/privacy", frequency: "weekly", priority: "0.8"},
		{path: "/server/help", frequency: "weekly", priority: "0.8"},
		{path: "/server/terms", frequency: "weekly", priority: "0.8"},
		{path: "/server/dpo", frequency: "weekly", priority: "0.8"},
		{path: "/server/security", frequency: "weekly", priority: "0.8"},
		{path: "/server/security/policy", frequency: "weekly", priority: "0.8"},
	}
	for _, page := range s.registeredPages("help") {
		for _, registered := range serverPageRegistry {
			if registered.Path == page.Path && registered.Sitemap {
				pages = append(pages, sitemapPage{path: page.Path, frequency: "weekly", priority: "0.8"})
				break
			}
		}
	}
	var body strings.Builder
	body.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n")
	for _, page := range pages {
		var escapedURL strings.Builder
		_ = xml.EscapeText(&escapedURL, []byte(s.BuildURL(r, page.path)))
		fmt.Fprintf(&body, "  <url><loc>%s</loc><lastmod>%s</lastmod><changefreq>%s</changefreq><priority>%s</priority></url>\n", escapedURL.String(), lastMod, page.frequency, page.priority)
	}
	body.WriteString("</urlset>\n")

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body.String()))
}

// handleRobotsTxt serves robots.txt file (AI.md PART 14)
func (s *Server) handleRobotsTxt(w http.ResponseWriter, r *http.Request) {
	sitemapURL := s.BuildURL(r, "/sitemap.xml")

	content := fmt.Sprintf("User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: %s\n", sitemapURL)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, content)
}

// handleLLMsTxt serves llms.txt for AI agent discovery (AI.md PART 14).
// Required for ALL projects. Tells AI agents what the application does and
// what API endpoints are available.
func (s *Server) handleLLMsTxt(w http.ResponseWriter, r *http.Request) {
	// Security contact
	_, requestHost, _ := s.GetURLVars(r)
	securityContact := "security@" + requestHost
	if requestHost == "" {
		securityContact = "security@localhost"
	}

	// Rate limit info
	rateLimit := s.config.RateLimit.Read.Requests
	if rateLimit == 0 {
		rateLimit = 100
	}

	apiBase := s.config.APIBasePath()
	var endpoints strings.Builder
	for _, route := range s.apiRoutes() {
		if !route.Listed || route.Internal || route.Auth == "operator" || route.Auth == "service" || !strings.HasPrefix(route.Path, "/api/") {
			continue
		}
		fmt.Fprintf(&endpoints, "- %s %s — %s\n", route.Method, route.Path, route.Summary)
	}
	content := fmt.Sprintf(`# caswhois
> WHOIS lookup service with domain, IP, and ASN queries

## API
Base URL: %s
Authentication: Bearer token where an operation requires it
Rate limit: %d requests/minute

## Endpoints
%s
## Output formats
- JSON (Accept: application/json)
- Plain text (Accept: text/plain)

## Contact
API issues: %s
Security: %s
`, s.BuildURL(r, apiBase), rateLimit, endpoints.String(), securityContact, securityContact)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, content)
}

// handleWellKnownNotFound returns 404 for unknown /.well-known/* entries.
// Per AI.md PART 14: unsupported well-known entries MUST return 404.
func (s *Server) handleWellKnownNotFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprint(w, "404 Not Found\n")
}

// wellKnownMethodCheck is middleware that enforces GET/HEAD only for /.well-known/*.
// Per AI.md PART 14: other methods MUST return 405 Method Not Allowed.
func wellKnownMethodCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = fmt.Fprint(w, "405 Method Not Allowed\n")
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
