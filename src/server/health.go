package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/apimgr/whois/src/cache"
	"github.com/apimgr/whois/src/common/constants"
	humanformat "github.com/apimgr/whois/src/common/format"
	"github.com/apimgr/whois/src/config"
	"github.com/apimgr/whois/src/health"
	"github.com/apimgr/whois/src/i2p"
	"github.com/apimgr/whois/src/ratelimit"
	castor "github.com/apimgr/whois/src/tor"
)

// HealthResponse represents the /healthz response (per AI.md PART 13).
// Field order matches the canonical spec order.
type HealthResponse struct {
	// 1. Project identification (from config branding)
	Project ProjectInfo `json:"project"`

	// 2. Overall status
	// Status is one of "healthy", "degraded", or "unhealthy".
	Status string `json:"status"`
	// PendingRestart is true when a restart is needed to apply a config change.
	PendingRestart bool `json:"pending_restart,omitempty"`
	// RestartReason lists settings that changed and require a restart.
	RestartReason []string `json:"restart_reason,omitempty"`
	// Maintenance is present only while status is maintenance.
	Maintenance *MaintenanceInfo `json:"maintenance,omitempty"`

	// 3. Version & build info
	Version   string    `json:"version"`
	GoVersion string    `json:"go_version"`
	Build     BuildInfo `json:"build"`

	// 4. Runtime info
	Uptime    string    `json:"uptime"`
	Mode      string    `json:"mode"`
	Timestamp time.Time `json:"timestamp"`

	// 5. Features (non-negotiable first, then caswhois app-specific)
	Features FeaturesInfo `json:"features"`

	// 6. Component health checks
	Checks ChecksInfo `json:"checks"`

	// 7. Statistics (caswhois-specific)
	Stats StatsInfo `json:"stats"`
}

type MaintenanceInfo struct {
	Reason      string          `json:"reason"`
	Message     string          `json:"message"`
	Since       time.Time       `json:"since"`
	SelfHealing SelfHealingInfo `json:"self_healing"`
}

type SelfHealingInfo struct {
	Enabled     bool       `json:"enabled"`
	Exhausted   bool       `json:"exhausted"`
	Attempts    int        `json:"attempts"`
	LastAttempt *time.Time `json:"last_attempt"`
	NextAttempt *time.Time `json:"next_attempt"`
}

// ProjectInfo - from branding config (AI.md PART 16)
type ProjectInfo struct {
	Name        string `json:"name"`
	Tagline     string `json:"tagline"`
	Description string `json:"description"`
}

// BuildInfo - from build-time variables (AI.md PART 7)
type BuildInfo struct {
	// Commit is the git short hash (7 chars) embedded at build time.
	Commit string `json:"commit"`
	// Date is the ISO 8601 build timestamp embedded at build time.
	Date string `json:"date"`
}

// TorInfo - Tor hidden service status (AI.md PART 31)
type TorInfo struct {
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	Status   string `json:"status"`
	Hostname string `json:"hostname"`
}

type I2PInfo struct {
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	State    string `json:"state"`
	Status   string `json:"status"`
	Hostname string `json:"hostname"`
	Provider string `json:"provider"`
}

// FeaturesInfo - public features status (AI.md PART 13).
// Non-negotiable fields come first; caswhois app-specific fields follow.
type FeaturesInfo struct {
	// PART 31: Tor hidden service
	Tor TorInfo `json:"tor"`
	I2P I2PInfo `json:"i2p"`
	// PART 19: GeoIP database
	GeoIP bool `json:"geoip"`
	// caswhois app-specific features
	RateLimiting bool `json:"rate_limiting"`
	Caching      bool `json:"caching"`
	Email        bool `json:"email"`
}

// ChecksInfo stores core component results and ordered optional dataset checks.
type ChecksInfo struct {
	Database  string          `json:"database"`
	Cache     string          `json:"cache"`
	Disk      string          `json:"disk"`
	Scheduler string          `json:"scheduler"`
	Tor       string          `json:"tor,omitempty"`
	I2P       string          `json:"i2p,omitempty"`
	Datasets  []health.Result `json:"-"`
}

// StatsInfo - caswhois statistics
type StatsInfo struct {
	RequestsTotal int64 `json:"requests_total"`
	Requests24h   int64 `json:"requests_24h"`
	ActiveConns   int   `json:"active_connections"`
	CacheHits     int64 `json:"cache_hits"`
	CacheMisses   int64 `json:"cache_misses"`
	WhoisQueries  int64 `json:"whois_queries"`
	DomainQueries int64 `json:"domain_queries"`
	IPQueries     int64 `json:"ip_queries"`
	ASNQueries    int64 `json:"asn_queries"`
}

type healthPageData struct {
	translatablePageData
	AppName       string
	UptimeDisplay string
	HealthResponse
}

var healthPageTmpl = mustParseTemplate("health", "page/health.tmpl")

// NewMaintenanceReadOnlyHandler serves public, database-independent pages and
// assets while the application retries database startup. The returned cleanup
// function releases the temporary in-memory cache and rate limiters.
func NewMaintenanceReadOnlyHandler(cfg *config.ServerConfig) (http.Handler, func()) {
	read := cfg.RateLimit.Read
	if read.Requests <= 0 || read.Window <= 0 {
		read = config.RateLimitEndpointConfig{Requests: 120, Window: 60}
	}
	health := cfg.RateLimit.Health
	if health.Requests <= 0 || health.Window <= 0 {
		health = config.RateLimitEndpointConfig{Requests: 120, Window: 60}
	}
	write := cfg.RateLimit.Write
	if write.Requests <= 0 || write.Window <= 0 {
		write = config.RateLimitEndpointConfig{Requests: 10, Window: 60}
	}
	global := cfg.RateLimit.GlobalBurst
	if global <= 0 {
		global = 240
	}
	strict := cfg.RateLimit.Strict
	if strict.Requests <= 0 || strict.Window <= 0 {
		strict = config.RateLimitEndpointConfig{Requests: 10, Window: 900}
	}
	authFailures := cfg.RateLimit.AuthFailures
	if authFailures.Requests <= 0 || authFailures.Window <= 0 {
		authFailures = config.RateLimitEndpointConfig{Requests: 5, Window: 900}
	}
	s := &Server{
		config:             cfg,
		cache:              cache.NewMemoryCache(16*1024*1024, time.Minute),
		ratelimit:          ratelimit.New(read.Requests, time.Duration(read.Window)*time.Second),
		writeLimiter:       ratelimit.New(write.Requests, time.Duration(write.Window)*time.Second),
		healthLimiter:      ratelimit.New(health.Requests, time.Duration(health.Window)*time.Second),
		globalBurstLimiter: ratelimit.New(global, time.Minute),
		strictLimiter:      ratelimit.New(strict.Requests, time.Duration(strict.Window)*time.Second),
		authFailureLimiter: ratelimit.New(authFailures.Requests, time.Duration(authFailures.Window)*time.Second),
		startTime:          time.Now(),
	}
	handler := s.setupMiddleware(s.setupRoutes())
	cleanup := func() {
		s.ratelimit.Close()
		s.writeLimiter.Close()
		s.healthLimiter.Close()
		s.globalBurstLimiter.Close()
		s.strictLimiter.Close()
		s.authFailureLimiter.Close()
		_ = s.cache.Close()
	}
	return handler, cleanup
}

// RenderMaintenanceHealth writes the normal health representation for a
// database-unavailable maintenance response, including content negotiation.
func RenderMaintenanceHealth(w http.ResponseWriter, r *http.Request, cfg *config.ServerConfig, response HealthResponse) {
	s := &Server{config: cfg, startTime: time.Now().Add(-parseHealthUptime(response.Uptime))}
	if !strings.HasPrefix(r.URL.Path, "/api/") && DetectClientType(r) == ClientTypeHTML {
		data := healthPageData{
			translatablePageData: s.newPageData(w, r),
			AppName:              s.brandName(),
			UptimeDisplay:        response.Uptime,
			HealthResponse:       response,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(healthHTTPStatus(response.Status))
		if err := s.renderTemplate(healthPageTmpl, w, r, data); err != nil {
			writeRequestError(w, r, http.StatusInternalServerError)
		}
		return
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		s.renderHealthJSON(w, response)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") && DetectClientType(r) == ClientTypeText {
		s.renderHealthFrontendText(w, r, response)
		return
	}
	if strings.Contains(accept, "text/plain") {
		s.renderHealthText(w, response)
		return
	}
	s.renderHealthJSON(w, response)
}

// IsMaintenanceReadOnlyPath reports whether the request can be served from
// configuration or embedded assets without consulting the database.
func IsMaintenanceReadOnlyPath(cfg *config.ServerConfig, requestPath string) bool {
	base := normalizeBaseURL(cfg.BaseURL)
	if base != "" {
		if requestPath == base {
			requestPath = "/"
		} else if strings.HasPrefix(requestPath, base+"/") {
			requestPath = strings.TrimPrefix(requestPath, base)
		} else {
			return false
		}
	}
	if strings.HasPrefix(requestPath, "/static/") || strings.HasPrefix(requestPath, "/locales/") {
		return true
	}
	if requestPath == "/" || requestPath == "/manifest.json" || requestPath == "/sw.js" || requestPath == "/offline-strings.json" || requestPath == "/sitemap.xml" || requestPath == "/robots.txt" || requestPath == "/llms.txt" || requestPath == "/api/autodiscover" || requestPath == "/api/swagger" {
		return true
	}
	if requestPath == "/.well-known/security.txt" || requestPath == "/.well-known/llms.txt" {
		return true
	}
	switch requestPath {
	case "/about", "/docs", "/server/about", "/server/docs", "/server/docs/swagger", "/server/docs/graphql", "/server/help", "/server/help/mcp", "/server/privacy", "/server/terms", "/server/dpo", "/server/security/policy":
		return true
	}
	apiBase := cfg.APIBasePath()
	for _, suffix := range []string{"/server/about", "/server/privacy", "/server/help", "/server/terms", "/server/dpo", "/server/security/policy"} {
		if requestPath == apiBase+suffix {
			return true
		}
	}
	return false
}

// handleHealth handles /healthz and /api/{version}/healthz requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := s.buildHealthResponse()
	statusCode := healthHTTPStatus(response.Status)
	if !strings.HasPrefix(r.URL.Path, "/api/") && DetectClientType(r) == ClientTypeHTML {
		data := healthPageData{
			translatablePageData: s.newPageData(w, r),
			AppName:              s.brandName(),
			UptimeDisplay:        humanformat.Duration(time.Since(s.startTime), LangFromContext(r.Context())),
			HealthResponse:       response,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(statusCode)
		if err := s.renderTemplate(healthPageTmpl, w, r, data); err != nil {
			writeRequestError(w, r, http.StatusInternalServerError)
		}
		return
	}

	// Content negotiation per AI.md PART 14:
	// Only serve text/plain when the client explicitly requests it.
	// Default (no Accept header, or unknown) → JSON.
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		s.renderHealthJSON(w, response)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") && DetectClientType(r) == ClientTypeText {
		s.renderHealthFrontendText(w, r, response)
		return
	}
	if strings.Contains(accept, "text/plain") {
		s.renderHealthText(w, response)
		return
	}
	s.renderHealthJSON(w, response)
}

func (s *Server) renderHealthFrontendText(w http.ResponseWriter, r *http.Request, response HealthResponse) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(healthHTTPStatus(response.Status))
	lang := LangFromContext(r.Context())
	formatTime := func(value time.Time) string {
		return value.UTC().Format("January 2, 2006 at 3:04 PM UTC")
	}
	buildDate := response.Build.Date
	if parsed, err := time.Parse(time.RFC3339, buildDate); err == nil {
		buildDate = formatTime(parsed)
	}
	statusKey := "health." + response.Status
	statusLabel := translateKey(lang, statusKey)
	if statusLabel == statusKey {
		statusLabel = response.Status
	}
	_, _ = fmt.Fprintf(w, "%s - %s\n\n", response.Project.Name, response.Project.Tagline)
	_, _ = fmt.Fprintf(w, "%s:    %s\n", translateKey(lang, "health.status"), statusLabel)
	_, _ = fmt.Fprintf(w, "%s:   %s\n", translateKey(lang, "health.version"), response.Version)
	_, _ = fmt.Fprintf(w, "%s:     %s (%s)\n", translateKey(lang, "health.build"), response.Build.Commit, buildDate)
	_, _ = fmt.Fprintf(w, "%s:        %s\n", translateKey(lang, "health.go_version"), response.GoVersion)
	_, _ = fmt.Fprintf(w, "%s:    %s\n", translateKey(lang, "health.uptime"), humanformat.Duration(time.Since(s.startTime), lang))
	_, _ = fmt.Fprintf(w, "%s:      %s\n", translateKey(lang, "health.mode"), response.Mode)
	_, _ = fmt.Fprintf(w, "%s:   %s\n\n", translateKey(lang, "health.checked"), formatTime(response.Timestamp))
	_, _ = fmt.Fprintln(w, translateKey(lang, "health.features"))
	_, _ = fmt.Fprintf(w, "  %s:     %s", translateKey(lang, "health.tor"), healthStatusLabel(lang, response.Features.Tor.Status))
	if response.Features.Tor.Hostname != "" {
		_, _ = fmt.Fprintf(w, " - %s", response.Features.Tor.Hostname)
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "  %s:     %s", translateKey(lang, "health.i2p"), healthStatusLabel(lang, response.Features.I2P.Status))
	if response.Features.I2P.Hostname != "" {
		_, _ = fmt.Fprintf(w, " - %s", response.Features.I2P.Hostname)
	}
	_, _ = fmt.Fprintln(w)
	geoIPLabel := translateKey(lang, "common.disabled")
	if response.Features.GeoIP {
		geoIPLabel = translateKey(lang, "common.enabled")
	}
	_, _ = fmt.Fprintf(w, "  GeoIP:   %s\n\n", geoIPLabel)
	_, _ = fmt.Fprintln(w, translateKey(lang, "health.checks"))
	_, _ = fmt.Fprintf(w, "  %-19s %s\n", translateKey(lang, "health.database")+":", response.Checks.Database)
	_, _ = fmt.Fprintf(w, "  %-19s %s\n", translateKey(lang, "health.cache")+":", response.Checks.Cache)
	_, _ = fmt.Fprintf(w, "  %-19s %s\n", translateKey(lang, "health.disk")+":", response.Checks.Disk)
	_, _ = fmt.Fprintf(w, "  %-19s %s\n", translateKey(lang, "health.scheduler")+":", response.Checks.Scheduler)
	if response.Checks.Tor != "" {
		_, _ = fmt.Fprintf(w, "  %-19s %s\n", translateKey(lang, "health.tor")+":", response.Checks.Tor)
	}
	if response.Checks.I2P != "" {
		_, _ = fmt.Fprintf(w, "  %-19s %s\n", translateKey(lang, "health.i2p")+":", response.Checks.I2P)
	}
	for _, check := range response.Checks.Datasets {
		label := translateFormat(lang, "health.check.unknown", "key", check.Key)
		_, _ = fmt.Fprintf(w, "  %-19s %s\n", label+":", check.Status)
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, translateKey(lang, "health.statistics"))
	_, _ = fmt.Fprintf(w, "  %s: %s\n", translateKey(lang, "health.requests_total"), humanformat.Count(response.Stats.RequestsTotal, lang))
	_, _ = fmt.Fprintf(w, "  %s: %s\n", translateKey(lang, "health.requests_24h"), humanformat.Count(response.Stats.Requests24h, lang))
	_, _ = fmt.Fprintf(w, "  %s: %s\n", translateKey(lang, "health.active_connections"), humanformat.Count(int64(response.Stats.ActiveConns), lang))
}

func parseHealthUptime(value string) time.Duration {
	var elapsed time.Duration
	for _, field := range strings.Fields(value) {
		if len(field) < 2 {
			continue
		}
		amount, err := strconv.Atoi(field[:len(field)-1])
		if err != nil {
			continue
		}
		switch field[len(field)-1] {
		case 'd':
			elapsed += time.Duration(amount) * 24 * time.Hour
		case 'h':
			elapsed += time.Duration(amount) * time.Hour
		case 'm':
			elapsed += time.Duration(amount) * time.Minute
		case 's':
			elapsed += time.Duration(amount) * time.Second
		}
	}
	return elapsed
}

func healthStatusLabel(lang, status string) string {
	key := "health." + status
	label := translateKey(lang, key)
	if label == key {
		return status
	}
	return label
}

// buildHealthResponse builds the health response data
func (s *Server) buildHealthResponse() HealthResponse {
	uptime := time.Since(s.startTime)

	// Get cache stats
	ctx := context.Background()
	var cacheStats *cache.Stats
	var cacheErr error
	if s.cache != nil {
		cacheStats, cacheErr = s.cache.Stats(ctx)
	}
	if cacheStats == nil {
		cacheStats = &cache.Stats{}
	}

	// Build response
	name := s.config.Branding.Title
	if name == "" {
		name = constants.InternalName
	}
	tagline := s.config.Branding.Tagline
	if tagline == "" {
		tagline = "WHOIS Lookup Service"
	}
	description := s.config.Branding.Description
	if description == "" {
		description = "Domain, IP, and ASN WHOIS lookup service"
	}

	checks := ChecksInfo{
		Database:  s.checkDatabase(),
		Cache:     s.checkCache(cacheErr),
		Disk:      s.checkDisk(),
		Scheduler: s.checkScheduler(),
		Datasets:  health.Snapshot(),
	}
	// checks.tor is reported only when the Tor hidden service is enabled (AI.md PART 13).
	if tor := s.buildTorInfo(); tor.Enabled {
		switch tor.Status {
		case "unavailable":
			checks.Tor = "degraded"
		default:
			checks.Tor = "ok"
		}
	}
	i2pInfo := s.buildI2PInfo()
	if i2pInfo.Enabled {
		if i2pInfo.Status == "unavailable" {
			checks.I2P = "degraded"
		} else {
			checks.I2P = "ok"
		}
	}

	status := getOverallStatus(checks)
	var pendingRestart bool
	var restartReason []string
	if s.configManager != nil {
		pendingRestart = s.configManager.PendingRestart()
		if pendingRestart {
			restartReason = s.configManager.RestartSettings()
			if status == "healthy" {
				status = "restart_required"
			}
		}
	}
	if s.shuttingDown.Load() {
		status = "shutting_down"
	}
	return HealthResponse{
		Project: ProjectInfo{
			Name:        name,
			Tagline:     tagline,
			Description: description,
		},
		Status:         status,
		PendingRestart: pendingRestart,
		RestartReason:  restartReason,
		Version:        Version,
		GoVersion:      runtime.Version(),
		Build: BuildInfo{
			Commit: CommitID,
			Date:   BuildDate,
		},
		Uptime:    formatUptime(uptime),
		Mode:      s.config.Mode,
		Timestamp: time.Now().UTC(),
		Features: FeaturesInfo{
			Tor:          s.buildTorInfo(),
			I2P:          s.buildI2PInfo(),
			GeoIP:        s.geoip != nil && s.geoip.Enabled(),
			RateLimiting: true,
			Caching:      true,
			Email:        s.email != nil && s.email.IsEnabled(),
		},
		Checks: checks,
		Stats: StatsInfo{
			RequestsTotal: s.stats.requestsTotal.Load(),
			Requests24h:   s.stats.requests24h.Load(),
			ActiveConns:   int(s.stats.activeConns.Load()),
			CacheHits:     cacheStats.Hits,
			CacheMisses:   cacheStats.Misses,
			WhoisQueries:  s.stats.domainQueries.Load() + s.stats.ipQueries.Load() + s.stats.asnQueries.Load(),
			DomainQueries: s.stats.domainQueries.Load(),
			IPQueries:     s.stats.ipQueries.Load(),
			ASNQueries:    s.stats.asnQueries.Load(),
		},
	}
}

// checkCache reports whether the configured cache backend can provide a
// health snapshot. Cache failures are non-critical because requests can use
// the database and the in-process fallback.
func (s *Server) checkCache(statsErr error) string {
	if s.cache == nil || statsErr != nil {
		return "error"
	}
	return "ok"
}

// checkDisk checks that the configured data and configuration locations are
// reachable. Paths and filesystem errors are never exposed in health output.
func (s *Server) checkDisk() string {
	return checkDiskConfig(s.config)
}

func checkDiskConfig(cfg *config.ServerConfig) string {
	directories := []string{cfg.ConfigDir, cfg.GetLogDir()}
	driver, _, _ := cfg.GetDatabaseConfig()
	if driver == "sqlite" || driver == "" {
		directories = append(directories, cfg.GetDatabaseDir())
	}
	for _, directory := range directories {
		if directory == "" {
			continue
		}
		info, err := os.Stat(directory)
		if err != nil || !info.IsDir() {
			return "error"
		}
	}
	return "ok"
}

// MaintenanceHealthComponents reports the probes available before the normal
// server, scheduler, and provider managers have started.
func MaintenanceHealthComponents(cfg *config.ServerConfig) (FeaturesInfo, ChecksInfo) {
	features := FeaturesInfo{
		GeoIP: cfg.GeoIP.Enabled, RateLimiting: true, Caching: true,
		Tor: TorInfo{Status: "disabled"},
		I2P: I2PInfo{State: "disabled", Status: "disabled", Provider: "none"},
	}
	checks := ChecksInfo{
		Database: "error", Cache: checkConfiguredCache(cfg), Disk: checkDiskConfig(cfg),
		Scheduler: "error", Datasets: health.Snapshot(),
	}
	if castor.FindBinary(cfg.Tor.Binary) != "" {
		features.Tor = TorInfo{Enabled: true, Status: "starting"}
		checks.Tor = "ok"
	}
	if cfg.I2P.Enabled {
		provider, _, _ := resolveMaintenanceI2P(cfg.I2P)
		if provider != "" {
			features.I2P = I2PInfo{Enabled: true, State: "starting", Status: "starting", Provider: string(provider)}
			checks.I2P = "ok"
		} else {
			features.I2P = I2PInfo{State: "no_provider", Status: "disabled", Provider: "none"}
		}
	}
	return features, checks
}

func checkConfiguredCache(cfg *config.ServerConfig) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	configured, err := cache.New(ctx, cache.Config{
		Type: cfg.Cache.Type, URL: cfg.Cache.URL, Host: cfg.Cache.Host, Port: cfg.Cache.Port,
		Username: cfg.Cache.Username, Password: cfg.Cache.Password, DB: cfg.Cache.DB,
		TLS: cfg.Cache.TLS, TLSSkipVerify: cfg.Cache.TLSSkipVerify, PoolSize: cfg.Cache.PoolSize,
		MinIdle: cfg.Cache.MinIdle, Timeout: cfg.Cache.Timeout, Prefix: cfg.Cache.Prefix,
	})
	if err != nil {
		return "error"
	}
	_, statsErr := configured.Stats(ctx)
	closeErr := configured.Close()
	if statsErr != nil || closeErr != nil {
		return "error"
	}
	return "ok"
}

func resolveMaintenanceI2P(cfg config.I2PConfig) (i2p.Provider, string, string) {
	if binary := i2p.FindBinary(cfg.Binary); binary != "" {
		return i2p.ProviderI2PD, binary, ""
	}
	address := cfg.SAMAddress
	if address == "" {
		address = "127.0.0.1:7656"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if i2p.ProbeSAM(ctx, address) {
		return i2p.ProviderSAM, "", address
	}
	return "", "", ""
}

func (s *Server) buildI2PInfo() I2PInfo {
	if !s.config.I2P.Enabled {
		return I2PInfo{State: "disabled", Status: "disabled", Provider: "none"}
	}
	s.i2pMu.RLock()
	svc, state, provider := s.i2pService, s.i2pStatus, s.i2pProvider
	s.i2pMu.RUnlock()
	if state == "" {
		state = "starting"
	}
	if svc != nil {
		provider = svc.Provider()
	}
	providerName := string(provider)
	if providerName == "" {
		providerName = "none"
	}
	if state == "no_provider" || provider == "" {
		return I2PInfo{State: "no_provider", Status: "disabled", Provider: "none"}
	}
	status := "starting"
	switch state {
	case "running":
		status = "healthy"
	case "error":
		status = "unavailable"
	}
	address := ""
	if svc != nil {
		address = svc.Address()
	}
	return I2PInfo{Enabled: true, Running: state == "running", State: state, Status: status, Hostname: address, Provider: providerName}
}

func (s *Server) currentI2P() *i2p.Service {
	s.i2pMu.RLock()
	defer s.i2pMu.RUnlock()
	return s.i2pService
}

// renderHealthJSON renders health response as JSON
func (s *Server) renderHealthJSON(w http.ResponseWriter, response HealthResponse) {
	writeJSON(w, healthHTTPStatus(response.Status), response)
}

// renderHealthText renders health response as plain text
func (s *Server) renderHealthText(w http.ResponseWriter, response HealthResponse) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(healthHTTPStatus(response.Status))

	// Per AI.md PART 13: Fields in canonical order, flattened with dot notation
	_, _ = fmt.Fprintf(w, "# 1. Project\n")
	_, _ = fmt.Fprintf(w, "project.name: %s\n", response.Project.Name)
	_, _ = fmt.Fprintf(w, "project.tagline: %s\n", response.Project.Tagline)
	_, _ = fmt.Fprintf(w, "project.description: %s\n", response.Project.Description)
	_, _ = fmt.Fprintf(w, "\n")

	_, _ = fmt.Fprintf(w, "# 2. Status\n")
	_, _ = fmt.Fprintf(w, "status: %s\n", response.Status)
	_, _ = fmt.Fprintf(w, "\n")

	_, _ = fmt.Fprintf(w, "# 3. Version & Build\n")
	_, _ = fmt.Fprintf(w, "version: %s\n", response.Version)
	_, _ = fmt.Fprintf(w, "go_version: %s\n", response.GoVersion)
	_, _ = fmt.Fprintf(w, "build.commit: %s\n", response.Build.Commit)
	_, _ = fmt.Fprintf(w, "build.date: %s\n", response.Build.Date)
	_, _ = fmt.Fprintf(w, "\n")

	_, _ = fmt.Fprintf(w, "# 4. Runtime\n")
	_, _ = fmt.Fprintf(w, "uptime: %s\n", response.Uptime)
	_, _ = fmt.Fprintf(w, "mode: %s\n", response.Mode)
	_, _ = fmt.Fprintf(w, "timestamp: %s\n", response.Timestamp.Format(time.RFC3339))
	_, _ = fmt.Fprintf(w, "\n")

	_, _ = fmt.Fprintf(w, "# 5. Features\n")
	_, _ = fmt.Fprintf(w, "features.rate_limiting: %v\n", response.Features.RateLimiting)
	_, _ = fmt.Fprintf(w, "features.caching: %v\n", response.Features.Caching)
	_, _ = fmt.Fprintf(w, "features.geoip: %v\n", response.Features.GeoIP)
	_, _ = fmt.Fprintf(w, "features.email: %v\n", response.Features.Email)
	_, _ = fmt.Fprintf(w, "features.tor.enabled: %v\n", response.Features.Tor.Enabled)
	_, _ = fmt.Fprintf(w, "features.tor.running: %v\n", response.Features.Tor.Running)
	_, _ = fmt.Fprintf(w, "features.tor.status: %s\n", response.Features.Tor.Status)
	if response.Features.Tor.Hostname != "" {
		_, _ = fmt.Fprintf(w, "features.tor.hostname: %s\n", response.Features.Tor.Hostname)
	}
	_, _ = fmt.Fprintf(w, "features.i2p: %s", response.Features.I2P.Status)
	if response.Features.I2P.Hostname != "" {
		_, _ = fmt.Fprintf(w, " %s", response.Features.I2P.Hostname)
	}
	_, _ = fmt.Fprintf(w, "\n")
	_, _ = fmt.Fprintf(w, "\n")

	_, _ = fmt.Fprintf(w, "# 6. Checks\n")
	_, _ = fmt.Fprintf(w, "checks.database: %s\n", response.Checks.Database)
	_, _ = fmt.Fprintf(w, "checks.cache: %s\n", response.Checks.Cache)
	_, _ = fmt.Fprintf(w, "checks.disk: %s\n", response.Checks.Disk)
	_, _ = fmt.Fprintf(w, "checks.scheduler: %s\n", response.Checks.Scheduler)
	if response.Checks.Tor != "" {
		_, _ = fmt.Fprintf(w, "checks.tor: %s\n", response.Checks.Tor)
	}
	if response.Checks.I2P != "" {
		_, _ = fmt.Fprintf(w, "checks.i2p: %s\n", response.Checks.I2P)
	}
	for _, check := range response.Checks.Datasets {
		_, _ = fmt.Fprintf(w, "checks.%s: %s\n", check.Key, check.Status)
	}
	_, _ = fmt.Fprintf(w, "\n")

	_, _ = fmt.Fprintf(w, "# 7. Stats\n")
	_, _ = fmt.Fprintf(w, "stats.requests_total: %d\n", response.Stats.RequestsTotal)
	_, _ = fmt.Fprintf(w, "stats.requests_24h: %d\n", response.Stats.Requests24h)
	_, _ = fmt.Fprintf(w, "stats.active_connections: %d\n", response.Stats.ActiveConns)
	_, _ = fmt.Fprintf(w, "stats.cache_hits: %d\n", response.Stats.CacheHits)
	_, _ = fmt.Fprintf(w, "stats.cache_misses: %d\n", response.Stats.CacheMisses)
	_, _ = fmt.Fprintf(w, "stats.whois_queries: %d\n", response.Stats.WhoisQueries)
	_, _ = fmt.Fprintf(w, "stats.domain_queries: %d\n", response.Stats.DomainQueries)
	_, _ = fmt.Fprintf(w, "stats.ip_queries: %d\n", response.Stats.IPQueries)
	_, _ = fmt.Fprintf(w, "stats.asn_queries: %d\n", response.Stats.ASNQueries)
}

// healthHTTPStatus maps the public health state to the status code required by
// AI.md PART 13. Degraded service remains available; unhealthy and maintenance
// states signal that callers should treat the service as unavailable.
func healthHTTPStatus(status string) int {
	switch status {
	case "unhealthy", "maintenance", "shutting_down":
		return http.StatusServiceUnavailable
	default:
		return http.StatusOK
	}
}

// CachedDatasetChecks returns the background-refreshed optional data checks.
func CachedDatasetChecks() []health.Result {
	return health.Snapshot()
}

// getOverallStatus applies PART 13 criticality to core, overlay, and dataset checks.
func getOverallStatus(checks ChecksInfo) string {
	if checks.Database == "error" || checks.Disk == "error" {
		return "unhealthy"
	}
	degraded := false
	for _, state := range []string{checks.Database, checks.Cache, checks.Disk, checks.Scheduler, checks.Tor, checks.I2P} {
		if state == "error" || state == "warn" || state == "degraded" {
			degraded = true
		}
	}
	for _, check := range checks.Datasets {
		if check.Status == "error" && check.Critical {
			return "unhealthy"
		}
		if check.Status == "degraded" || check.Status == "error" {
			degraded = true
		}
	}
	if degraded {
		return "degraded"
	}
	return "healthy"
}

// checkDatabase verifies the database connection is alive
func (s *Server) checkDatabase() string {
	if s.database == nil {
		return "error"
	}
	if err := s.database.Read().PingContext(context.Background()); err != nil {
		return "error"
	}
	return "ok"
}

// checkScheduler reports whether the scheduler is running
func (s *Server) checkScheduler() string {
	if s.scheduler == nil {
		return "error"
	}
	return "ok"
}

// buildTorInfo returns current Tor hidden service status
func (s *Server) buildTorInfo() TorInfo {
	s.torMu.RLock()
	service, status := s.torService, s.torStatus
	s.torMu.RUnlock()
	if service == nil {
		if status == "starting" || status == "unavailable" {
			return TorInfo{Enabled: true, Status: status}
		}
		return TorInfo{
			Enabled: false,
			Running: false,
			Status:  "disabled",
		}
	}
	addr := service.OnionAddress()
	if addr == ".onion" {
		addr = ""
	}
	running := addr != ""
	status = "starting"
	if running {
		status = "healthy"
	}
	return TorInfo{
		Enabled:  true,
		Running:  running,
		Status:   status,
		Hostname: addr,
	}
}

// formatUptime formats duration as human readable string
func formatUptime(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	} else {
		return fmt.Sprintf("%dm", minutes)
	}
}
