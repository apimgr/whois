package server

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/apimgr/whois/src/common/constants"
	humanformat "github.com/apimgr/whois/src/common/format"
	"github.com/apimgr/whois/src/i2p"
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

// ChecksInfo - component health (ok/error only, AI.md PART 13)
type ChecksInfo struct {
	Database  string `json:"database"`
	Cache     string `json:"cache"`
	Disk      string `json:"disk"`
	Scheduler string `json:"scheduler"`
	Tor       string `json:"tor,omitempty"`
	I2P       string `json:"i2p,omitempty"`
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

// handleHealth handles /healthz and /api/{version}/healthz requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := s.buildHealthResponse()
	if !strings.HasPrefix(r.URL.Path, "/api/") && DetectClientType(r) == ClientTypeHTML {
		data := healthPageData{
			translatablePageData: s.newPageData(w, r),
			AppName:              s.brandName(),
			UptimeDisplay:        humanformat.Duration(time.Since(s.startTime), LangFromContext(r.Context())),
			HealthResponse:       response,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := s.renderTemplate(healthPageTmpl, w, r, data); err != nil {
			writeRequestError(w, r, http.StatusInternalServerError)
		}
		return
	}

	// Content negotiation per AI.md PART 14:
	// Only serve text/plain when the client explicitly requests it.
	// Default (no Accept header, or unknown) → JSON.
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/plain") && !strings.Contains(accept, "application/json") {
		s.renderHealthText(w, response)
		return
	}
	s.renderHealthJSON(w, response)
}

// buildHealthResponse builds the health response data
func (s *Server) buildHealthResponse() HealthResponse {
	uptime := time.Since(s.startTime)

	// Get cache stats
	ctx := context.Background()
	cacheStats, _ := s.cache.Stats(ctx)

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
		Cache:     "ok",
		Disk:      "ok",
		Scheduler: s.checkScheduler(),
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

	return HealthResponse{
		Project: ProjectInfo{
			Name:        name,
			Tagline:     tagline,
			Description: description,
		},
		Status:    getOverallStatus(checks),
		Version:   Version,
		GoVersion: runtime.Version(),
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
	writeJSON(w, http.StatusOK, response)
}

// renderHealthText renders health response as plain text
func (s *Server) renderHealthText(w http.ResponseWriter, response HealthResponse) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

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

// getOverallStatus derives the overall service status from per-component check results.
// Returns "unhealthy" if any check is "error", "degraded" if any is "warn",
// and "healthy" when all checks pass.
func getOverallStatus(checks ChecksInfo) string {
	values := []string{checks.Database, checks.Cache, checks.Disk, checks.Scheduler}
	if checks.Tor != "" {
		values = append(values, checks.Tor)
	}
	if checks.I2P != "" {
		values = append(values, checks.I2P)
	}
	degraded := false
	for _, v := range values {
		if v == "error" {
			return "unhealthy"
		}
		if v == "warn" || v == "degraded" {
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
