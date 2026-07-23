package server

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/apimgr/whois/src/common/constants"
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
	Hostname string `json:"hostname,omitempty"`
}

// FeaturesInfo - public features status (AI.md PART 13).
// Non-negotiable fields come first; caswhois app-specific fields follow.
type FeaturesInfo struct {
	// PART 31: Tor hidden service
	Tor TorInfo `json:"tor"`
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

// handleHealth handles /healthz and /api/{version}/healthz requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := s.buildHealthResponse()

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
		if tor.Running {
			checks.Tor = "ok"
		} else {
			checks.Tor = "error"
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

// renderHealthJSON renders health response as JSON
func (s *Server) renderHealthJSON(w http.ResponseWriter, response HealthResponse) {
	writeJSON(w, http.StatusOK, response)
}

// renderHealthText renders health response as plain text
func (s *Server) renderHealthText(w http.ResponseWriter, response HealthResponse) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	// Per AI.md PART 13: Fields in canonical order, flattened with dot notation
	fmt.Fprintf(w, "# 1. Project\n")
	fmt.Fprintf(w, "project.name: %s\n", response.Project.Name)
	fmt.Fprintf(w, "project.tagline: %s\n", response.Project.Tagline)
	fmt.Fprintf(w, "project.description: %s\n", response.Project.Description)
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# 2. Status\n")
	fmt.Fprintf(w, "status: %s\n", response.Status)
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# 3. Version & Build\n")
	fmt.Fprintf(w, "version: %s\n", response.Version)
	fmt.Fprintf(w, "go_version: %s\n", response.GoVersion)
	fmt.Fprintf(w, "build.commit: %s\n", response.Build.Commit)
	fmt.Fprintf(w, "build.date: %s\n", response.Build.Date)
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# 4. Runtime\n")
	fmt.Fprintf(w, "uptime: %s\n", response.Uptime)
	fmt.Fprintf(w, "mode: %s\n", response.Mode)
	fmt.Fprintf(w, "timestamp: %s\n", response.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# 5. Features\n")
	fmt.Fprintf(w, "features.rate_limiting: %v\n", response.Features.RateLimiting)
	fmt.Fprintf(w, "features.caching: %v\n", response.Features.Caching)
	fmt.Fprintf(w, "features.geoip: %v\n", response.Features.GeoIP)
	fmt.Fprintf(w, "features.email: %v\n", response.Features.Email)
	fmt.Fprintf(w, "features.tor.enabled: %v\n", response.Features.Tor.Enabled)
	fmt.Fprintf(w, "features.tor.running: %v\n", response.Features.Tor.Running)
	fmt.Fprintf(w, "features.tor.status: %s\n", response.Features.Tor.Status)
	if response.Features.Tor.Hostname != "" {
		fmt.Fprintf(w, "features.tor.hostname: %s\n", response.Features.Tor.Hostname)
	}
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# 6. Checks\n")
	fmt.Fprintf(w, "checks.database: %s\n", response.Checks.Database)
	fmt.Fprintf(w, "checks.cache: %s\n", response.Checks.Cache)
	fmt.Fprintf(w, "checks.disk: %s\n", response.Checks.Disk)
	fmt.Fprintf(w, "checks.scheduler: %s\n", response.Checks.Scheduler)
	if response.Checks.Tor != "" {
		fmt.Fprintf(w, "checks.tor: %s\n", response.Checks.Tor)
	}
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# 7. Stats\n")
	fmt.Fprintf(w, "stats.requests_total: %d\n", response.Stats.RequestsTotal)
	fmt.Fprintf(w, "stats.requests_24h: %d\n", response.Stats.Requests24h)
	fmt.Fprintf(w, "stats.active_connections: %d\n", response.Stats.ActiveConns)
	fmt.Fprintf(w, "stats.cache_hits: %d\n", response.Stats.CacheHits)
	fmt.Fprintf(w, "stats.cache_misses: %d\n", response.Stats.CacheMisses)
	fmt.Fprintf(w, "stats.whois_queries: %d\n", response.Stats.WhoisQueries)
	fmt.Fprintf(w, "stats.domain_queries: %d\n", response.Stats.DomainQueries)
	fmt.Fprintf(w, "stats.ip_queries: %d\n", response.Stats.IPQueries)
	fmt.Fprintf(w, "stats.asn_queries: %d\n", response.Stats.ASNQueries)
}

// getOverallStatus derives the overall service status from per-component check results.
// Returns "unhealthy" if any check is "error", "degraded" if any is "warn",
// and "healthy" when all checks pass.
func getOverallStatus(checks ChecksInfo) string {
	values := []string{checks.Database, checks.Cache, checks.Disk, checks.Scheduler}
	if checks.Tor != "" {
		values = append(values, checks.Tor)
	}
	degraded := false
	for _, v := range values {
		if v == "error" {
			return "unhealthy"
		}
		if v == "warn" {
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
	if err := s.database.Server.PingContext(context.Background()); err != nil {
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
	if s.torService == nil {
		return TorInfo{
			Enabled: false,
			Running: false,
			Status:  "disabled",
		}
	}
	addr := s.torService.OnionAddress()
	running := addr != "" && addr != ".onion"
	status := "starting"
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
