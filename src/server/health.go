package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"
)

// HealthResponse represents the /healthz response (per AI.md PART 13)
type HealthResponse struct {
	// 1. Project identification (from config branding)
	Project ProjectInfo `json:"project"`

	// 2. Overall status
	Status string `json:"status"` // "healthy", "unhealthy", "degraded"

	// 3. Version & build info
	Version   string    `json:"version"`
	GoVersion string    `json:"go_version"`
	Build     BuildInfo `json:"build"`

	// 4. Runtime info
	Uptime    string    `json:"uptime"`
	Mode      string    `json:"mode"`
	Timestamp time.Time `json:"timestamp"`

	// 5. Features (caswhois-specific)
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
	Commit string `json:"commit"` // git short hash (7 chars)
	Date   string `json:"date"`   // ISO 8601 build timestamp
}

// TorInfo - Tor hidden service status (AI.md PART 31)
type TorInfo struct {
	Enabled  bool   `json:"enabled"`
	Running  bool   `json:"running"`
	Status   string `json:"status"`
	Hostname string `json:"hostname,omitempty"`
}

// FeaturesInfo - caswhois features (AI.md PART 13)
type FeaturesInfo struct {
	RateLimiting bool    `json:"rate_limiting"`
	Caching      bool    `json:"caching"`
	GeoIP        bool    `json:"geoip"`
	Email        bool    `json:"email"`
	Tor          TorInfo `json:"tor"`
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
	RequestsTotal   int64 `json:"requests_total"`
	Requests24h     int64 `json:"requests_24h"`
	ActiveConns     int   `json:"active_connections"`
	CacheHits       int64 `json:"cache_hits"`
	CacheMisses     int64 `json:"cache_misses"`
	WhoisQueries    int64 `json:"whois_queries"`
	DomainQueries   int64 `json:"domain_queries"`
	IPQueries       int64 `json:"ip_queries"`
	ASNQueries      int64 `json:"asn_queries"`
}

// handleHealth handles /healthz and /api/{version}/healthz requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := s.buildHealthResponse()

	// Content negotiation handled by middleware (see AI.md PART 14)
	// Determine format from content detection (already done in middleware)
	format := r.Context().Value("content_type")
	if format == nil {
		format = "json" // default
	}

	switch format {
	case "text":
		s.renderHealthText(w, response)
	case "json":
		s.renderHealthJSON(w, response)
	default:
		s.renderHealthJSON(w, response)
	}
}

// buildHealthResponse builds the health response data
func (s *Server) buildHealthResponse() HealthResponse {
	uptime := time.Since(s.startTime)

	// Get cache stats
	ctx := context.Background()
	cacheStats, _ := s.cache.Stats(ctx)
	
	// Build response
	name := s.config.BrandingTitle
	if name == "" {
		name = "caswhois"
	}
	tagline := s.config.BrandingTagline
	if tagline == "" {
		tagline = "WHOIS Lookup Service"
	}
	description := s.config.BrandingDescription
	if description == "" {
		description = "Domain, IP, and ASN WHOIS lookup service"
	}

	return HealthResponse{
		Project: ProjectInfo{
			Name:        name,
			Tagline:     tagline,
			Description: description,
		},
		Status:    "healthy",
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
			RateLimiting: true,
			Caching:      true,
			GeoIP:        s.geoip != nil && s.geoip.Enabled(),
			Email:        s.email != nil && s.email.IsEnabled(),
			Tor:          s.buildTorInfo(),
		},
		Checks: ChecksInfo{
			Database:  s.checkDatabase(),
			Cache:     "ok",
			Disk:      "ok",
			Scheduler: s.checkScheduler(),
		},
		Stats: StatsInfo{
			RequestsTotal:   s.stats.requestsTotal.Load(),
			Requests24h:     s.stats.requests24h.Load(),
			ActiveConns:     int(s.stats.activeConns.Load()),
			CacheHits:       cacheStats.Hits,
			CacheMisses:     cacheStats.Misses,
			WhoisQueries:    s.stats.domainQueries.Load() + s.stats.ipQueries.Load() + s.stats.asnQueries.Load(),
			DomainQueries:   s.stats.domainQueries.Load(),
			IPQueries:       s.stats.ipQueries.Load(),
			ASNQueries:      s.stats.asnQueries.Load(),
		},
	}
}

// renderHealthJSON renders health response as JSON
func (s *Server) renderHealthJSON(w http.ResponseWriter, response HealthResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
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
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# 6. Checks\n")
	fmt.Fprintf(w, "checks.database: %s\n", response.Checks.Database)
	fmt.Fprintf(w, "checks.cache: %s\n", response.Checks.Cache)
	fmt.Fprintf(w, "checks.disk: %s\n", response.Checks.Disk)
	fmt.Fprintf(w, "checks.scheduler: %s\n", response.Checks.Scheduler)
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "# 8. Stats\n")
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
