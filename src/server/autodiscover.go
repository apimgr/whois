package server

import (
	"net/http"
	"runtime"
	"time"
)

// AutodiscoverResponse is the payload returned by GET /api/autodiscover.
// Clients use this to learn the server's API version, feature set, and the
// current CLI binary versions available for download.
type AutodiscoverResponse struct {
	// Server identification
	Server AutodiscoverServer `json:"server"`

	// API versioning
	APIVersion  string   `json:"api_version"`
	APIVersions []string `json:"api_versions"`
	BaseURL     string   `json:"base_url"`

	// Feature flags the client can check before calling versioned routes
	Features AutodiscoverFeatures `json:"features"`

	// CLI binary download info (for caswhois-cli auto-update)
	CLIVersions   map[string]CLIBinaryInfo `json:"cli_versions"`
	CLIMinVersion string                   `json:"cli_min_version"`

	// Tor .onion address (when Tor is enabled and running)
	OnionAddress string `json:"onion_address,omitempty"`

	Timestamp time.Time `json:"timestamp"`
}

// AutodiscoverServer contains server identification fields.
type AutodiscoverServer struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	Build     struct {
		Commit string `json:"commit"`
		Date   string `json:"date"`
	} `json:"build"`
}

// AutodiscoverFeatures lists enabled capabilities.
type AutodiscoverFeatures struct {
	WHOIS        bool `json:"whois"`
	BulkLookup   bool `json:"bulk_lookup"`
	RateLimiting bool `json:"rate_limiting"`
	Caching      bool `json:"caching"`
	GeoIP        bool `json:"geoip"`
	Metrics      bool `json:"metrics"`
	TorHidden    bool `json:"tor_hidden_service"`
}

// CLIBinaryInfo holds version and checksum for a single platform's CLI binary.
type CLIBinaryInfo struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// handleAutodiscover handles GET /api/autodiscover.
// Public endpoint — no auth required.
func (s *Server) handleAutodiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		SendError(w, ErrMethodNotAllowed, "method not allowed")
		return
	}

	// Determine base URL from request
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
		scheme = fwd
	}
	baseURL := scheme + "://" + r.Host

	// Tor .onion address (if hidden service is running)
	var onionAddr string
	if s.torService != nil {
		onionAddr = s.torService.OnionAddress()
	}

	resp := AutodiscoverResponse{
		Server: AutodiscoverServer{
			Name:      s.config.Branding.Title,
			Version:   Version,
			GoVersion: runtime.Version(),
		},
		APIVersion:  "v1",
		APIVersions: []string{"v1"},
		BaseURL:     baseURL,
		Features: AutodiscoverFeatures{
			WHOIS:        true,
			BulkLookup:   true,
			RateLimiting: s.config.RateLimit.Enabled,
			Caching:      true,
			GeoIP:        s.config.GeoIP.Enabled,
			Metrics:      s.config.Metrics.Enabled,
			TorHidden:    onionAddr != "",
		},
		// CLI versions map is empty until server-side binary hosting is added.
		// Clients check this map before attempting an update.
		CLIVersions:   map[string]CLIBinaryInfo{},
		CLIMinVersion: "0.0.0",
		OnionAddress:  onionAddr,
		Timestamp:     time.Now().UTC(),
	}

	// Populate build info from package-level build variables
	resp.Server.Build.Commit = CommitID
	resp.Server.Build.Date = BuildDate

	SendSuccess(w, resp)
}
