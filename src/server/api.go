package server

import (
	"net/http"
	"time"

	"github.com/casapps/caswhois/src/whois"
)

// ServerInfo represents a WHOIS server for API response
type ServerInfo struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        string `json:"port"`
	Description string `json:"description"`
	Type        string `json:"type"` // "rir", "tld", "root"
}

// handleWhoisServers returns list of supported WHOIS servers
// GET /api/v1/whois-servers
func (s *Server) handleWhoisServers(w http.ResponseWriter, r *http.Request) {
	servers := []ServerInfo{
		// Root server
		{
			Name:        "IANA",
			Host:        whois.IANAServer.Host,
			Port:        whois.IANAServer.Port,
			Description: "Root WHOIS server",
			Type:        "root",
		},
		// Regional Internet Registries (RIRs)
		{
			Name:        "ARIN",
			Host:        whois.ARINServer.Host,
			Port:        whois.ARINServer.Port,
			Description: "American Registry for Internet Numbers (North America)",
			Type:        "rir",
		},
		{
			Name:        "RIPE",
			Host:        whois.RIPEServer.Host,
			Port:        whois.RIPEServer.Port,
			Description: "Réseaux IP Européens (Europe, Middle East, Russia)",
			Type:        "rir",
		},
		{
			Name:        "APNIC",
			Host:        whois.APNICServer.Host,
			Port:        whois.APNICServer.Port,
			Description: "Asia Pacific Network Information Centre",
			Type:        "rir",
		},
		{
			Name:        "LACNIC",
			Host:        whois.LACNICServer.Host,
			Port:        whois.LACNICServer.Port,
			Description: "Latin America and Caribbean Network Information Centre",
			Type:        "rir",
		},
		{
			Name:        "AFRINIC",
			Host:        whois.AFRINICServer.Host,
			Port:        whois.AFRINICServer.Port,
			Description: "African Network Information Centre",
			Type:        "rir",
		},
		// Common TLDs
		{
			Name:        "COM",
			Host:        "whois.verisign-grs.com",
			Port:        "43",
			Description: ".com and .net domains",
			Type:        "tld",
		},
		{
			Name:        "ORG",
			Host:        "whois.pir.org",
			Port:        "43",
			Description: ".org domains",
			Type:        "tld",
		},
		{
			Name:        "INFO",
			Host:        "whois.afilias.net",
			Port:        "43",
			Description: ".info domains",
			Type:        "tld",
		},
		{
			Name:        "IO",
			Host:        "whois.nic.io",
			Port:        "43",
			Description: ".io domains",
			Type:        "tld",
		},
	}

	data := map[string]interface{}{
		"servers": servers,
		"count":   len(servers),
	}

	SendSuccess(w, data)
}

// handleStats returns service statistics
// GET /api/v1/stats
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	// Get cache stats
	ctx := r.Context()
	cacheStats, _ := s.cache.Stats(ctx)

	// Calculate uptime
	uptime := time.Since(s.startTime)

	data := map[string]interface{}{
		"cache": map[string]interface{}{
			"hits":      cacheStats.Hits,
			"misses":    cacheStats.Misses,
			"size":      cacheStats.Size,
			"keys":      cacheStats.Keys,
			"evictions": cacheStats.Evictions,
			"hit_rate":  cacheStats.HitRate,
		},
		"uptime": formatUptime(uptime),
	}

	SendSuccess(w, data)
}
