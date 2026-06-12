package server

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	appdata "github.com/casapps/caswhois/src/data"
)

// ServerInfo represents a WHOIS server entry (AI.md PART 7 — application data from src/data/).
type ServerInfo struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        string `json:"port"`
	Description string `json:"description"`
	Type        string `json:"type"`
}

// whoisServerList is parsed once at init from the embedded JSON (src/data/whois-servers.json).
var whoisServerList []ServerInfo

func init() {
	if err := json.Unmarshal(appdata.WHOISServersJSON, &whoisServerList); err != nil {
		log.Printf("WARN: failed to parse embedded whois-servers.json: %v", err)
	}
}

// handleWhoisServers returns the list of supported WHOIS servers.
// GET /api/v1/whois-servers
func (s *Server) handleWhoisServers(w http.ResponseWriter, r *http.Request) {
	SendSuccess(w, map[string]interface{}{
		"servers": whoisServerList,
		"count":   len(whoisServerList),
	})
}

// handleStats returns service statistics.
// GET /api/v1/stats
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cacheStats, _ := s.cache.Stats(ctx)

	uptime := time.Since(s.startTime)

	SendSuccess(w, map[string]interface{}{
		"cache": map[string]interface{}{
			"hits":      cacheStats.Hits,
			"misses":    cacheStats.Misses,
			"size":      cacheStats.Size,
			"keys":      cacheStats.Keys,
			"evictions": cacheStats.Evictions,
			"hit_rate":  cacheStats.HitRate,
		},
		"uptime": formatUptime(uptime),
	})
}
