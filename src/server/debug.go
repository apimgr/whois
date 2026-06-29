package server

import (
	"expvar"
	"net/http"
	"net/http/pprof"
	"runtime"

	"github.com/go-chi/chi/v5"
)

// registerDebugRoutes registers debug endpoints (--debug / DEBUG=true only).
// All debug routes are under /debug/. In production without --debug, requests
// to /debug/* fall through to handleNotFound returning 404 (PART 6).
func (s *Server) registerDebugRoutes(r chi.Router) {
	if !s.config.IsDebug() {
		return
	}

	// pprof endpoints
	r.HandleFunc("/debug/pprof/", pprof.Index)
	r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	r.HandleFunc("/debug/pprof/profile", pprof.Profile)
	r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	r.HandleFunc("/debug/pprof/trace", pprof.Trace)
	r.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	r.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	r.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
	r.Handle("/debug/pprof/block", pprof.Handler("block"))
	r.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	r.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))

	// expvar
	r.Handle("/debug/vars", expvar.Handler())

	// Custom debug endpoints
	r.Get("/debug/config", s.handleDebugConfig)
	r.Get("/debug/routes", s.handleDebugRoutes)
	r.Get("/debug/cache", s.handleDebugCache)
	r.Get("/debug/db", s.handleDebugDB)
	r.Get("/debug/scheduler", s.handleDebugScheduler)
	r.Get("/debug/memory", s.handleDebugMemory)
	r.Get("/debug/goroutines", s.handleDebugGoroutines)
}

// handleDebugConfig returns sanitized configuration.
func (s *Server) handleDebugConfig(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, s.config.Sanitized())
}

// handleDebugRoutes returns a static list of all registered API and debug routes.
func (s *Server) handleDebugRoutes(w http.ResponseWriter, r *http.Request) {
	routes := []map[string]string{
		{"method": "GET", "route": "/server/healthz"},
		{"method": "GET", "route": "/api/v1/server/healthz"},
		{"method": "GET", "route": "/healthz"},
		{"method": "GET", "route": "/metrics"},
		{"method": "GET", "route": "/.well-known/security.txt"},
		{"method": "GET", "route": "/sitemap.xml"},
		{"method": "GET", "route": "/robots.txt"},
		{"method": "GET", "route": "/"},
		{"method": "GET", "route": "/about"},
		{"method": "GET", "route": "/server/about"},
		{"method": "GET", "route": "/docs"},
		{"method": "GET", "route": "/server/docs"},
		{"method": "GET", "route": "/whois"},
		{"method": "GET", "route": "/api/v1/whois/{query}"},
		{"method": "GET", "route": "/api/v1/whois/domain/{domain}"},
		{"method": "GET", "route": "/api/v1/whois/ip/{ip}"},
		{"method": "GET", "route": "/api/v1/whois/asn/{asn}"},
		{"method": "GET", "route": "/api/v1/whois/validate/{query}"},
		{"method": "POST", "route": "/api/v1/whois/bulk"},
		{"method": "GET", "route": "/api/v1/whois-servers"},
		{"method": "GET", "route": "/api/v1/server/stats"},
		{"method": "GET", "route": "/api/v1/server/schedulers"},
		{"method": "POST", "route": "/api/v1/server/schedulers/run"},
		{"method": "GET", "route": "/api/v1/server/backups"},
		{"method": "POST", "route": "/api/v1/server/backups/run"},
		{"method": "GET", "route": "/debug/pprof/"},
		{"method": "GET", "route": "/debug/vars"},
		{"method": "GET", "route": "/debug/config"},
		{"method": "GET", "route": "/debug/routes"},
		{"method": "GET", "route": "/debug/cache"},
		{"method": "GET", "route": "/debug/db"},
		{"method": "GET", "route": "/debug/scheduler"},
		{"method": "GET", "route": "/debug/memory"},
		{"method": "GET", "route": "/debug/goroutines"},
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"count":  len(routes),
		"routes": routes,
	})
}

// handleDebugMemory returns memory statistics.
func (s *Server) handleDebugMemory(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	respondJSON(w, http.StatusOK, map[string]any{
		"alloc_mb":       m.Alloc / 1024 / 1024,
		"total_alloc_mb": m.TotalAlloc / 1024 / 1024,
		"sys_mb":         m.Sys / 1024 / 1024,
		"num_gc":         m.NumGC,
		"heap_objects":   m.HeapObjects,
		"goroutines":     runtime.NumGoroutine(),
	})
}

// handleDebugGoroutines returns goroutine count and stack traces.
func (s *Server) handleDebugGoroutines(w http.ResponseWriter, r *http.Request) {
	// 1 MB buffer for stack traces
	buf := make([]byte, 1024*1024)
	// true = include all goroutines
	n := runtime.Stack(buf, true)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf[:n])
}

// handleDebugCache returns cache statistics.
func (s *Server) handleDebugCache(w http.ResponseWriter, r *http.Request) {
	stats, err := s.cache.Stats(r.Context())
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "SERVER_ERROR", "message": "Failed to get cache stats"})
		return
	}
	respondJSON(w, http.StatusOK, stats)
}

// handleDebugDB returns database connection pool statistics.
func (s *Server) handleDebugDB(w http.ResponseWriter, r *http.Request) {
	if s.database == nil || s.database.Server == nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "SERVER_ERROR", "message": "Database not available"})
		return
	}
	stats := s.database.Server.Stats()
	respondJSON(w, http.StatusOK, map[string]any{
		"open_connections":    stats.OpenConnections,
		"in_use":              stats.InUse,
		"idle":                stats.Idle,
		"wait_count":          stats.WaitCount,
		"wait_duration_ms":    stats.WaitDuration.Milliseconds(),
		"max_idle_closed":     stats.MaxIdleClosed,
		"max_lifetime_closed": stats.MaxLifetimeClosed,
	})
}

// handleDebugScheduler returns scheduler task status.
func (s *Server) handleDebugScheduler(w http.ResponseWriter, r *http.Request) {
	if s.scheduler == nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "SERVER_ERROR", "message": "Scheduler not available"})
		return
	}
	tasks := s.scheduler.Status()
	respondJSON(w, http.StatusOK, tasks)
}
