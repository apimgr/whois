package server

import (
	"expvar"
	"net/http"
	"net/http/pprof"
	"runtime"

	"github.com/go-chi/chi/v5"
)

// registerDebugRoutes registers operator-protected debug endpoints only when
// debug mode is explicitly enabled.
func (s *Server) registerDebugRoutes(r chi.Router) {
	if !s.config.IsDebug() {
		return
	}

	r.Route("/debug", func(debug chi.Router) {
		debug.Use(s.requireOperatorToken)
		debug.HandleFunc("/pprof", pprof.Index)
		debug.HandleFunc("/pprof/", pprof.Index)
		debug.HandleFunc("/pprof/cmdline", pprof.Cmdline)
		debug.HandleFunc("/pprof/profile", pprof.Profile)
		debug.HandleFunc("/pprof/symbol", pprof.Symbol)
		debug.HandleFunc("/pprof/trace", pprof.Trace)
		debug.Handle("/pprof/heap", pprof.Handler("heap"))
		debug.Handle("/pprof/goroutine", pprof.Handler("goroutine"))
		debug.Handle("/pprof/allocs", pprof.Handler("allocs"))
		debug.Handle("/pprof/block", pprof.Handler("block"))
		debug.Handle("/pprof/mutex", pprof.Handler("mutex"))
		debug.Handle("/pprof/threadcreate", pprof.Handler("threadcreate"))
		debug.Handle("/vars", expvar.Handler())
		debug.Get("/config", s.handleDebugConfig)
		debug.Get("/routes", s.handleDebugRoutes)
		debug.Get("/cache", s.handleDebugCache)
		debug.Get("/db", s.handleDebugDB)
		debug.Get("/scheduler", s.handleDebugScheduler)
		debug.Get("/memory", s.handleDebugMemory)
		debug.Get("/goroutines", s.handleDebugGoroutines)
		debug.Get("/error500", s.handleDebugError500)
	})
}

func (s *Server) requireOperatorToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requireToken(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})(w, r)
	})
}

// handleDebugConfig returns sanitized configuration.
func (s *Server) handleDebugConfig(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, s.config.Sanitized())
}

// handleDebugRoutes reports the routes registered on the current server.
func (s *Server) handleDebugRoutes(w http.ResponseWriter, r *http.Request) {
	routes := make([]map[string]string, 0)
	if s.apiRouter == nil {
		SendError(w, ErrServerError, "Routes are unavailable")
		return
	}
	if err := chi.Walk(s.apiRouter, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, map[string]string{"method": method, "route": route})
		return nil
	}); err != nil {
		SendError(w, ErrServerError, "Failed to walk routes")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"count":  len(routes),
		"routes": routes,
	})
}

func (s *Server) handleDebugError500(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Deterministic debug error", http.StatusInternalServerError)
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
		writeLocalizedAPIError(w, http.StatusInternalServerError, ErrServerError, requestErrorLanguage(r))
		return
	}
	respondJSON(w, http.StatusOK, stats)
}

// handleDebugDB returns database connection pool statistics.
func (s *Server) handleDebugDB(w http.ResponseWriter, r *http.Request) {
	if s.database == nil || s.database.Read() == nil {
		writeLocalizedAPIError(w, http.StatusServiceUnavailable, ErrMaintenance, requestErrorLanguage(r))
		return
	}
	stats := s.database.Read().Stats()
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
		writeLocalizedAPIError(w, http.StatusServiceUnavailable, ErrMaintenance, requestErrorLanguage(r))
		return
	}
	tasks := s.scheduler.Status()
	respondJSON(w, http.StatusOK, tasks)
}
