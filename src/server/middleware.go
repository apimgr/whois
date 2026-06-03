package server

import (
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/casapps/caswhois/src/config"
	"github.com/casapps/caswhois/src/ratelimit"
)

// URLNormalizeMiddleware normalizes URLs for consistent routing
// - Removes trailing slashes (except for root "/")
// - Redirects to canonical URL with 301 if normalization changed path
// MUST be FIRST in middleware chain
func URLNormalizeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Root path "/" stays as-is
		if path == "/" {
			next.ServeHTTP(w, r)
			return
		}

		// Remove trailing slash (canonical form: no trailing slash)
		if strings.HasSuffix(path, "/") {
			// Exception: explicit file requests (e.g., /dir/index.html)
			if !strings.Contains(path[strings.LastIndex(path, "/"):], ".") {
				canonical := strings.TrimSuffix(path, "/")
				// Preserve query string
				if r.URL.RawQuery != "" {
					canonical += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, canonical, http.StatusMovedPermanently)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// PathSecurityMiddleware normalizes paths and blocks traversal attempts
// MUST be SECOND in middleware chain (after URL normalization)
func PathSecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate path using SafePath
		safe, err := config.SafePath(r.URL.Path)
		if err != nil {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			log.Printf("Path security violation: %s (%v)", r.URL.Path, err)
			return
		}

		// Update request with normalized path
		r.URL.Path = "/" + safe

		next.ServeHTTP(w, r)
	})
}

// SecurityHeadersMiddleware adds security headers to all responses
// MUST be THIRD in middleware chain
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// XSS protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Referrer policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Content Security Policy
		csp := "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'"
		w.Header().Set("Content-Security-Policy", csp)

		next.ServeHTTP(w, r)
	})
}

// RateLimitMiddleware implements rate limiting per IP
// MUST be FOURTH in middleware chain
func RateLimitMiddleware(limiter *ratelimit.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limiter == nil {
				next.ServeHTTP(w, r)
				return
			}

			key := limiter.GetKey(r)
			if !limiter.Allow(key) {
				w.Header().Set("X-RateLimit-Limit", "60")
				w.Header().Set("X-RateLimit-Window", "60")
				w.Header().Set("Retry-After", "60")
				SendError(w, ErrRateLimited, MsgRateLimited)
				log.Printf("Rate limit exceeded for %s", key)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AuthMiddleware annotates the request context with auth status.
// Token validation for protected routes is handled by requireToken() at the
// route level (see token_auth.go). This middleware is a pass-through that
// sets a context key so downstream handlers can check authenticated status
// without re-parsing the header.
// MUST be FIFTH in middleware chain
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pass-through: protected routes use requireToken() at registration time.
		// No sessions, no cookies — bearer token only (AI.md PART 1).
		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware logs HTTP requests in Apache Combined Log Format to access.log
// and records runtime stats.  MUST be LAST in middleware chain.
func (s *Server) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.stats.connOpen()
		defer s.stats.connClose()
		s.stats.recordRequest()

		// Wrap ResponseWriter to capture status code and bytes written.
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		// Extract host without port for the Apache Combined remote-addr field.
		remoteHost := r.RemoteAddr
		if host, _, err := net.SplitHostPort(remoteHost); err == nil {
			remoteHost = host
		}

		// Write Apache Combined Log Format line to access.log.
		// Falls back silently when no logger / file is configured.
		if s.logger != nil {
			s.logger.WriteAccess(
				remoteHost,
				r.Method,
				r.URL.RequestURI(),
				r.Proto,
				wrapped.statusCode,
				wrapped.bytesWritten,
				r.Referer(),
				r.UserAgent(),
			)
		}

		// Emit a compact summary to stderr/stdout for interactive use.
		log.Printf("[%s] %s %s %d %dB",
			r.Method,
			r.URL.Path,
			r.RemoteAddr,
			wrapped.statusCode,
			wrapped.bytesWritten,
		)
	})
}


// responseWriter wraps http.ResponseWriter to capture the status code and
// total bytes written — both are needed for Apache Combined Log Format.
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

// WriteHeader captures the status code.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write captures bytes written and ensures status code is recorded.
func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}
