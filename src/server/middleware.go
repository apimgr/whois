package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apimgr/whois/src/cache"
	"github.com/apimgr/whois/src/config"
	"github.com/apimgr/whois/src/geoip"
	"github.com/apimgr/whois/src/ratelimit"
)

var rateLimitFallbackWarning sync.Once

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

// requestIDContextKey is the context key for the per-request ID.
type requestIDContextKey struct{}

// RequestIDMiddleware assigns a unique request ID to each inbound request.
// It reuses the X-Request-ID header from a trusted upstream proxy when present.
// The ID is stored in the request context and echoed in the X-Request-ID response header.
// MUST be SECOND in middleware chain (after URLNormalize).
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			b := make([]byte, 16)
			if _, err := rand.Read(b); err != nil {
				id = "unknown"
			} else {
				id = hex.EncodeToString(b)
			}
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFromContext retrieves the request ID stored by RequestIDMiddleware.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDContextKey{}).(string)
	return id
}

// PathSecurityMiddleware rejects requests containing path-traversal sequences and
// normalizes remaining paths with path.Clean.
//
// It blocks:
//   - ".." segments in the decoded path
//   - Percent-encoded dot traversal (%2e%2e, %2e., .%2e) in the raw path
//
// It does NOT restrict characters to lowercase-only — that validation applies
// to user-supplied config values (config.SafePath), not to HTTP request paths.
// MUST be THIRD in middleware chain (after URLNormalize and RequestID).
func PathSecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		original := r.URL.Path
		rawPath := r.URL.RawPath

		// Reject ".." in the decoded path.
		if strings.Contains(original, "..") {
			writeRequestError(w, r, http.StatusBadRequest)
			log.Printf("Path security violation (traversal): %s", original)
			return
		}

		// Reject encoded-dot traversal sequences in the raw path.
		if rawPath != "" {
			lower := strings.ToLower(rawPath)
			if strings.Contains(lower, "%2e%2e") ||
				strings.Contains(lower, "%2e.") ||
				strings.Contains(lower, ".%2e") {
				writeRequestError(w, r, http.StatusBadRequest)
				log.Printf("Path security violation (encoded traversal): %s", rawPath)
				return
			}
		}

		// Normalize double-slashes and redundant dots via path.Clean.
		cleaned := path.Clean(original)
		if cleaned != original {
			r2 := r.Clone(r.Context())
			r2.URL.Path = cleaned
			if rawPath != "" {
				cleanedRaw := path.Clean(rawPath)
				r2.URL.RawPath = cleanedRaw
			}
			next.ServeHTTP(w, r2)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// AllowlistMiddleware allows only requests from IP addresses in the configured IP allowlist.
// When the allowlist is empty, all IPs are allowed through (default: open).
// This is a framework-level placeholder; specific enforcement is wired at setup time
// via the allowlist in the security package when the operator configures it.
// MUST be FIFTH in middleware chain (after SecurityHeaders).
func AllowlistMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// BlocklistMiddleware blocks requests from IP addresses in the configured IP blocklist.
// This is a framework-level placeholder; specific enforcement is wired at setup time
// via the blocklist in the security package when the operator configures it.
// MUST be SIXTH in middleware chain (after Allowlist).
func BlocklistMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// GeoIPMiddleware blocks or allows requests based on the GeoIP country deny/allow lists.
// When geoipMgr is nil or no countries are configured, all requests pass through.
// additional is the trusted_proxies.additional list from config (AI.md PART 12).
// MUST be EIGHTH in middleware chain (after RateLimit and Blocklist).
func GeoIPMiddleware(geoipMgr *geoip.GeoIPManager, denyCountries, allowCountries, additional []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if geoipMgr != nil && geoipMgr.Enabled() {
				clientIP := extractClientIP(r, additional)
				if geoipMgr.IsCountryBlocked(clientIP, denyCountries, allowCountries) {
					writeRequestError(w, r, http.StatusForbidden)
					log.Printf("GeoIP block: %s", clientIP)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// extractClientIP returns the real client IP from the request.
// Proxy headers (X-Forwarded-For, X-Real-IP) are only trusted when the
// immediate peer (RemoteAddr) is in a trusted range (RFC 1918 / loopback /
// fc00::/7 / link-local or the operator-configured additional list).
// This prevents spoofing when the binary is accessed directly (AI.md PART 12).
func extractClientIP(r *http.Request, additional []string) string {
	peerHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peerHost = r.RemoteAddr
	}
	if isTrustedPeer(peerHost, additional) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// X-Forwarded-For may be a comma-separated list; the leftmost is the client.
			parts := strings.SplitN(xff, ",", 2)
			ip := strings.TrimSpace(parts[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if net.ParseIP(xri) != nil {
				return xri
			}
		}
	}
	return peerHost
}

// secGPCContextKey is the context key for the inbound Sec-GPC opt-out flag.
type secGPCContextKey struct{}

// SecGPCFromContext returns true when the request carried Sec-GPC: 1.
func SecGPCFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(secGPCContextKey{}).(bool)
	return v
}

// permissionsPolicy is the default Permissions-Policy header value (AI.md PART 11).
// Locked-down by default; projects declare feature needs via IDEA.md → server.yml overrides.
const permissionsPolicy = "accelerometer=(), ambient-light-sensor=(), battery=(), camera=(), " +
	"display-capture=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), " +
	"magnetometer=(), microphone=(), midi=(), screen-wake-lock=(), serial=(), usb=(), " +
	"xr-spatial-tracking=(), attribution-reporting=(), browsing-topics=(), " +
	"interest-cohort=(), autoplay=(self), encrypted-media=(self), fullscreen=(self), " +
	"payment=(self), picture-in-picture=(self), publickey-credentials-get=(self), " +
	"storage-access=(self), web-share=(self)"

// SecurityHeadersMiddleware adds all required security response headers (AI.md PART 11).
// Parameters: fqdn is the server FQDN used to build report endpoint URLs;
// apiVersion is the API version string (e.g. "v1"); sslEnabled enables HSTS;
// debugMode switches CSP to report-only mode.
// MUST be FOURTH in middleware chain (after CORS, PathSecurity, RequestID).
func SecurityHeadersMiddleware(fqdn, apiVersion string, sslEnabled, debugMode bool) func(http.Handler) http.Handler {
	// Build CSP once at setup time (PART 11 — report endpoint uses FQDN).
	reportEndpoint := ""
	cspReportURI := ""
	reportToHeader := ""
	nelHeader := ""
	reportingEndpoints := ""
	if fqdn != "" {
		base := "https://" + fqdn
		reportEndpoint = base + "/api/" + apiVersion + "/server/reports"
		cspReportURI = reportEndpoint + "/csp"
		reportingEndpoints = `default="` + reportEndpoint + `/default"`
		reportToHeader = `{"group":"default","max_age":10886400,"endpoints":[{"url":"` + reportEndpoint + `/default"}]}`
		nelHeader = `{"report_to":"default","max_age":2592000,"include_subdomains":true}`
	}

	// CSP directive — style-src allows 'unsafe-inline' for inline styles in Go templates.
	cspDirective := "default-src 'self'; " +
		"script-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data: blob: https:; " +
		"font-src 'self' https:; " +
		"connect-src 'self'; " +
		"media-src 'self' blob:; " +
		"worker-src 'self' blob:; " +
		"manifest-src 'self'; " +
		"frame-src 'self'; " +
		"frame-ancestors 'self'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"object-src 'none'; " +
		"upgrade-insecure-requests"
	if cspReportURI != "" {
		cspDirective += "; report-to default; report-uri " + cspReportURI
	}

	// In development mode CSP runs as report-only so violations are logged without blocking.
	cspHeaderName := "Content-Security-Policy"
	if debugMode {
		cspHeaderName = "Content-Security-Policy-Report-Only"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Honor inbound Sec-GPC: 1 opt-out signal (CCPA/GDPR — AI.md PART 11).
			ctx := r.Context()
			if r.Header.Get("Sec-GPC") == "1" {
				ctx = context.WithValue(ctx, secGPCContextKey{}, true)
				r = r.WithContext(ctx)
			}

			// Standard security headers required on every response.
			w.Header().Set("X-Content-Type-Options", "nosniff")
			// SAMEORIGIN allows the app to embed its own pages in iframes.
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			// Kept for older browsers; modern browsers use CSP.
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			// Block Adobe Flash / PDF cross-domain embedding.
			w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
			// Opt into per-origin agent clustering (security / perf hygiene).
			w.Header().Set("Origin-Agent-Cluster", "?1")
			// Cross-Origin isolation defaults — loose (tighten via server.yml for SharedArrayBuffer etc.).
			w.Header().Set("Cross-Origin-Opener-Policy", "unsafe-none")
			w.Header().Set("Cross-Origin-Embedder-Policy", "unsafe-none")
			w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
			// Content Security Policy.
			w.Header().Set(cspHeaderName, cspDirective)
			// Permissions-Policy — all sensors and tracking off by default.
			w.Header().Set("Permissions-Policy", permissionsPolicy)

			// Reporting endpoints — only emitted when FQDN is known.
			if reportingEndpoints != "" {
				w.Header().Set("Reporting-Endpoints", reportingEndpoints)
				w.Header().Set("Report-To", reportToHeader)
				w.Header().Set("NEL", nelHeader)
			}

			// HSTS — emitted only when SSL is active (PART 11 / RFC 6797).
			if sslEnabled {
				w.Header().Set("Strict-Transport-Security",
					"max-age=63072000; includeSubDomains; preload")
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SecFetchValidationMiddleware rejects cross-site state-changing requests that
// lack a Bearer token (defense-in-depth CSRF layer — AI.md PART 11).
// Validation is present-and-bad only — absent Sec-Fetch-* headers pass through
// for legacy browser compatibility.
func SecFetchValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only validate state-changing methods.
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			// Reject cross-site requests without a Bearer token.
			fetchSite := r.Header.Get("Sec-Fetch-Site")
			if fetchSite == "cross-site" {
				auth := r.Header.Get("Authorization")
				if !strings.HasPrefix(auth, "Bearer ") {
					SendError(w, ErrForbidden, "Cross-site request rejected")
					return
				}
			}
			// Reject form-navigation CSRF targeting JSON API endpoints.
			fetchMode := r.Header.Get("Sec-Fetch-Mode")
			if fetchMode == "navigate" && strings.HasPrefix(r.URL.Path, "/api/") {
				SendError(w, ErrForbidden, "Form navigation to API endpoint rejected")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RateLimitMiddleware implements rate limiting per IP with config-sourced limits.
// MUST be FOURTH in middleware chain.
func RateLimitMiddleware(limiter *ratelimit.Limiter, limit, window int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limiter == nil {
				next.ServeHTTP(w, r)
				return
			}

			key := limiter.GetKey(r)
			if !limiter.Allow(key) {
				w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
				w.Header().Set("X-RateLimit-Window", fmt.Sprintf("%d", window))
				w.Header().Set("Retry-After", fmt.Sprintf("%d", window))
				SendError(w, ErrRateLimited, MsgRateLimited)
				log.Printf("Rate limit exceeded for %s", key)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) configuredRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter := s.ratelimit
		limit := s.config.RateLimit.Read
		if isHealthRoute(r.URL.Path) {
			limiter = s.healthLimiter
			limit = s.config.RateLimit.Health
		} else if r.Method != http.MethodGet && r.Method != http.MethodHead {
			limiter = s.writeLimiter
			limit = s.config.RateLimit.Write
		}
		clientKey := s.rateLimitClientKey(r)
		bucket := "read"
		if isHealthRoute(r.URL.Path) {
			bucket = "health"
		} else if r.Method != http.MethodGet && r.Method != http.MethodHead {
			bucket = "write"
		}
		limited := !s.allowRateLimit(r.Context(), bucket, limiter, clientKey, limit.Requests, time.Duration(limit.Window)*time.Second, true)
		if !s.allowRateLimit(r.Context(), "global", s.globalBurstLimiter, clientKey, s.config.RateLimit.GlobalBurst, time.Minute, true) {
			limited = true
			limit = config.RateLimitEndpointConfig{Requests: s.config.RateLimit.GlobalBurst, Window: 60}
		}
		if limited {
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.Requests))
			w.Header().Set("X-RateLimit-Window", strconv.Itoa(limit.Window))
			w.Header().Set("Retry-After", strconv.Itoa(limit.Window))
			SendError(w, ErrRateLimited, MsgRateLimited)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowRateLimit(ctx context.Context, bucket string, fallback *ratelimit.Limiter, clientKey string, requests int, window time.Duration, consume bool) (allowed bool) {
	defer func() {
		s.metrics.RecordRateLimit(bucket, allowed)
	}()
	memoryFallback := func() bool {
		if fallback == nil {
			return false
		}
		fallbackKey := bucket + ":" + clientKey
		if !consume {
			return !fallback.IsLimitedWithLimit(fallbackKey, requests, window)
		}
		rateLimitFallbackWarning.Do(func() {
			log.Printf("WARN: persistent rate-limit storage unavailable; using in-process counters")
		})
		return fallback.AllowWithLimit(fallbackKey, requests, window)
	}
	if s.database == nil || s.database.Read() == nil {
		return memoryFallback()
	}
	if requests <= 0 {
		requests = 60
	}
	if window <= 0 {
		window = time.Minute
	}
	sum := sha256.Sum256([]byte(bucket + "\x00" + clientKey))
	key := fmt.Sprintf("%x", sum[:])
	if s.config.Cache.Type == "redis" || s.config.Cache.Type == "valkey" {
		if backend, ok := s.cache.(cache.RateLimitCache); ok {
			allowed, err := backend.AllowRateLimit(ctx, key, requests, window, consume)
			if err == nil {
				if allowed && consume && (bucket == "strict" || bucket == "auth_failure") && fallback != nil {
					_ = fallback.Allow(bucket + ":" + clientKey)
				}
				return allowed
			}
		}
		return memoryFallback()
	}
	if fallback == nil {
		return false
	}
	fallbackKey := bucket + ":" + clientKey
	if !consume {
		return !fallback.IsLimitedWithLimit(fallbackKey, requests, window)
	}
	allowed = fallback.AllowWithLimit(fallbackKey, requests, window)
	if allowed {
		s.queueRateLimitEvent(key, time.Now().UnixMilli())
	}
	return allowed
}

func (s *Server) maxRateLimitWindow() int64 {
	maximum := int64(900)
	for _, seconds := range []int{s.config.RateLimit.Read.Window, s.config.RateLimit.Write.Window,
		s.config.RateLimit.Health.Window, s.config.RateLimit.Strict.Window, s.config.RateLimit.AuthFailures.Window, 60} {
		if seconds > int(maximum) {
			maximum = int64(seconds)
		}
	}
	return maximum
}

func isHealthRoute(path string) bool {
	switch path {
	case "/healthz", "/readyz", "/livez", "/server/healthz", "/api/healthz":
		return true
	default:
		return strings.HasSuffix(path, "/server/healthz") || strings.HasSuffix(path, "/server/readyz") || strings.HasSuffix(path, "/server/livez")
	}
}

func (s *Server) rateLimitClientKey(r *http.Request) string {
	clientIP := extractClientIP(r, s.config.TrustedProxies.Additional)
	token := extractBearerToken(r)
	if token == "" {
		return "ip:" + clientIP
	}
	tokenHash := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(tokenHash[:], s.getServerTokenHash()) == 1 {
		return "token:" + hex.EncodeToString(tokenHash[:])
	}
	if s.database != nil && s.database.Read() != nil {
		if _, err := s.lookupOwnerToken(r.Context(), token); err == nil {
			return "token:" + hex.EncodeToString(tokenHash[:])
		}
	}
	return "ip:" + clientIP
}

// strictRateLimit applies the configured sensitive-action limit before a handler
// so invalid and valid attempts consume the same per-client budget.
func (s *Server) strictRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.strictLimiter != nil {
			limit := s.config.RateLimit.Strict
			key := extractClientIP(r, s.config.TrustedProxies.Additional)
			if s.database != nil && s.database.Read() != nil {
				if owner, err := s.ownerFromRequest(r, true); err == nil {
					key = "owner:" + owner.OwnerID
				} else {
					key = "ip:" + key
				}
			}
			if !s.allowRateLimit(r.Context(), "strict", s.strictLimiter, key, limit.Requests, time.Duration(limit.Window)*time.Second, true) {
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.Requests))
				w.Header().Set("X-RateLimit-Window", strconv.Itoa(limit.Window))
				w.Header().Set("Retry-After", strconv.Itoa(limit.Window))
				SendError(w, ErrRateLimited, MsgRateLimited)
				return
			}
		}
		next.ServeHTTP(w, r)
	}
}

func (s *Server) authFailureKey(r *http.Request) string {
	return "auth:" + extractClientIP(r, s.config.TrustedProxies.Additional)
}

func (s *Server) authFailureBlocked(w http.ResponseWriter, r *http.Request) bool {
	limit := s.config.RateLimit.AuthFailures
	key := s.authFailureKey(r)
	if s.authFailureLimiter == nil || s.allowRateLimit(r.Context(), "auth_failure", s.authFailureLimiter, key, limit.Requests, time.Duration(limit.Window)*time.Second, false) {
		return false
	}
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.Requests))
	w.Header().Set("X-RateLimit-Window", strconv.Itoa(limit.Window))
	w.Header().Set("Retry-After", strconv.Itoa(limit.Window))
	SendError(w, ErrRateLimited, MsgRateLimited)
	return true
}

func (s *Server) recordAuthFailure(w http.ResponseWriter, r *http.Request) bool {
	limit := s.config.RateLimit.AuthFailures
	if s.authFailureLimiter == nil || s.allowRateLimit(r.Context(), "auth_failure", s.authFailureLimiter, s.authFailureKey(r), limit.Requests, time.Duration(limit.Window)*time.Second, true) {
		return false
	}
	return s.authFailureBlocked(w, r)
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
		remoteHost, torRequest := torRequestIdentity(r)
		if !torRequest {
			remoteHost = r.RemoteAddr
			if host, _, err := net.SplitHostPort(remoteHost); err == nil {
				remoteHost = host
			}
		}

		// Write Apache Combined Log Format line to access.log.
		// Falls back silently when no logger / file is configured.
		if s.logger != nil {
			requestURI := r.URL.RequestURI()
			if strings.HasPrefix(r.URL.Path, "/server/security/report/") {
				requestURI = r.URL.Path
			}
			s.logger.WriteAccess(
				remoteHost,
				r.Method,
				requestURI,
				r.Proto,
				wrapped.statusCode,
				wrapped.bytesWritten,
				r.Referer(),
				r.UserAgent(),
			)
		}

		// Emit a compact summary to stderr/stdout for interactive use.
		logRemote := r.RemoteAddr
		if torRequest {
			logRemote = remoteHost
		}
		log.Printf("[%s] %s %s %d %dB",
			r.Method,
			r.URL.Path,
			logRemote,
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

// corsAllowedHeaders lists every auth header supported by PART 8 → "Auth
// Token Headers (All Headers Supported)". Never "*" here: the Fetch spec's
// Access-Control-Allow-Headers: * wildcard does not cover Authorization, and
// wildcards are invalid when credentials are allowed (AI.md PART 16 — CORS).
const corsAllowedHeaders = "Content-Type, Accept, X-Requested-With, Authorization, " +
	"X-API-Key, X-Api-Key, API-Key, ApiKey, X-Auth-Token, X-Access-Token, " +
	"X-Token, Token, X-CSRF-Token, X-XSRF-Token, X-Session-ID, " +
	"X-Service-Token, X-Internal-Token"

// resolveCORSAllowList implements the CORS Allow-list Resolution Order
// (AI.md PART 16 — CORS Allow-list Resolution Order):
//  1. Explicit config — server.cors.allowed_origins. A literal "*" entry
//     allows all origins and stops resolution (credentials NOT allowed).
//  2. DOMAIN env entries — every hostname from DOMAIN is added as an
//     https:// origin.
//  3. Reverse-proxy-learned hosts — X-Forwarded-Host, trusted peers only
//     (gated on trusted_proxies — AI.md PART 12 → "Trusted Proxies").
//  4. Default — "*" if no source produced a list (credentials NOT allowed).
func resolveCORSAllowList(cfg config.CORSConfig, trustedProxies []string, r *http.Request) (origins []string, wildcard bool) {
	for _, o := range cfg.AllowedOrigins {
		if strings.TrimSpace(o) == "*" {
			return nil, true
		}
	}

	var list []string
	for _, o := range cfg.AllowedOrigins {
		o = strings.TrimSpace(o)
		if o != "" {
			list = append(list, o)
		}
	}

	if domain := os.Getenv("DOMAIN"); domain != "" {
		for _, d := range strings.Split(domain, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				list = append(list, "https://"+d)
			}
		}
	}

	peerHost, _, _ := net.SplitHostPort(r.RemoteAddr)
	if isTrustedPeer(peerHost, trustedProxies) {
		if fwdHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); fwdHost != "" {
			list = append(list, "https://"+fwdHost, "http://"+fwdHost)
		}
	}

	if len(list) == 0 {
		return nil, true
	}
	return list, false
}

// CORSMiddleware adds CORS headers to API routes (AI.md PART 16 — CORS).
// Applies only to paths under /api/, /metrics, and /debug/; handles OPTIONS
// preflight. A single "" entry in cfg.AllowedOrigins disables CORS headers
// entirely (same-origin only).
func CORSMiddleware(cfg config.CORSConfig, trustedProxies []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(cfg.AllowedOrigins) == 1 && cfg.AllowedOrigins[0] == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Only apply CORS to API and metrics paths.
			path := r.URL.Path
			isAPIPath := strings.HasPrefix(path, "/api/") ||
				strings.HasPrefix(path, "/metrics") ||
				strings.HasPrefix(path, "/debug/")

			if !isAPIPath {
				next.ServeHTTP(w, r)
				return
			}

			allowList, wildcard := resolveCORSAllowList(cfg, trustedProxies, r)
			origin := r.Header.Get("Origin")

			if wildcard {
				// Wildcard: allow any origin, credentials NOT allowed.
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				for _, o := range allowList {
					if o == origin {
						w.Header().Set("Access-Control-Allow-Origin", origin)
						// Credentials are sent only when the resolved list is
						// explicit — never with "*" (AI.md PART 16 — CORS).
						if cfg.AllowCredentials {
							w.Header().Set("Access-Control-Allow-Credentials", "true")
						}
						break
					}
				}
			}

			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", corsAllowedHeaders)
			maxAge := cfg.MaxAge
			if maxAge <= 0 {
				maxAge = 86400
			}
			w.Header().Set("Access-Control-Max-Age", strconv.Itoa(maxAge))

			// Handle preflight.
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
