package server

import (
	"net/http"
	"strings"

	"github.com/apimgr/whois/src/common/constants"
)

// offlineCacheSignal marks only shared, form-free HTML pages as eligible for a
// service-worker offline copy. Requests with any cookie are visitor-specific.
func (s *Server) offlineCacheSignal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || hasVisitorCookie(r) || !isOfflinePublicPage(s.GetBaseURL(r), r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(&offlineSignalWriter{ResponseWriter: w}, r)
	})
}

func hasVisitorCookie(r *http.Request) bool {
	for _, cookie := range r.Cookies() {
		if cookie.Name != constants.InternalName+"_build" {
			return true
		}
	}
	return false
}

func isOfflinePublicPage(base, requestPath string) bool {
	path := strings.TrimPrefix(requestPath, base)
	switch path {
	case "/server/about", "/about", "/server/docs", "/docs",
		"/server/help", "/server/terms", "/server/dpo",
		"/server/security", "/server/security/policy":
		return true
	default:
		return false
	}
}

type offlineSignalWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *offlineSignalWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if status >= http.StatusOK && status < http.StatusMultipleChoices &&
		strings.HasPrefix(strings.ToLower(w.Header().Get("Content-Type")), "text/html") {
		w.Header().Set("X-Offline-Cache", "public")
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *offlineSignalWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

func (w *offlineSignalWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
