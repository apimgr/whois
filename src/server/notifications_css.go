package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
)

func (s *Server) handleNotificationsCSS(w http.ResponseWriter, r *http.Request) {
	duration := s.config.Notifications.WebUI.Duration
	if duration < 0 {
		duration = 0
	}
	warningDuration := s.config.Notifications.WebUI.WarningDuration
	if warningDuration < 0 {
		warningDuration = 0
	}
	content := []byte(fmt.Sprintf(":root{--toast-duration:%ds;--toast-duration-warning:%ds}\n", duration, warningDuration))
	sum := sha256.Sum256(content)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}
