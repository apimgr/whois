package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/apimgr/whois/src/common/i18n"
)

// handleCLIBinaryDownload serves prebuilt caswhois-cli binaries.
// Route: GET /cli/binaries/{binary_name}
// e.g.  GET /cli/binaries/caswhois-cli-linux-amd64
//
// Binaries are served from {data_dir}/cli-binaries/ if present.
// Returns 404 when the requested binary has not been published.
// Public by default; set cli.binary_download.require_auth in server.yml to require a token.
func (s *Server) handleCLIBinaryDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		SendError(w, ErrMethodNotAllowed, "method not allowed")
		return
	}

	// Extract binary filename from the URL path.
	// Strip the route prefix to get the filename.
	name := strings.TrimPrefix(r.URL.Path, "/cli/binaries/")
	name = filepath.Base(name)

	// Reject empty, dotfile, or path-traversal attempts.
	if name == "" || name == "." || strings.Contains(name, "/") || strings.HasPrefix(name, ".") {
		SendError(w, ErrNotFound, "binary not found")
		return
	}

	// Only serve files that look like project binaries to limit the attack surface.
	if !strings.HasPrefix(name, "caswhois-cli-") {
		SendError(w, ErrNotFound, "binary not found")
		return
	}

	binPath := filepath.Join(s.config.DataDir, "cli-binaries", name)

	// Check existence before opening to produce a clean 404.
	info, err := os.Stat(binPath)
	if err != nil || info.IsDir() {
		SendError(w, ErrNotFound, "binary not found")
		return
	}

	// Serve the binary with an appropriate Content-Type and disposition.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	http.ServeFile(w, r, binPath)
}

// handleLocaleJSON serves the embedded locale JSON file for the requested language.
// Route: GET /locales/{lang}.json
// Used by the web UI JavaScript to load translations at runtime.
// Falls back to English for unsupported or missing languages.
func (s *Server) handleLocaleJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		SendError(w, ErrMethodNotAllowed, "method not allowed")
		return
	}

	// Extract language code from path: /locales/en.json → "en"
	name := strings.TrimPrefix(r.URL.Path, "/locales/")
	lang := strings.TrimSuffix(name, ".json")

	// Validate — only serve supported language codes
	if !i18n.IsSupported(lang) {
		lang = "en"
	}

	data, err := i18n.LocaleJSON(lang)
	if err != nil {
		SendError(w, ErrServerError, "locale unavailable")
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}
