package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/apimgr/whois/src/common/constants"
)

// HTTPClientType represents the type of client making the request
type HTTPClientType string

const (
	ClientTypeHTML HTTPClientType = "html"
	ClientTypeJSON HTTPClientType = "json"
	ClientTypeText HTTPClientType = "text"
)

// DetectClientType detects the client type based on Accept header and User-Agent
func DetectClientType(r *http.Request) HTTPClientType {
	// 1. Check Accept header first (explicit preference)
	accept := r.Header.Get("Accept")

	if strings.Contains(accept, "text/html") {
		return ClientTypeHTML
	}
	if strings.Contains(accept, "application/json") {
		return ClientTypeJSON
	}
	if strings.Contains(accept, "text/plain") {
		return ClientTypeText
	}

	// 2. Check User-Agent for browser detection
	ua := r.Header.Get("User-Agent")

	// Browser User-Agents (common patterns)
	browsers := []string{
		"Mozilla/", "Chrome/", "Safari/", "Edge/", "Firefox/",
		"Opera/", "MSIE", "Trident/",
	}

	for _, browser := range browsers {
		if strings.Contains(ua, browser) {
			return ClientTypeHTML
		}
	}

	// 3. CLI tools (curl, wget, httpie, etc.)
	cliTools := []string{
		"curl/", "Wget/", "HTTPie/", "python-requests/",
		"Go-http-client/", "node-fetch/",
	}

	for _, tool := range cliTools {
		if strings.Contains(ua, tool) {
			return ClientTypeText
		}
	}

	// 4. Empty or unknown User-Agent - default to text for programmatic access
	if ua == "" {
		return ClientTypeText
	}

	// 5. Default: HTML (safest fallback)
	return ClientTypeHTML
}

// RespondWithFormat responds with the appropriate format based on client type
func RespondWithFormat(w http.ResponseWriter, r *http.Request, data interface{}) {
	clientType := DetectClientType(r)

	switch clientType {
	case ClientTypeJSON:
		respondJSON(w, http.StatusOK, data)
	case ClientTypeText:
		respondText(w, http.StatusOK, data)
	case ClientTypeHTML:
		respondHTML(w, r, http.StatusOK, data)
	default:
		respondHTML(w, r, http.StatusOK, data)
	}
}

// respondJSON sends a JSON response with 2-space indentation and a single
// trailing newline (AI.md PART 14).
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	writeJSON(w, status, data)
}

// respondText sends a plain text response
func respondText(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)

	// Convert data to text
	var text string
	switch v := data.(type) {
	case string:
		text = v
	case fmt.Stringer:
		text = v.String()
	default:
		// Try to format as simple text
		text = fmt.Sprintf("%v", v)
	}

	fmt.Fprintf(w, "%s\n", text)
}

// htmlResponseTmpl is the generic response template (AI.md PART 7 — loaded from src/server/template/).
var htmlResponseTmpl = mustParseTemplate("response", "response.html")

// responsePageData is the data model for the generic response.html template.
type responsePageData struct {
	translatablePageData
	// Name is the brand name shown in the page title.
	Name    string
	Content string
}

// respondHTML sends an HTML response using the generic response template.
// The content value is HTML-escaped by html/template before rendering.
func respondHTML(w http.ResponseWriter, r *http.Request, status int, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	pd := responsePageData{
		translatablePageData: newPageData(r),
		Name:                 constants.InternalName,
		Content:              fmt.Sprintf("%v", data),
	}
	if err := htmlResponseTmpl.Execute(w, pd); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// RespondError responds with an error in the appropriate format.
// The JSON branch emits the canonical envelope (AI.md PART 14):
// {"ok":false,"error":"CODE","message":"..."}.
func RespondError(w http.ResponseWriter, r *http.Request, status int, message string) {
	clientType := DetectClientType(r)

	switch clientType {
	case ClientTypeJSON:
		respondJSON(w, status, APIResponse{
			OK:      false,
			Error:   statusToErrorCode(status),
			Message: message,
		})
	case ClientTypeText:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		fmt.Fprintf(w, "Error: %s\n", message)
	case ClientTypeHTML:
		respondHTML(w, r, status, fmt.Sprintf("%s — %s", http.StatusText(status), message))
	}
}
