package server

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
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
		respondHTML(w, http.StatusOK, data)
	default:
		respondHTML(w, http.StatusOK, data)
	}
}

// respondJSON sends a JSON response
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
	}
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

// htmlResponseTmpl is the template for generic data HTML responses.
var htmlResponseTmpl = template.Must(template.New("response").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>caswhois</title>
</head>
<body>
<pre>{{.}}</pre>
</body>
</html>
`))

// respondHTML sends an HTML response using a server-side template.
// The data value is HTML-escaped by html/template before rendering.
func respondHTML(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := htmlResponseTmpl.Execute(w, fmt.Sprintf("%v", data)); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

// RespondError responds with an error in the appropriate format
func RespondError(w http.ResponseWriter, r *http.Request, status int, message string) {
	clientType := DetectClientType(r)

	errResp := ErrorResponse{
		Error:   http.StatusText(status),
		Message: message,
		Code:    status,
	}

	switch clientType {
	case ClientTypeJSON:
		respondJSON(w, status, errResp)
	case ClientTypeText:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		fmt.Fprintf(w, "Error: %s\n", message)
	case ClientTypeHTML:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		fmt.Fprintf(w, "<!DOCTYPE html>\n")
		fmt.Fprintf(w, "<html>\n")
		fmt.Fprintf(w, "<head><title>Error %d</title></head>\n", status)
		fmt.Fprintf(w, "<body>\n")
		fmt.Fprintf(w, "<h1>%s</h1>\n", http.StatusText(status))
		fmt.Fprintf(w, "<p>%s</p>\n", message)
		fmt.Fprintf(w, "</body>\n")
		fmt.Fprintf(w, "</html>\n")
	}
}
