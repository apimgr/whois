package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"

	"github.com/apimgr/whois/src/common/constants"
	"github.com/apimgr/whois/src/common/i18n"
)

// HTTPClientType represents the type of client making the request
type HTTPClientType string

type serverContextKey struct{}

func withServerContext(server *Server, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), serverContextKey{}, server))
		next.ServeHTTP(w, r)
	})
}

func serverFromContext(ctx context.Context) *Server {
	server, _ := ctx.Value(serverContextKey{}).(*Server)
	return server
}

const (
	ClientTypeHTML HTTPClientType = "html"
	ClientTypeJSON HTTPClientType = "json"
	ClientTypeText HTTPClientType = "text"
)

// isOurCliClient detects our own client binary ({project_name}-cli).
// The client is INTERACTIVE (TUI/GUI) — it receives JSON and renders itself.
// AI.md PART 14 "Client Type Detection & Response".
func isOurCliClient(r *http.Request) bool {
	ua := r.Header.Get("User-Agent")
	return strings.HasPrefix(ua, constants.InternalName+"-cli/") || ua == constants.InternalName+"-cli"
}

// isTextBrowser detects text-mode browsers (lynx, w3m, links, elinks, etc.).
// Text browsers are INTERACTIVE but do NOT support JavaScript — they receive
// the no-JS HTML alternative (server-rendered, standard form POST).
// AI.md PART 14 "Client Type Detection & Response".
func isTextBrowser(r *http.Request) bool {
	ua := strings.ToLower(r.Header.Get("User-Agent"))

	textBrowsers := []string{
		"lynx/",
		"w3m/",
		"links ",
		"links/",
		"elinks/",
		"browsh/",
		"carbonyl/",
		"netsurf",
	}
	for _, browser := range textBrowsers {
		if strings.Contains(ua, browser) {
			return true
		}
	}
	return false
}

// isHttpTool detects HTTP tools (curl, wget, httpie, etc.).
// HTTP tools are NON-INTERACTIVE — they just fetch and dump output.
// AI.md PART 14 "Client Type Detection & Response".
func isHttpTool(r *http.Request) bool {
	ua := strings.ToLower(r.Header.Get("User-Agent"))

	httpTools := []string{
		"curl/", "wget/", "httpie/",
		"libcurl/", "python-requests/",
		"go-http-client/", "axios/", "node-fetch/",
	}
	for _, tool := range httpTools {
		if strings.Contains(ua, tool) {
			return true
		}
	}

	// No User-Agent = likely HTTP tool (non-interactive)
	if ua == "" {
		return true
	}

	return false
}

// isNonInteractiveClient detects clients that need pre-formatted text.
// ONLY HTTP tools are non-interactive — our client and text browsers handle
// their own rendering. AI.md PART 14 "Client Type Detection & Response".
func isNonInteractiveClient(r *http.Request) bool {
	if isOurCliClient(r) {
		return false
	}
	if isTextBrowser(r) {
		return false
	}
	if isHttpTool(r) {
		return true
	}
	return false
}

// isBrowserUserAgent detects general graphical browser User-Agents.
func isBrowserUserAgent(ua string) bool {
	browsers := []string{
		"Mozilla/", "Chrome/", "Safari/", "Edge/", "Firefox/",
		"Opera/", "MSIE", "Trident/",
	}
	for _, browser := range browsers {
		if strings.Contains(ua, browser) {
			return true
		}
	}
	return false
}

// DetectClientType detects the client type based on Accept header and
// User-Agent, using the isOurCliClient/isTextBrowser/isHttpTool client
// detection model from AI.md PART 14.
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

	// 2. Our client is interactive — it renders its own TUI/GUI from JSON.
	if isOurCliClient(r) {
		return ClientTypeJSON
	}

	// 3. Text browsers are interactive — they receive HTML (no-JS alternative).
	if isTextBrowser(r) {
		return ClientTypeHTML
	}

	// 4. Graphical browser User-Agents get the full HTML page.
	ua := r.Header.Get("User-Agent")
	if isBrowserUserAgent(ua) {
		return ClientTypeHTML
	}

	// 5. Non-interactive HTTP tools (curl, wget, httpie, ...) and empty
	// User-Agents get pre-formatted plain text.
	if isNonInteractiveClient(r) {
		return ClientTypeText
	}

	// 6. Default: HTML (safest fallback for unknown clients)
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

// apiContentNegotiation applies the API response format rules and dispatches
// .txt aliases to the same route handler.
func apiContentNegotiation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/api/mcp") || strings.Contains(r.URL.Path, "/server/mcp") {
			next.ServeHTTP(w, r)
			return
		}

		request := r.Clone(r.Context())
		request.Header = r.Header.Clone()
		textResponse := strings.HasSuffix(request.URL.Path, ".txt")
		if textResponse {
			urlCopy := *request.URL
			urlCopy.Path = strings.TrimSuffix(urlCopy.Path, ".txt")
			request.URL = &urlCopy
		} else {
			accept := request.Header.Get("Accept")
			if strings.Contains(accept, "text/plain") {
				textResponse = true
			} else if strings.TrimSpace(accept) == "" {
				textResponse = isNonInteractiveClient(request)
			}
		}
		if !textResponse {
			next.ServeHTTP(w, request)
			return
		}

		captured := httptest.NewRecorder()
		next.ServeHTTP(captured, request)
		result := captured.Result()
		defer func() { _ = result.Body.Close() }()
		for name, values := range result.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.Header().Del("Content-Length")
		body, err := io.ReadAll(result.Body)
		if err != nil {
			writeRequestError(w, r, http.StatusInternalServerError)
			return
		}
		// API errors keep their JSON envelope even for non-interactive clients;
		// callers need stable machine-readable error codes and messages.
		if result.StatusCode >= http.StatusBadRequest {
			w.Header().Set("Content-Type", result.Header.Get("Content-Type"))
			w.WriteHeader(result.StatusCode)
			_, _ = w.Write(body)
			return
		}
		contentType := result.Header.Get("Content-Type")
		if !strings.Contains(contentType, "application/json") {
			w.Header().Set("Content-Type", contentType)
			w.WriteHeader(result.StatusCode)
			_, _ = w.Write(ensureTrailingNewline(body))
			return
		}
		plain, ok := serializeAPIText(body, request.Method)
		if !ok {
			w.Header().Set("Content-Type", contentType)
			w.WriteHeader(result.StatusCode)
			_, _ = w.Write(body)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(result.StatusCode)
		_, _ = io.WriteString(w, ensureTextNewline(plain))
	})
}

func serializeAPIText(body []byte, method string) (string, bool) {
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", false
	}
	if object, ok := payload.(map[string]any); ok {
		if _, hasEnvelope := object["ok"]; !hasEnvelope {
			return "OK: Retrieved successfully\n" + strings.Join(flattenAPIText(payload, ""), "\n"), true
		}
	}
	var response APIResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", false
	}
	if !response.OK {
		return fmt.Sprintf("ERROR: %s: %s", response.Error, response.Message), true
	}
	if response.Data == nil {
		return "OK: " + defaultTextMessage(method), true
	}
	if items, ok := response.Data.([]any); ok {
		if len(items) == 0 {
			return "OK: 0 items found", true
		}
		var lines []string
		for _, item := range items {
			if _, object := item.(map[string]any); object {
				if len(lines) > 0 {
					lines = append(lines, "")
				}
				lines = append(lines, flattenAPIText(item, "")...)
			} else {
				lines = append(lines, fmt.Sprint(item))
			}
		}
		return fmt.Sprintf("OK: %d items found\n%s", len(items), strings.Join(lines, "\n")), true
	}
	return "OK: Retrieved successfully\n" + strings.Join(flattenAPIText(response.Data, ""), "\n"), true
}

func flattenAPIText(value any, prefix string) []string {
	switch typed := value.(type) {
	case map[string]any:
		var lines []string
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			name := key
			if prefix != "" {
				name = prefix + "." + key
			}
			lines = append(lines, flattenAPIText(typed[key], name)...)
		}
		return lines
	case []any:
		values := make([]string, len(typed))
		for i, item := range typed {
			values[i] = fmt.Sprint(item)
		}
		return []string{prefix + ": " + strings.Join(values, ", ")}
	default:
		if prefix == "" {
			return []string{fmt.Sprint(value)}
		}
		return []string{prefix + ": " + fmt.Sprint(value)}
	}
}

func defaultTextMessage(method string) string {
	switch method {
	case http.MethodPost:
		return "Created successfully"
	case http.MethodPut, http.MethodPatch:
		return "Updated successfully"
	case http.MethodDelete:
		return "Deleted successfully"
	default:
		return "Retrieved successfully"
	}
}

func ensureTextNewline(value string) string {
	return strings.TrimRight(value, "\r\n") + "\n"
}

func ensureTrailingNewline(value []byte) []byte {
	return []byte(ensureTextNewline(string(value)))
}

// respondJSON sends a JSON response with 2-space indentation and a single
// trailing newline (AI.md PART 14).
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	writeJSON(w, status, data)
}

// respondText sends a plain text response for non-interactive HTTP tools
// (curl, wget, ...) hitting a frontend route. Per AI.md PART 14 "Client Type
// Detection & Response", these clients receive the full HTML page rendered
// server-side, then converted to beautifully formatted text via
// HTML2TextConverter — not raw/hand-rolled data formatting.
func respondText(w http.ResponseWriter, status int, data interface{}) {
	var rendered string
	switch v := data.(type) {
	case string:
		rendered = v
	case fmt.Stringer:
		rendered = v.String()
	default:
		rendered = fmt.Sprintf("%v", v)
	}

	var buf bytes.Buffer
	pd := responsePageData{
		Name:    constants.InternalName,
		Content: rendered,
	}
	text := rendered
	if err := htmlResponseTmpl.ExecuteTemplate(&buf, "page_content", pd); err == nil {
		text = HTML2TextConverter(buf.String())
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "%s\n", text)
}

// htmlBlockTagPattern matches closing block-level tags that should become
// paragraph/line breaks in the converted plain text.
var htmlBlockTagPattern = regexp.MustCompile(`(?i)</\s*(p|div|h[1-6]|li|tr|section|article|header|footer|nav|main|table|ul|ol)\s*>`)

// htmlBreakTagPattern matches <br> and <br/> tags.
var htmlBreakTagPattern = regexp.MustCompile(`(?i)<\s*br\s*/?\s*>`)

// htmlScriptStylePattern matches <script>...</script> and <style>...</style>
// blocks, which must never appear in the text output.
var htmlScriptStylePattern = regexp.MustCompile(`(?is)<\s*(script|style)[^>]*>.*?</\s*(script|style)\s*>`)

// htmlTagPattern matches any remaining HTML tag.
var htmlTagPattern = regexp.MustCompile(`(?s)<[^>]+>`)

// htmlBlankLinesPattern collapses 3+ consecutive newlines down to 2.
var htmlBlankLinesPattern = regexp.MustCompile(`\n{3,}`)

// HTML2TextConverter converts a rendered HTML page into beautifully
// formatted, readable plain text for non-interactive HTTP tools (curl, wget,
// httpie). It strips scripts/styles, turns block-level closing tags and
// <br> into line breaks, decodes entities, and collapses extra blank lines.
// AI.md PART 14 "Client Type Detection & Response".
func HTML2TextConverter(htmlContent string) string {
	text := htmlScriptStylePattern.ReplaceAllString(htmlContent, "")
	text = htmlBreakTagPattern.ReplaceAllString(text, "\n")
	text = htmlBlockTagPattern.ReplaceAllString(text, "\n")
	text = htmlTagPattern.ReplaceAllString(text, "")
	text = html.UnescapeString(text)

	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(strings.TrimSpace(line), " \t")
	}
	text = strings.Join(lines, "\n")
	text = htmlBlankLinesPattern.ReplaceAllString(text, "\n\n")

	return strings.TrimSpace(text)
}

// htmlResponseTmpl is the generic response template (AI.md PART 7 — loaded from src/server/template/).
var htmlResponseTmpl = mustParseTemplate("response", "page/response.tmpl")

// responsePageData is the data model for the generic response.html template.
type responsePageData struct {
	translatablePageData
	// Name is the brand name shown in the page title.
	Name    string
	Content string
}

// respondHTML sends an HTML response using the generic response template.
// The content value is HTML-escaped by html/template before rendering.
// The server instance is carried in the request context by setupMiddleware,
// which lets this shared response path use the same page chrome and CSRF data.
func respondHTML(w http.ResponseWriter, r *http.Request, status int, data interface{}) {
	lang := LangFromContext(r.Context())
	pd := responsePageData{
		translatablePageData: translatablePageData{
			AppName:     constants.InternalName,
			CurrentPath: r.URL.Path,
			Lang:        lang,
			Dir:         i18n.Dir(lang),
			Theme:       themeFromRequest(r),
		},
		Name:    constants.InternalName,
		Content: fmt.Sprintf("%v", data),
	}
	if server := serverFromContext(r.Context()); server != nil {
		pageData := server.newPageData(w, r)
		pageData.AppName = server.brandName()
		pageData.CurrentPath = r.URL.Path
		pd.translatablePageData = pageData
		pd.Name = server.brandName()
	} else {
		csrfToken := ""
		if cookie, err := r.Cookie("csrf_token"); err == nil && cookie.Value != "" {
			csrfToken = cookie.Value
		} else {
			csrfToken = generateCSRFToken(32)
			http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: csrfToken, Path: "/", Secure: r.TLS != nil,
				SameSite: http.SameSiteStrictMode})
		}
		pd.CSRFToken = csrfToken
		pd.Footer = FooterData{Lang: lang, LanguageName: localeNativeLanguageName(lang), ProjectVersion: Version,
			RepoURL: constants.RepoURL}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := htmlResponseTmpl.ExecuteTemplate(w, "public.tmpl", pd); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
	}
}

// RespondError responds with an error in the appropriate format.
// The JSON branch emits the canonical envelope (AI.md PART 14):
// {"ok":false,"error":"CODE","message":"..."}.
func RespondError(w http.ResponseWriter, r *http.Request, status int, _ string) {
	clientType := DetectClientType(r)
	lang := requestErrorLanguage(r)
	_, messageKey := statusErrorKeys(status)

	switch clientType {
	case ClientTypeJSON:
		writeRequestAPIError(w, r, status)
	case ClientTypeText:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Language", lang)
		addVaryHeader(w.Header(), "Accept-Language")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, "%s\n", translateKey(lang, messageKey))
	case ClientTypeHTML:
		if server := serverFromContext(r.Context()); server != nil {
			server.renderStatusError(w, r, status)
		} else {
			titleKey, _ := statusErrorKeys(status)
			respondHTML(w, r, status, fmt.Sprintf("%s — %s", translateKey(lang, titleKey), translateKey(lang, messageKey)))
		}
	}
}
