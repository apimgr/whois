package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/apimgr/whois/src/common/i18n"
	"github.com/apimgr/whois/src/whois"
)

// newTranslatorFunc returns a T(key) function for template use, loaded from request context.
func newTranslatorFunc(r *http.Request) func(string) string {
	lang := LangFromContext(r.Context())
	tr, err := i18n.Load(lang)
	if err != nil {
		tr, _ = i18n.Load("en")
	}
	return tr.T
}

// Templates are loaded from src/server/template/ via embed (AI.md PART 7).
var homepageTmpl = mustParseTemplate("home", "home.html")
var whoisPageTmpl = mustParseTemplate("whois-page", "whois.html")

// homePageData holds template data for the homepage.
type homePageData struct {
	translatablePageData
	Query  string
	Result *whoisResultView
	Err    string
}

// whoisResultView is a presentation-layer view of a WHOISResult.
type whoisResultView struct {
	Query     string
	Type      string
	Server    string
	Timestamp string
	Raw       string
}

// whoisPageData holds template data for the /whois result page.
type whoisPageData struct {
	translatablePageData
	Query  string
	Result *whoisResultView
	Err    string
}

// handlePublicWHOISPage serves the public WHOIS lookup homepage at /.
// GET /
func (s *Server) handlePublicWHOISPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// JSON API clients get the API info response.
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		s.handleRootAPI(w, r)
		return
	}

	data := homePageData{translatablePageData: newPageData(r)}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := homepageTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// handleWHOISPage handles the form-submission fallback at GET /whois?q=...
// Browsers with JS never reach this — the fetch intercepts first.
// Browsers without JS (and curl with Accept: text/html) do reach it.
func (s *Server) handleWHOISPage(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))

	clientType := DetectClientType(r)

	// Plain-text clients (curl, wget, etc.) get raw WHOIS output.
	if clientType == ClientTypeText || strings.Contains(r.Header.Get("Accept"), "text/plain") {
		if q == "" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Usage: GET /whois?q=<domain|ip|asn>\n"))
			return
		}
		result, err := whois.QueryWHOISWithCache(r.Context(), q, s.cache)
		if err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("WHOIS lookup failed: " + err.Error() + "\n"))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(result.Raw))
		return
	}

	// JSON clients get the structured response.
	if clientType == ClientTypeJSON || strings.Contains(r.Header.Get("Accept"), "application/json") {
		if q == "" {
			SendError(w, ErrBadRequest, "Query parameter q is required")
			return
		}
		result, err := whois.QueryWHOISWithCache(r.Context(), q, s.cache)
		if err != nil {
			SendError(w, ErrServerError, "WHOIS lookup failed: "+err.Error())
			return
		}
		SendSuccess(w, map[string]interface{}{
			"query":     result.Query,
			"type":      result.Type.String(),
			"server":    result.Server,
			"timestamp": result.Timestamp.Format(time.RFC3339),
			"raw":       result.Raw,
		})
		return
	}

	// HTML clients — render the server-side result page.
	data := whoisPageData{translatablePageData: newPageData(r), Query: q}

	if q != "" {
		result, err := whois.QueryWHOISWithCache(r.Context(), q, s.cache)
		if err != nil {
			data.Err = "WHOIS lookup failed: " + err.Error()
		} else {
			data.Result = &whoisResultView{
				Query:     result.Query,
				Type:      result.Type.String(),
				Server:    result.Server,
				Timestamp: result.Timestamp.Format(time.RFC3339),
				Raw:       result.Raw,
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := whoisPageTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// handleRootAPI returns API information for root endpoint when Accept: application/json.
func (s *Server) handleRootAPI(w http.ResponseWriter, r *http.Request) {
	SendSuccess(w, map[string]interface{}{
		"service":     "caswhois",
		"description": "WHOIS lookup service — query domains, IPs, and ASNs",
		"version":     "0.1.0",
		"endpoints": []string{
			"GET /api/v1/whois/{query}         — generic lookup",
			"GET /api/v1/whois/domain/{domain} — domain lookup",
			"GET /api/v1/whois/ip/{ip}         — IP lookup",
			"GET /api/v1/whois/asn/{asn}       — ASN lookup",
			"GET /api/v1/whois/validate/{q}    — validate without lookup",
			"POST /api/v1/whois/bulk           — bulk lookup (auth required)",
			"GET /api/v1/whois-servers         — list WHOIS servers",
			"GET /api/v1/server/stats          — service statistics",
			"GET /server/healthz               — health check",
		},
	})
}
