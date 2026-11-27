package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/apimgr/whois/src/common/constants"
)

// Templates are loaded from src/server/template/ via embed (AI.md PART 7).
var homepageTmpl = mustParseTemplate("home", "page/home.tmpl")
var whoisPageTmpl = mustParseTemplate("whois-page", "page/whois.tmpl")

// homePageData holds template data for the homepage.
type homePageData struct {
	translatablePageData
	// Name is the operator-configured brand name, falling back to the internal binary name.
	Name    string
	APIBase string
	Query   string
	Result  *whoisResultView
	Err     string
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
	// Name is the operator-configured brand name, falling back to the internal binary name.
	Name    string
	APIBase string
	Query   string
	Result  *whoisResultView
	Err     string
}

// brandName returns the operator-configured brand title, falling back to InternalName.
func (s *Server) brandName() string {
	if s.config.Branding.Title != "" {
		return s.config.Branding.Title
	}
	return constants.InternalName
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

	data := homePageData{translatablePageData: s.newPageData(w, r), Name: s.brandName(), APIBase: s.config.APIBasePath()}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := homepageTmpl.ExecuteTemplate(w, "public.tmpl", data); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
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
			_, _ = w.Write([]byte("Usage: GET /whois?q=<domain|ip|asn>\n"))
			return
		}
		result, err := s.lookupWHOIS(r.Context(), q)
		if err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("WHOIS lookup failed: " + err.Error() + "\n"))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(lookupRaw(result)))
		return
	}

	// JSON clients get the structured response.
	if clientType == ClientTypeJSON || strings.Contains(r.Header.Get("Accept"), "application/json") {
		if q == "" {
			SendError(w, ErrBadRequest, "Query parameter q is required")
			return
		}
		result, err := s.lookupWHOIS(r.Context(), q)
		if err != nil {
			SendError(w, ErrServerError, "WHOIS lookup failed: "+err.Error())
			return
		}
		SendSuccess(w, lookupResponseData(result))
		return
	}

	// HTML clients — render the server-side result page.
	data := whoisPageData{translatablePageData: s.newPageData(w, r), Name: s.brandName(), APIBase: s.config.APIBasePath(), Query: q}

	if q != "" {
		result, err := s.lookupWHOIS(r.Context(), q)
		if err != nil {
			data.Err = "WHOIS lookup failed: " + err.Error()
		} else {
			data.Result = &whoisResultView{
				Query:     result.Query,
				Type:      result.QueryType.String(),
				Server:    lookupServer(result),
				Timestamp: result.Timestamp.Format(time.RFC3339),
				Raw:       lookupRaw(result),
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := whoisPageTmpl.ExecuteTemplate(w, "public.tmpl", data); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
	}
}

// handleRootAPI returns API information for root endpoint when Accept: application/json.
func (s *Server) handleRootAPI(w http.ResponseWriter, r *http.Request) {
	SendSuccess(w, map[string]interface{}{
		"service":     constants.InternalName,
		"description": "WHOIS lookup service — query domains, IPs, and ASNs",
		"version":     "0.1.0",
		"endpoints": []string{
			"GET " + s.config.APIBasePath() + "/whois/{query}         — generic lookup",
			"GET " + s.config.APIBasePath() + "/whois/domain/{domain} — domain lookup",
			"GET " + s.config.APIBasePath() + "/whois/ip/{ip}         — IP lookup",
			"GET " + s.config.APIBasePath() + "/whois/asn/{asn}       — ASN lookup",
			"GET " + s.config.APIBasePath() + "/whois/validate/{q}    — validate without lookup",
			"POST " + s.config.APIBasePath() + "/whois/bulk           — bulk lookup (auth required)",
			"GET " + s.config.APIBasePath() + "/whois-servers         — list WHOIS servers",
			"GET " + s.config.APIBasePath() + "/server/stats          — service statistics",
			"GET /server/healthz               — health check",
		},
	})
}
