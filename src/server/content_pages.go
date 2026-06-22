package server

import (
	"net/http"

	"github.com/casapps/caswhois/src/common/i18n"
)

// translatablePageData embeds language and translation fields into page data structs.
// All HTML page data structs must embed this to satisfy AI.md PART 16 and PART 30.
type translatablePageData struct {
	// T is the translation function for the request's detected language.
	T func(string) string
	// Lang is the BCP-47 language code used in the <html lang="…"> attribute.
	Lang string
	// Dir is the text direction ("ltr" or "rtl") used in the <html dir="…"> attribute.
	Dir string
}

// newPageData returns a translatablePageData populated from the request context.
func newPageData(r *http.Request) translatablePageData {
	lang := LangFromContext(r.Context())
	return translatablePageData{
		T:    newTranslatorFunc(r),
		Lang: lang,
		Dir:  i18n.Dir(lang),
	}
}

// AboutPageData holds the dynamic data for the /about and /server/about pages.
// Content is sourced from branding config (which defaults to IDEA.md values) per AI.md PART 16.
type AboutPageData struct {
	translatablePageData
	Name         string
	Tagline      string
	Description  string
	Version      string
	BuildDate    string
	OfficialSite string
}

// DocsPageData holds the dynamic data for the /docs and /server/docs pages.
type DocsPageData struct {
	translatablePageData
	Name          string
	Tagline       string
	APIVersion    string
	RateLimitRead int
	OfficialSite  string
}

// Templates loaded from src/server/template/ via embed (AI.md PART 7).
var aboutTmpl = mustParseTemplate("about", "about.html")
var docsTmpl = mustParseTemplate("docs", "docs.html")

// handleAboutPage serves the about page.
// Content is sourced from branding config (defaults to IDEA.md values) per AI.md PART 16.
// GET /about, /server/about
func (s *Server) handleAboutPage(w http.ResponseWriter, r *http.Request) {
	name := s.config.Branding.Title
	if name == "" {
		name = "caswhois"
	}
	tagline := s.config.Branding.Tagline
	if tagline == "" {
		tagline = "Self-hosted WHOIS lookup service"
	}
	description := s.config.Branding.Description
	if description == "" {
		description = "caswhois is a self-hosted WHOIS lookup service for domain names, IP addresses, and ASNs."
	}
	data := AboutPageData{
		translatablePageData: newPageData(r),
		Name:         name,
		Tagline:      tagline,
		Description:  description,
		Version:      Version,
		BuildDate:    BuildDate,
		OfficialSite: s.config.FQDN,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := aboutTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// handleDocsPage serves the API documentation page.
// Content uses branding config and live config values (rate limits, API version) per AI.md PART 16.
// GET /docs, /server/docs
func (s *Server) handleDocsPage(w http.ResponseWriter, r *http.Request) {
	name := s.config.Branding.Title
	if name == "" {
		name = "caswhois"
	}
	data := DocsPageData{
		translatablePageData: newPageData(r),
		Name:          name,
		Tagline:       s.config.Branding.Tagline,
		APIVersion:    "v1",
		RateLimitRead: s.config.RateLimit.Read.Requests,
		OfficialSite:  s.config.FQDN,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := docsTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}
