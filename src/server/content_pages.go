package server

import (
	"net/http"

	"github.com/apimgr/whois/src/common/constants"
	"github.com/apimgr/whois/src/common/i18n"
)

// translatablePageData embeds language and translation fields into page data structs.
// All HTML page data structs must embed this to satisfy AI.md PART 16 and PART 30.
type translatablePageData struct {
	// Lang is the BCP-47 language code used in the <html lang="…"> attribute.
	Lang string
	// Dir is the text direction ("ltr" or "rtl") used in the <html dir="…"> attribute.
	Dir string
	// Theme is the active theme name (dark/light/auto) read from the theme cookie.
	// The server sets data-theme on <html> so the page renders correctly without JS.
	Theme string
}

// themeFromRequest reads the theme cookie and returns the active theme.
// Falls back to "dark" (the default per AI.md PART 16) when no cookie is present
// or the value is not one of the allowed values.
func themeFromRequest(r *http.Request) string {
	c, err := r.Cookie("theme")
	if err != nil {
		return "dark"
	}
	switch c.Value {
	case "dark", "light", "auto":
		return c.Value
	default:
		return "dark"
	}
}

// newPageData returns a translatablePageData populated from the request context.
func newPageData(r *http.Request) translatablePageData {
	lang := LangFromContext(r.Context())
	return translatablePageData{
		Lang:  lang,
		Dir:   i18n.Dir(lang),
		Theme: themeFromRequest(r),
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
		name = constants.InternalName
	}
	tagline := s.config.Branding.Tagline
	if tagline == "" {
		tagline = "Self-hosted WHOIS lookup service"
	}
	description := s.config.Branding.Description
	if description == "" {
		description = constants.InternalName + " is a self-hosted WHOIS lookup service for domain names, IP addresses, and ASNs."
	}
	data := AboutPageData{
		translatablePageData: newPageData(r),
		Name:                 name,
		Tagline:              tagline,
		Description:          description,
		Version:              Version,
		BuildDate:            BuildDate,
		OfficialSite:         s.config.FQDN,
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
		name = constants.InternalName
	}
	data := DocsPageData{
		translatablePageData: newPageData(r),
		Name:                 name,
		Tagline:              s.config.Branding.Tagline,
		APIVersion:           "v1",
		RateLimitRead:        s.config.RateLimit.Read.Requests,
		OfficialSite:         s.config.FQDN,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := docsTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}
