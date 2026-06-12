package server

import (
	"net/http"
)

// translatablePageData embeds a translation function into page data structs.
// All page data structs that render HTML should embed this (AI.md PART 30).
type translatablePageData struct {
	// T is the translation function for the request's detected language.
	T func(string) string
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
	name := s.config.BrandingTitle
	if name == "" {
		name = "caswhois"
	}
	tagline := s.config.BrandingTagline
	if tagline == "" {
		tagline = "Self-hosted WHOIS lookup service"
	}
	description := s.config.BrandingDescription
	if description == "" {
		description = "caswhois is a self-hosted WHOIS lookup service for domain names, IP addresses, and ASNs."
	}
	data := AboutPageData{
		translatablePageData: translatablePageData{T: newTranslatorFunc(r)},
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
	name := s.config.BrandingTitle
	if name == "" {
		name = "caswhois"
	}
	data := DocsPageData{
		translatablePageData: translatablePageData{T: newTranslatorFunc(r)},
		Name:          name,
		Tagline:       s.config.BrandingTagline,
		APIVersion:    "v1",
		RateLimitRead: s.config.RateLimit.Read.Requests,
		OfficialSite:  s.config.FQDN,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := docsTmpl.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}
