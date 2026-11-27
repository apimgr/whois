package server

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/apimgr/whois/src/common/constants"
	"github.com/apimgr/whois/src/common/i18n"
)

// translatablePageData embeds language and translation fields into page data structs.
// All HTML page data structs must embed this to satisfy AI.md PART 16 and PART 30.
type translatablePageData struct {
	AppName     string
	CurrentPath string
	// Lang is the BCP-47 language code used in the <html lang="…"> attribute.
	Lang string
	// Dir is the text direction ("ltr" or "rtl") used in the <html dir="…"> attribute.
	Dir string
	// Theme is the active theme name (dark/light/auto) read from the theme cookie.
	// The server renders class="theme-{{.Theme}}" on <html> so the page renders
	// correctly without JS (AI.md PART 16 Themes — NON-NEGOTIABLE).
	Theme           string
	ConsentRequired bool
	// Footer holds the values needed to render the shared application footer
	// via {{footer .Footer}} (AI.md PART 16 — Footer Customization).
	Footer FooterData
	// HeaderHTML is the sanitized optional branding.content.header fragment.
	HeaderHTML template.HTML
	// CSRFToken is embedded as a hidden form field on state-changing forms
	// (AI.md PART 16 — CSRF Protection, double-submit cookie pattern).
	CSRFToken string
	// ConsentBannerHTML renders the cookie consent banner markup, or empty
	// when a valid cookie_consent cookie already exists (AI.md PART 16 —
	// Cookie Consent Banner, Banner Behavior).
	ConsentBannerHTML template.HTML
	// AnnouncementsHTML renders the stacked site-banner markup for active,
	// non-dismissed announcements, or empty when there are none (AI.md
	// PART 16 — Site Banner, Placement: "Immediately after <body>, before
	// <main>").
	AnnouncementsHTML template.HTML
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

// newPageData returns a translatablePageData populated from the request context,
// including the shared footer data (AI.md PART 16 — Footer Customization) and a
// CSRF token cookie/value for any forms on the page (AI.md PART 16 — CSRF Protection).
func (s *Server) newPageData(w http.ResponseWriter, r *http.Request) translatablePageData {
	lang := LangFromContext(r.Context())
	csrfToken := s.csrfToken(w, r)
	headerHTML := ""
	if strings.TrimSpace(s.config.Branding.Content.Header) != "" {
		headerHTML = SanitizeFooterHTML(s.config.Branding.Content.Header)
	}
	return translatablePageData{
		AppName:           s.brandName(),
		CurrentPath:       r.URL.Path,
		Lang:              lang,
		Dir:               i18n.Dir(lang),
		Theme:             themeFromRequest(r),
		ConsentRequired:   r.URL.Query().Get("consent_required") == "1",
		Footer:            s.footerData(lang),
		HeaderHTML:        template.HTML(headerHTML),
		CSRFToken:         csrfToken,
		ConsentBannerHTML: s.consentBannerHTML(w, r, lang),
		AnnouncementsHTML: s.announcementsHTML(w, r),
	}
}

// footerData builds the FooterData used to render the shared application
// footer for the given language (AI.md PART 16 — Footer Customization).
func (s *Server) footerData(lang string) FooterData {
	tor := s.buildTorInfo()
	torEnabled := tor.Enabled
	torRunning := tor.Running
	onionAddr := tor.Hostname
	return FooterData{
		Lang:         lang,
		LanguageName: s.nativeLanguageName(lang),
		TorEnabled:   torEnabled,
		TorRunning:   torRunning,
		OnionAddress: onionAddr,
		I2PAddress: func() string {
			if s.config.I2P.Expose {
				if svc := s.currentI2P(); svc != nil {
					return svc.Address()
				}
			}
			return ""
		}(),
		ProjectVersion: Version,
		BuildDatetime:  BuildDate,
		CustomHTML:     SanitizeFooterHTML(s.config.Web.Footer.CustomHTML),
		RepoURL:        constants.RepoURL,
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
	Name         string
	Tagline      string
	APIVersion   string
	RateLimits   []rateLimitPageRow
	OfficialSite string
}

type rateLimitPageRow struct {
	Label    string
	Requests int
	Window   int
}

// Templates loaded from src/server/template/ via embed (AI.md PART 7).
var aboutTmpl = mustParseTemplate("about", "page/about.tmpl")
var docsTmpl = mustParseTemplate("docs", "page/docs.tmpl")

// renderTemplate executes tmpl with the per-request tracking/consent
// template functions bound (AI.md PART 16 — Cookie Consent Banner, Consent
// check in templates: trackingAllowed / trackingScript / preferencesAllowed).
func (s *Server) renderTemplate(tmpl *template.Template, w http.ResponseWriter, r *http.Request, data interface{}) error {
	funcs := s.consentTemplateFuncs(r)
	funcs["path"] = func(urlPath string) string {
		result := s.withBaseURL(r, urlPath)
		if strings.HasPrefix(urlPath, "/static/") {
			stamp := url.QueryEscape(Version + "-" + CommitID)
			separator := "?"
			if strings.Contains(result, "?") {
				separator = "&"
			}
			result += separator + "v=" + stamp
		}
		return result
	}
	return tmpl.Funcs(funcs).ExecuteTemplate(w, "public.tmpl", data)
}

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
		translatablePageData: s.newPageData(w, r),
		Name:                 name,
		Tagline:              tagline,
		Description:          description,
		Version:              Version,
		BuildDate:            BuildDate,
		OfficialSite:         s.config.FQDN,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(aboutTmpl, w, r, data); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
	}
}

func (s *Server) handleAboutAPI(w http.ResponseWriter, r *http.Request) {
	tagline := s.config.Branding.Tagline
	if tagline == "" {
		tagline = "Self-hosted WHOIS lookup service"
	}
	description := s.config.Branding.Description
	if description == "" {
		description = constants.InternalName + " is a self-hosted WHOIS lookup service for domain names, IP addresses, and ASNs."
	}
	content := s.config.Pages.About.Content
	if content == "" {
		content = "# " + s.brandName() + "\n\n" + tagline + "\n\n" + description
	}
	SendSuccess(w, map[string]string{"title": s.brandName(), "content": content, "format": "markdown"})
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
		translatablePageData: s.newPageData(w, r),
		Name:                 name,
		Tagline:              s.config.Branding.Tagline,
		APIVersion:           s.config.APIVersion,
		RateLimits: []rateLimitPageRow{
			{Label: "docs.rate_read", Requests: s.config.RateLimit.Read.Requests, Window: s.config.RateLimit.Read.Window},
			{Label: "docs.rate_write", Requests: s.config.RateLimit.Write.Requests, Window: s.config.RateLimit.Write.Window},
			{Label: "docs.rate_health", Requests: s.config.RateLimit.Health.Requests, Window: s.config.RateLimit.Health.Window},
			{Label: "docs.rate_strict", Requests: s.config.RateLimit.Strict.Requests, Window: s.config.RateLimit.Strict.Window},
			{Label: "docs.rate_auth_failures", Requests: s.config.RateLimit.AuthFailures.Requests, Window: s.config.RateLimit.AuthFailures.Window},
			{Label: "docs.rate_global", Requests: s.config.RateLimit.GlobalBurst, Window: 60},
		},
		OfficialSite: s.config.FQDN,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(docsTmpl, w, r, data); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
	}
}
