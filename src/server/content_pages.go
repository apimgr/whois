package server

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

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
	AnnouncementsHTML    template.HTML
	ToastDuration        int
	ToastWarningDuration int
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
	headerHTML := string(s.operatorHTML(r, "header"))
	return translatablePageData{
		AppName:              s.brandName(),
		CurrentPath:          r.URL.Path,
		Lang:                 lang,
		Dir:                  i18n.Dir(lang),
		Theme:                themeFromRequest(r),
		ConsentRequired:      r.URL.Query().Get("consent_required") == "1",
		Footer:               s.footerData(lang, r),
		HeaderHTML:           template.HTML(headerHTML),
		CSRFToken:            csrfToken,
		ConsentBannerHTML:    s.consentBannerHTML(w, r, lang),
		AnnouncementsHTML:    s.announcementsHTML(w, r),
		ToastDuration:        s.config.Notifications.WebUI.Duration,
		ToastWarningDuration: s.config.Notifications.WebUI.WarningDuration,
	}
}

// footerData builds the FooterData used to render the shared application
// footer for the given language (AI.md PART 16 — Footer Customization).
func (s *Server) footerData(lang string, requests ...*http.Request) FooterData {
	tor := s.buildTorInfo()
	torEnabled := tor.Enabled
	torRunning := tor.Running
	onionAddr := tor.Hostname
	customHTML := SanitizeFooterHTML(s.config.Web.Footer.CustomHTML)
	if len(requests) > 0 {
		if custom := s.operatorHTML(requests[0], "footer"); custom != "" {
			customHTML = string(custom)
		}
	}
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
		CustomHTML:     customHTML,
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
	funcs["asset"] = func(assetPath string) string {
		result := s.withBaseURL(r, "/static/"+strings.TrimLeft(assetPath, "/"))
		separator := "?"
		if strings.Contains(result, "?") {
			separator = "&"
		}
		return result + separator + "v=" + url.QueryEscape(Version+"-"+CommitID)
	}
	funcs["operatorHTML"] = func(name string) template.HTML { return s.operatorHTML(r, name) }
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
		description = "caswhois is a self-hosted WHOIS lookup service that provides fast, cached information about domain names, IP addresses, and Autonomous System Numbers (ASNs). It ships as a single static binary with an embedded SQLite database, a web interface, a REST API, and a companion CLI client. No external dependencies are required for first-run."
	}
	content, format, _ := resolvedPageContent(s.config.Branding.Content.About.Body, s.config.Branding.Content.About.Format, LangFromContext(r.Context()))
	if content == "" {
		content = aboutFallback(s.brandName(), tagline, description)
	}
	content = substitutePageVariables(s, r, content)
	SendSuccess(w, map[string]string{"title": s.brandName(), "content": content, "format": format})
}

func aboutFallback(name, tagline, description string) string {
	content := "# " + name + "\n\n" + tagline + "\n\n" + description + "\n\n## Features\n\n" +
		"- WHOIS lookup for domains, IPv4, IPv6, and ASNs with automatic query detection\n" +
		"- RDAP-first retrieval with WHOIS fallback\n" +
		"- Cached lookups and a persistent local WHOIS dataset\n" +
		"- Owner and registrant reverse search with optional provider seeding\n" +
		"- GeoIP enrichment, optional Tor hidden service, and Prometheus metrics\n" +
		"- Encrypted backups, in-place updates, and a built-in scheduler\n" +
		"- Web interface, REST API, GraphQL, MCP, and companion CLI"
	links := []string{"- [Source repository](" + constants.RepoURL + ")", "- [API documentation](/server/docs)", "- [API reference](/server/docs/swagger)"}
	if OfficialSite != "" {
		links = append([]string{"- [Official site](" + OfficialSite + ")"}, links...)
	}
	return content + "\n\n## Links\n\n" + strings.Join(links, "\n")
}

func substitutePageVariables(s *Server, r *http.Request, body string) string {
	footer := s.footerData(LangFromContext(r.Context()))
	buildDate := BuildDate
	if parsed, err := time.Parse(time.RFC3339, BuildDate); err == nil {
		buildDate = parsed.UTC().Format("January 02, 2006 at 15:04:05 MST")
	}
	values := []string{
		"{current_year}", fmt.Sprint(time.Now().Year()),
		"{project_name}", constants.InternalName,
		"{project_org}", constants.InternalOrg,
		"{project_version}", Version,
		"{build_datetime}", buildDate,
		"{onion_address}", footer.OnionAddress,
		"{i2p_address}", footer.I2PAddress,
	}
	return strings.NewReplacer(values...).Replace(body)
}

func resolvedPageContent(body any, configuredFormat, language string) (string, string, bool) {
	format := "markdown"
	switch strings.ToLower(configuredFormat) {
	case "", "md", "markdown":
	case "html":
		format = "html"
	case "txt", "text":
		format = "text"
	default:
		return "", "markdown", false
	}
	content, ok := contentBody(body, language)
	if !ok || len(content) > 256*1024 {
		return "", "markdown", false
	}
	return content, format, true
}

func contentBody(body any, language string) (string, bool) {
	switch value := body.(type) {
	case string:
		return value, strings.TrimSpace(value) != ""
	case map[string]any:
		if content, ok := value[language].(string); ok && strings.TrimSpace(content) != "" {
			return content, true
		}
		content, ok := value["default"].(string)
		return content, ok && strings.TrimSpace(content) != ""
	case map[string]string:
		if content, ok := value[language]; ok && strings.TrimSpace(content) != "" {
			return content, true
		}
		content, ok := value["default"]
		return content, ok && strings.TrimSpace(content) != ""
	default:
		return "", false
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
