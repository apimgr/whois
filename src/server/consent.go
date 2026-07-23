package server

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// consentCookieName is the name of the granular cookie-consent cookie
// (AI.md PART 16 — Cookie Consent Banner, Consent Logic (Granular)).
const consentCookieName = "cookie_consent"

// ccpaCookieName tracks a CCPA "Do Not Sell" opt-out independent of the
// general consent categories (AI.md PART 16 — CCPA Compliance).
const ccpaCookieName = "ccpa_opt_out"

// consentCookie is the JSON shape persisted in the cookie_consent cookie
// (AI.md PART 16 — Cookie Consent Banner, Consent Logic (Granular)).
type consentCookie struct {
	Essential   bool  `json:"essential"`
	Preferences bool  `json:"preferences"`
	Analytics   bool  `json:"analytics"`
	Timestamp   int64 `json:"timestamp"`
}

// hasConsentCookie reports whether the request already carries a valid
// cookie_consent cookie, in which case the banner must not be rendered
// again (AI.md PART 16 — Cookie Consent Banner, Server-side behavior).
func hasConsentCookie(r *http.Request) bool {
	return getConsentFromRequest(r) != nil
}

// getConsentFromRequest decodes the cookie_consent cookie, returning nil
// when absent, empty, or malformed.
func getConsentFromRequest(r *http.Request) *consentCookie {
	c, err := r.Cookie(consentCookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	raw, err := url.QueryUnescape(c.Value)
	if err != nil {
		raw = c.Value
	}
	var cc consentCookie
	if err := json.Unmarshal([]byte(raw), &cc); err != nil {
		return nil
	}
	return &cc
}

// writeConsentCookie persists the granular consent choice for one year
// (AI.md PART 16 — Cookie Consent Banner, Consent Logic (Granular)).
func (s *Server) writeConsentCookie(w http.ResponseWriter, r *http.Request, cc consentCookie) {
	data, err := json.Marshal(cc)
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     consentCookieName,
		Value:    url.QueryEscape(string(data)),
		Path:     "/",
		MaxAge:   365 * 24 * 3600,
		HttpOnly: false,
		Secure:   csrfCookieSecure(s.config.CSRF.Secure, r),
		SameSite: http.SameSiteLaxMode,
	})
}

// redirectBack sends the user back to the same-origin page that submitted
// the form, falling back to fallback when Referer is unset or cross-origin
// (AI.md PART 16 — Cookie Consent Banner, Server-side behavior: "redirects
// back to the originating page").
func redirectBack(w http.ResponseWriter, r *http.Request, fallback string) {
	target := fallback
	if ref := r.Referer(); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Host == r.Host {
			target = ref
		}
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// handleConsent processes the cookie consent banner form submission
// (AI.md PART 16 — Cookie Consent Banner: POST /server/consent).
// choice=accept: all categories accepted. choice=decline: essential only.
// choice=save: granular preferences from the preferences modal.
func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	choice := r.FormValue("choice")
	cc := consentCookie{Essential: true, Timestamp: time.Now().Unix()}
	switch choice {
	case "accept":
		cc.Preferences = true
		cc.Analytics = true
	case "decline":
		// Essential only — Preferences and Analytics remain false.
	case "save":
		cc.Preferences = r.FormValue("preferences") == "on" || r.FormValue("preferences") == "true"
		cc.Analytics = r.FormValue("analytics") == "on" || r.FormValue("analytics") == "true"
	default:
		SendError(w, ErrBadRequest, "choice must be accept, decline, or save")
		return
	}
	s.writeConsentCookie(w, r, cc)
	redirectBack(w, r, "/")
}

// handleCCPA processes the CCPA "Do Not Sell My Personal Information"
// opt-out/opt-in form submission (AI.md PART 16 — Cookie Consent Banner,
// Decline Behavior / CCPA: POST /server/ccpa).
func (s *Server) handleCCPA(w http.ResponseWriter, r *http.Request) {
	choice := r.FormValue("choice")
	switch choice {
	case "opt-out":
		http.SetCookie(w, &http.Cookie{
			Name:     ccpaCookieName,
			Value:    "true",
			Path:     "/",
			MaxAge:   365 * 24 * 3600,
			HttpOnly: false,
			Secure:   csrfCookieSecure(s.config.CSRF.Secure, r),
			SameSite: http.SameSiteLaxMode,
		})
	case "opt-in":
		http.SetCookie(w, &http.Cookie{
			Name:     ccpaCookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: false,
			Secure:   csrfCookieSecure(s.config.CSRF.Secure, r),
			SameSite: http.SameSiteLaxMode,
		})
	default:
		SendError(w, ErrBadRequest, "choice must be opt-out or opt-in")
		return
	}
	redirectBack(w, r, "/server/privacy#ccpa-opt-out")
}

// CheckTrackingAllowed returns true only when the visitor has consented to
// analytics AND an analytics provider is configured (AI.md PART 16 —
// Cookie Consent Banner, Decline Behavior → Implementation).
func (s *Server) CheckTrackingAllowed(r *http.Request) bool {
	consent := getConsentFromRequest(r)
	if consent == nil || !consent.Analytics {
		return false
	}
	return s.config.Tracking.Type != ""
}

// consentTemplateFuncs returns the per-request template functions used by
// the "trackingAllowed" / "trackingScript" / "preferencesAllowed" template
// calls (AI.md PART 16 — Cookie Consent Banner, Consent check in templates).
func (s *Server) consentTemplateFuncs(r *http.Request) template.FuncMap {
	return template.FuncMap{
		"trackingAllowed": func() bool {
			return s.CheckTrackingAllowed(r)
		},
		"trackingScript": func() template.HTML {
			if !s.CheckTrackingAllowed(r) {
				return ""
			}
			return s.generateTrackingScript()
		},
		"preferencesAllowed": func() bool {
			consent := getConsentFromRequest(r)
			return consent != nil && consent.Preferences
		},
	}
}

// generateTrackingScript renders the configured analytics provider's
// embed snippet (AI.md PART 16 — Cookie Consent Banner, Decline Behavior →
// Implementation: generateTrackingScript).
func (s *Server) generateTrackingScript() template.HTML {
	t := s.config.Tracking
	switch t.Type {
	case "umami":
		return template.HTML(`<script async src="` + template.HTMLEscapeString(t.URL) + `" data-website-id="` + template.HTMLEscapeString(t.ID) + `"></script>`)
	case "simple":
		return template.HTML(`<script async defer src="https://scripts.simpleanalyticscdn.com/latest.js"></script>`)
	case "cloudflare":
		return template.HTML(`<script defer src="https://static.cloudflareinsights.com/beacon.min.js" data-cf-beacon='{"token": "` + template.HTMLEscapeString(t.ID) + `"}'></script>`)
	default:
		return ""
	}
}

// consentBannerData holds the values needed to render the cookie consent
// banner partial (AI.md PART 16 — Cookie Consent Banner, Implementation →
// Template Variable Source table).
type consentBannerData struct {
	Message             string
	PolicyURL           string
	PolicyText          string
	DeclineText         string
	AcceptText          string
	PreferencesText     string
	ShowPreferences     bool
	DataSold            bool
	CSRFToken           string
	PreferencesHeading  string
	EssentialLabel      string
	EssentialDesc       string
	AlwaysOnText        string
	PreferencesLabel    string
	PreferencesDesc     string
	AnalyticsLabel      string
	AnalyticsDesc       string
	SavePreferencesText string
	CloseText           string
}

// consentBannerTmpl is the embedded cookie-consent banner partial
// (AI.md PART 16 — Cookie Consent Banner, HTML markup + Banner styles).
var consentBannerTmpl = mustParseTemplate("consent_banner", "consent_banner.html")

// consentBannerHTML renders the cookie consent banner markup, or an empty
// string when the visitor already has a valid cookie_consent cookie
// (AI.md PART 16 — Cookie Consent Banner, Banner Behavior: "Already set" /
// "First visit").
func (s *Server) consentBannerHTML(w http.ResponseWriter, r *http.Request, lang string) template.HTML {
	if hasConsentCookie(r) {
		return ""
	}
	p := s.config.Privacy
	policyText := p.Consent.Policy.Text
	if policyText == "" {
		policyText = translateKey(lang, "consent.policy_text")
	}
	policyURL := p.Consent.Policy.URL
	if policyURL == "" {
		policyURL = "/server/privacy"
	}
	declineText := p.Consent.Buttons.Decline
	if declineText == "" {
		declineText = translateKey(lang, "consent.decline")
	}
	acceptText := p.Consent.Buttons.Accept
	if acceptText == "" {
		acceptText = translateKey(lang, "consent.accept")
	}
	prefText := p.Consent.PreferencesText
	if prefText == "" {
		prefText = translateKey(lang, "consent.preferences")
	}
	message := p.GetConsentMessage()
	if message == "" {
		message = translateKey(lang, "consent.default_message")
	}
	data := consentBannerData{
		Message:             message,
		PolicyURL:           policyURL,
		PolicyText:          policyText,
		DeclineText:         declineText,
		AcceptText:          acceptText,
		PreferencesText:     prefText,
		ShowPreferences:     p.Consent.ShowPreferences,
		DataSold:            p.Data.Sold,
		CSRFToken:           s.csrfToken(w, r),
		PreferencesHeading:  translateKey(lang, "consent.preferences_heading"),
		EssentialLabel:      translateKey(lang, "consent.essential_label"),
		EssentialDesc:       translateKey(lang, "consent.essential_desc"),
		AlwaysOnText:        translateKey(lang, "consent.always_on"),
		PreferencesLabel:    translateKey(lang, "consent.preferences_label"),
		PreferencesDesc:     translateKey(lang, "consent.preferences_desc"),
		AnalyticsLabel:      translateKey(lang, "consent.analytics_label"),
		AnalyticsDesc:       translateKey(lang, "consent.analytics_desc"),
		SavePreferencesText: translateKey(lang, "consent.save_preferences"),
		CloseText:           translateKey(lang, "common.close"),
	}
	var sb strings.Builder
	if err := consentBannerTmpl.Execute(&sb, data); err != nil {
		return ""
	}
	return template.HTML(sb.String())
}
