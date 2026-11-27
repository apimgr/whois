package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/apimgr/whois/src/common/i18n"
)

const preferencesCookieAge = 31536000

type preferencesPageData struct {
	translatablePageData
	Name              string
	Theme             string
	Language          string
	Languages         []languageOption
	AutomaticLanguage string
	LanguageOverride  bool
	Consent           *consentCookie
	CCPAOptOut        bool
	CCPAApplicable    bool
	ConsentRequired   bool
	PreferencesURL    string
	PreferencesCode   string
	CancelURL         string
	MorePages         []pageRegistryEntry
}

type pageRegistryEntry struct {
	Hub         string
	Path        string
	TitleKey    string
	Description string
	Order       int
	Sitemap     bool
	Enabled     func(*Server) bool
}

var serverPageRegistry = []pageRegistryEntry{
	{Hub: "preferences", Path: "/server/preferences/tokens", TitleKey: "preferences.tokens", Description: "preferences.tokens_help", Order: 1},
	{Hub: "preferences", Path: "/server/preferences/sync", TitleKey: "preferences.sync", Description: "preferences.sync_help", Order: 2},
	{Hub: "help", Path: "/server/help/mcp", TitleKey: "help.mcp_title", Description: "help.mcp_desc", Order: 1, Sitemap: true},
}

func (s *Server) registeredPages(hub string) []pageRegistryEntry {
	pages := make([]pageRegistryEntry, 0)
	for _, page := range serverPageRegistry {
		if page.Hub == hub && (page.Enabled == nil || page.Enabled(s)) {
			pages = append(pages, page)
		}
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i].Order < pages[j].Order })
	return pages
}

type languageOption struct {
	Code       string
	NativeName string
}

type preferencesSyncResult struct {
	Theme           string            `json:"theme"`
	Lang            string            `json:"lang"`
	Prefs           map[string]string `json:"prefs"`
	URL             string            `json:"url,omitempty"`
	Code            string            `json:"code,omitempty"`
	Applied         []string          `json:"applied"`
	Ignored         []string          `json:"ignored"`
	ConsentRequired bool              `json:"consent_required,omitempty"`
	ValidCount      int               `json:"-"`
}

var preferencesTemplate = mustParseTemplate("preferences", "page/preferences.tmpl")
var preferencesSyncTemplate = mustParseTemplate("preferences_sync", "page/preferences_sync.tmpl")

func (s *Server) currentPreferences(r *http.Request) (string, string, map[string]string) {
	theme := "dark"
	if cookie, err := r.Cookie("theme"); err == nil && (cookie.Value == "dark" || cookie.Value == "light" || cookie.Value == "auto") {
		theme = cookie.Value
	}
	lang := LangFromContext(r.Context())
	if cookie, err := r.Cookie("lang"); err == nil {
		if canonical := s.canonicalPreferenceLanguage(cookie.Value); canonical != "" {
			lang = canonical
		}
	}
	return theme, lang, map[string]string{}
}

func (s *Server) canonicalPreferenceLanguage(value string) string {
	for _, supported := range s.config.I18n.Supported {
		if i18n.IsSupported(supported) && strings.EqualFold(value, supported) {
			return supported
		}
	}
	base := strings.Split(strings.ReplaceAll(value, "_", "-"), "-")[0]
	for _, supported := range s.config.I18n.Supported {
		if i18n.IsSupported(supported) && strings.EqualFold(base, supported) {
			return supported
		}
	}
	return ""
}

func (s *Server) preferenceCookieSecure(r *http.Request) bool {
	proto, _, _ := s.GetURLVars(r)
	return proto == "https"
}

func (s *Server) setPreferenceCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: preferencesCookieAge,
		Secure: s.preferenceCookieSecure(r), HttpOnly: false, SameSite: http.SameSiteLaxMode})
}

func (s *Server) handlePreferencesPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handlePreferencesSavePage(w, r)
		return
	}
	theme, lang, _ := s.currentPreferences(r)
	consent := getConsentFromRequest(r)
	if consent == nil {
		consent = &consentCookie{Essential: true}
	}
	ccpa, _ := r.Cookie("ccpa_opt_out")
	data := preferencesPageData{translatablePageData: s.newPageData(w, r), Name: s.brandName(), Theme: theme, Language: lang,
		Languages: s.preferenceLanguageOptions(), AutomaticLanguage: i18n.TranslateFormat(LangFromContext(r.Context()), "preferences.automatic", map[string]string{"language": s.nativeLanguageName(lang)}),
		LanguageOverride: s.preferenceLanguageCookiePresent(r), Consent: consent, CCPAOptOut: ccpa != nil && ccpa.Value == "true",
		CCPAApplicable: s.config.Privacy.Data.Sold, ConsentRequired: r.URL.Query().Get("consent_required") == "1",
		CancelURL: s.BuildURL(r, preferenceRedirectTarget(s, r, r.URL.Query().Get("redirect"), "/"))}
	data.MorePages = s.registeredPages("preferences")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := preferencesTemplate.ExecuteTemplate(w, "public.tmpl", data); err != nil {
		return
	}
}

func (s *Server) handlePreferencesSavePage(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.preferencesRedirect(w, r, "/")
		return
	}
	if r.FormValue("action") == "theme_toggle" {
		redirect := preferenceRedirectTarget(s, r, r.FormValue("redirect"), "/")
		if preferenceConsentGranted(r) {
			theme, _, _ := s.currentPreferences(r)
			next := map[string]string{"dark": "light", "light": "auto", "auto": "dark"}[theme]
			s.setPreferenceCookie(w, r, "theme", next)
		} else {
			redirect = appendQueryValue(redirect, "consent_required", "1")
		}
		s.preferencesRedirect(w, r, redirect)
		return
	}
	if r.FormValue("action") == "reset" {
		csrfCookieName := s.config.CSRF.CookieName
		if csrfCookieName == "" {
			csrfCookieName = "csrf_token"
		}
		for _, cookie := range r.Cookies() {
			if strings.HasPrefix(cookie.Name, "csrf_") || cookie.Name == csrfCookieName || cookie.Name == ownerTokenCookieName || cookie.Name == "session" {
				continue
			}
			path, httpOnly, sameSite := "/", false, http.SameSiteLaxMode
			if cookie.Name == "caswhois_token_view" {
				path, httpOnly, sameSite = "/server/preferences/tokens", true, http.SameSiteStrictMode
			}
			http.SetCookie(w, &http.Cookie{Name: cookie.Name, Value: "", Path: path, MaxAge: -1, HttpOnly: httpOnly,
				Secure: s.preferenceCookieSecure(r), SameSite: sameSite})
		}
		http.SetCookie(w, &http.Cookie{Name: "caswhois_token_view", Value: "", Path: "/server/preferences/tokens", MaxAge: -1,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		w.Header().Set("Clear-Site-Data", `"storage"`)
		redirect := preferenceRedirectTarget(s, r, r.FormValue("redirect"), "/")
		s.preferencesRedirect(w, r, redirect)
		return
	}
	values := url.Values{}
	for key, entries := range r.Form {
		if len(entries) > 0 {
			values.Set(key, entries[len(entries)-1])
		}
	}
	if r.FormValue("consent_form") == "1" {
		previousConsent := getConsentFromRequest(r)
		consent := consentCookie{Essential: true, Preferences: r.FormValue("consent_preferences") == "on",
			Analytics: r.FormValue("consent_analytics") == "on", Timestamp: time.Now().Unix()}
		s.writeConsentCookie(w, r, consent)
		if previousConsent != nil && previousConsent.Preferences && !consent.Preferences {
			for _, cookie := range r.Cookies() {
				if cookie.Name == "theme" || cookie.Name == "lang" || strings.HasPrefix(cookie.Name, "caswhois_pref_") {
					http.SetCookie(w, &http.Cookie{Name: cookie.Name, Value: "", Path: "/", MaxAge: -1,
						Secure: s.preferenceCookieSecure(r), SameSite: http.SameSiteLaxMode})
				}
			}
			w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
		}
		if previousConsent != nil && previousConsent.Analytics && !consent.Analytics {
			w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
		}
		if s.config.Privacy.Data.Sold {
			if r.FormValue("ccpa_opt_out") == "on" {
				s.setPreferenceCookie(w, r, "ccpa_opt_out", "true")
			} else {
				http.SetCookie(w, &http.Cookie{Name: "ccpa_opt_out", Value: "", Path: "/", MaxAge: -1, Secure: s.preferenceCookieSecure(r), SameSite: http.SameSiteLaxMode})
			}
		}
	}
	if r.FormValue("lang") == "auto" && preferenceConsentGranted(r) {
		http.SetCookie(w, &http.Cookie{Name: "lang", Value: "", Path: "/", MaxAge: -1, Secure: s.preferenceCookieSecure(r), SameSite: http.SameSiteLaxMode})
		values.Del("lang")
	}
	result := s.applyPreferenceValues(w, r, values)
	redirect := preferenceRedirectTarget(s, r, r.FormValue("redirect"), "/")
	if result.ConsentRequired {
		redirect = appendQueryValue(redirect, "consent_required", "1")
	}
	s.preferencesRedirect(w, r, redirect)
}

func (s *Server) preferenceLanguageCookiePresent(r *http.Request) bool {
	cookie, err := r.Cookie("lang")
	return err == nil && s.canonicalPreferenceLanguage(cookie.Value) != ""
}

func (s *Server) preferenceLanguageOptions() []languageOption {
	options := make([]languageOption, 0, len(s.config.I18n.Supported))
	for _, code := range s.config.I18n.Supported {
		options = append(options, languageOption{Code: code, NativeName: s.nativeLanguageName(code)})
	}
	return options
}

func (s *Server) nativeLanguageName(code string) string {
	return localeNativeLanguageName(code)
}

func localeNativeLanguageName(code string) string {
	locale, ok := i18n.LocaleFor(code)
	if !ok || locale.NativeName == "" {
		return code
	}
	return locale.NativeName
}

func (s *Server) handlePreferencesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		theme, lang, prefs := s.currentPreferences(r)
		SendSuccess(w, map[string]any{"theme": theme, "lang": lang, "prefs": prefs})
		return
	}
	values, err := readPreferenceRequest(w, r)
	if err != nil {
		SendError(w, ErrBadRequest, "Invalid preference request")
		return
	}
	result := s.applyPreferenceValues(w, r, values)
	if result.ValidCount == 0 {
		SendError(w, ErrValidationFailed, "At least one valid preference is required")
		return
	}
	SendSuccess(w, result)
}

func readPreferenceRequest(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		defer func() { _ = r.Body.Close() }()
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
		var payload map[string]json.RawMessage
		if err := decoder.Decode(&payload); err != nil {
			return nil, err
		}
		values := url.Values{}
		for key, raw := range payload {
			if key == "prefs" {
				var prefs map[string]string
				if err := json.Unmarshal(raw, &prefs); err != nil {
					continue
				}
				for pref, value := range prefs {
					values.Set("caswhois_pref_"+pref, value)
				}
				continue
			}
			var value string
			if json.Unmarshal(raw, &value) == nil {
				values.Set(key, value)
			} else {
				values.Set(key, string(raw))
			}
		}
		return values, nil
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return r.Form, nil
}

func (s *Server) applyPreferenceValues(w http.ResponseWriter, r *http.Request, values url.Values) preferencesSyncResult {
	valid := map[string]string{}
	ignored := make([]string, 0)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for index, key := range keys {
		entries := values[key]
		if index >= 32 {
			ignored = append(ignored, key)
			continue
		}
		if isPreferenceControlField(key) {
			continue
		}
		if len(entries) == 0 || len(entries[len(entries)-1]) > 64 {
			ignored = append(ignored, key)
			continue
		}
		value := entries[len(entries)-1]
		switch key {
		case "theme":
			if value == "dark" || value == "light" || value == "auto" {
				valid[key] = value
			} else {
				ignored = append(ignored, key)
			}
		case "lang":
			if lang := s.canonicalPreferenceLanguage(value); lang != "" {
				valid[key] = lang
			} else {
				ignored = append(ignored, key)
			}
		default:
			ignored = append(ignored, key)
		}
	}
	sort.Strings(ignored)
	consentRequired := len(valid) > 0 && !preferenceConsentGranted(r)
	result := preferencesSyncResult{Applied: []string{}, Ignored: ignored, ConsentRequired: consentRequired}
	result.ValidCount = len(valid)
	if consentRequired {
		for key := range valid {
			result.Ignored = append(result.Ignored, key)
		}
		sort.Strings(result.Ignored)
	} else {
		for key, value := range valid {
			s.setPreferenceCookie(w, r, key, value)
			result.Applied = append(result.Applied, key)
		}
		sort.Strings(result.Applied)
	}
	result.Theme, result.Lang, result.Prefs = s.currentPreferences(r)
	if value, ok := valid["theme"]; ok && !consentRequired {
		result.Theme = value
	}
	if value, ok := valid["lang"]; ok && !consentRequired {
		result.Lang = value
	}
	return result
}

func isPreferenceControlField(key string) bool {
	switch key {
	case "csrf_token", "code", "redirect", "action", "consent_form", "consent_preferences", "consent_analytics", "ccpa_opt_out", "confirm":
		return true
	default:
		return false
	}
}

func preferenceConsentGranted(r *http.Request) bool {
	if r.Method == http.MethodPost && r.FormValue("consent_form") == "1" {
		return r.FormValue("consent_preferences") == "on"
	}
	consent := getConsentFromRequest(r)
	return consent != nil && consent.Preferences
}

func (s *Server) handlePreferencesSyncAPI(w http.ResponseWriter, r *http.Request) {
	theme, lang, prefs := s.currentPreferences(r)
	fullURL, code := s.preferenceExport(r)
	SendSuccess(w, map[string]any{"theme": theme, "lang": lang, "prefs": prefs, "url": fullURL, "code": code})
}

func (s *Server) preferenceExport(r *http.Request) (string, string) {
	theme, lang, prefs := s.currentPreferences(r)
	values := url.Values{"theme": {theme}, "lang": {lang}}
	for key, value := range prefs {
		values.Set("caswhois_pref_"+key, value)
	}
	query := values.Encode()
	code := base64.RawURLEncoding.EncodeToString([]byte(query))
	return s.BuildURL(r, "/server/preferences/sync/import") + "?" + query, code
}

func (s *Server) handlePreferencesSyncPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		values := mergePreferenceImport(r.Form, r.FormValue("code"))
		result := s.applyPreferenceValues(w, r, values)
		redirect := preferenceRedirectTarget(s, r, r.FormValue("redirect"), "/server/preferences/sync")
		if result.ConsentRequired {
			redirect = appendQueryValue(redirect, "consent_required", "1")
		}
		s.preferencesRedirect(w, r, redirect)
		return
	}
	fullURL, code := s.preferenceExport(r)
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/plain") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "URL: %s\nCode: %s\n", fullURL, code)
		return
	}
	if strings.Contains(accept, "application/json") {
		theme, lang, prefs := s.currentPreferences(r)
		SendSuccess(w, map[string]any{"theme": theme, "lang": lang, "prefs": prefs, "url": fullURL, "code": code})
		return
	}
	theme, lang, _ := s.currentPreferences(r)
	data := preferencesPageData{translatablePageData: s.newPageData(w, r), Name: s.brandName(), Theme: theme, Language: lang,
		PreferencesURL: fullURL, PreferencesCode: code, ConsentRequired: r.URL.Query().Get("consent_required") == "1"}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = preferencesSyncTemplate.ExecuteTemplate(w, "public.tmpl", data)
}

func (s *Server) handlePreferencesSyncImportPage(w http.ResponseWriter, r *http.Request) {
	values := mergePreferenceImport(r.URL.Query(), r.URL.Query().Get("code"))
	result := s.applyPreferenceValues(w, r, values)
	redirect := preferenceRedirectTarget(s, r, r.URL.Query().Get("redirect"), "/")
	if result.ConsentRequired {
		redirect = appendQueryValue(redirect, "consent_required", "1")
	}
	s.preferencesRedirect(w, r, redirect)
}

func (s *Server) handlePreferencesSyncImportAPI(w http.ResponseWriter, r *http.Request) {
	values := mergePreferenceImport(r.URL.Query(), r.URL.Query().Get("code"))
	result := s.applyPreferenceValues(w, r, values)
	SendSuccess(w, result)
}

func mergePreferenceImport(direct url.Values, code string) url.Values {
	decoded := url.Values{}
	trimmed := strings.TrimSpace(code)
	if len(trimmed) <= 2048 && trimmed != "" {
		payload := trimmed
		if at := strings.Index(payload, "?"); at >= 0 {
			payload = payload[at+1:]
		}
		withoutPadding := strings.TrimRight(payload, "=")
		if strings.Contains(withoutPadding, "=") {
			if parsed, err := url.ParseQuery(payload); err == nil {
				decoded = parsed
			}
		} else if raw, err := base64.RawURLEncoding.DecodeString(payload); err == nil {
			if parsed, parseErr := url.ParseQuery(string(raw)); parseErr == nil {
				decoded = parsed
			}
		} else if raw, err := base64.URLEncoding.DecodeString(payload); err == nil {
			if parsed, parseErr := url.ParseQuery(string(raw)); parseErr == nil {
				decoded = parsed
			}
		}
	}
	merged := url.Values{}
	for key, vals := range decoded {
		merged[key] = append([]string(nil), vals...)
	}
	for key, vals := range direct {
		if key == "code" || isPreferenceControlField(key) {
			continue
		}
		merged[key] = append([]string(nil), vals...)
	}
	mergedKeys := make([]string, 0, len(merged))
	for key := range merged {
		mergedKeys = append(mergedKeys, key)
	}
	sort.Strings(mergedKeys)
	for index, key := range mergedKeys {
		if index >= 32 {
			delete(merged, key)
		}
	}
	return merged
}

func preferenceRedirectTarget(s *Server, r *http.Request, candidate, fallback string) string {
	if safePreferenceRedirect(candidate) && !preferencesRoute(candidate) {
		return candidate
	}
	if referer := r.Referer(); referer != "" {
		if parsed, err := url.Parse(referer); err == nil {
			proto, host, port := s.GetURLVars(r)
			originHost := host
			if port != "" {
				originHost += ":" + port
			}
			path := parsed.EscapedPath()
			if path == "" {
				path = "/"
			}
			if parsed.Scheme == proto && strings.EqualFold(parsed.Host, originHost) && safePreferenceRedirect(path+queryString(parsed.RawQuery)) && !preferencesRoute(path) {
				return path + queryString(parsed.RawQuery)
			}
		}
	}
	return fallback
}

func safePreferenceRedirect(value string) bool {
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.HasPrefix(value, "/\\") || strings.ContainsAny(value, "\r\n") {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "" && parsed.Host == ""
}

func preferencesRoute(value string) bool {
	path := strings.SplitN(value, "?", 2)[0]
	return path == "/server/preferences" || path == "/server/preferences/sync" || path == "/server/preferences/sync/import"
}

func queryString(value string) string {
	if value == "" {
		return ""
	}
	return "?" + value
}

func appendQueryValue(path, key, value string) string {
	parsed, err := url.Parse(path)
	if err != nil {
		return path
	}
	query := parsed.Query()
	query.Set(key, value)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (s *Server) preferencesRedirect(w http.ResponseWriter, r *http.Request, path string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", s.BuildURL(r, path))
	w.WriteHeader(http.StatusSeeOther)
}
