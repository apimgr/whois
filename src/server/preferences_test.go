package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestPreferenceExportIsCanonicalAndExcludesConsent(t *testing.T) {
	s := newTestServer(t)
	s.config.I18n.Supported = append(s.config.I18n.Supported, "fr")
	r := httptest.NewRequest(http.MethodGet, "https://example.test/server/preferences/sync", nil)
	r.AddCookie(&http.Cookie{Name: "theme", Value: "light"})
	r.AddCookie(&http.Cookie{Name: "lang", Value: "fr"})
	r.AddCookie(&http.Cookie{Name: "cookie_consent", Value: `%7B%22essential%22:true%2C%22preferences%22:true%7D`})
	fullURL, code := s.preferenceExport(r)
	if !strings.HasSuffix(fullURL, "/server/preferences/sync/import?lang=fr&theme=light") {
		t.Fatalf("export URL contains unexpected preference set/order: %q", fullURL)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil || string(decoded) != "lang=fr&theme=light" {
		t.Fatalf("decode export code = %q, %v", decoded, err)
	}
}

func TestPreferenceAPISaveConsentGateAndImportMerge(t *testing.T) {
	s := newTestServer(t)
	s.config.I18n.Supported = append(s.config.I18n.Supported, "fr")
	handler := s.setupRoutes()

	body := strings.NewReader(`{"theme":"light","lang":"fr","cookie_consent":"bad"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/preferences", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"consent_required": true`) || !strings.Contains(res.Body.String(), `"applied": []`) {
		t.Fatalf("consent gate response = %d %s", res.Code, res.Body.String())
	}

	consent := url.QueryEscape(`{"essential":true,"preferences":true,"analytics":false,"timestamp":1}`)
	importReq := httptest.NewRequest(http.MethodGet, "/api/v1/server/preferences/sync/import?code=theme%3Ddark%26lang%3Den&theme=light&cookie_consent=declined", nil)
	importReq.AddCookie(&http.Cookie{Name: consentCookieName, Value: consent})
	importReq.Header.Set("Accept", "application/json")
	importRes := httptest.NewRecorder()
	handler.ServeHTTP(importRes, importReq)
	if importRes.Code != http.StatusOK || !strings.Contains(importRes.Body.String(), `"theme": "light"`) || !strings.Contains(importRes.Body.String(), `"cookie_consent"`) || !strings.Contains(importRes.Body.String(), `"ignored"`) {
		t.Fatalf("direct preference override not honored safely: %d %s", importRes.Code, importRes.Body.String())
	}
	var result struct {
		Data preferencesSyncResult `json:"data"`
	}
	if err := json.Unmarshal(importRes.Body.Bytes(), &result); err != nil || len(result.Data.Applied) != 2 {
		t.Fatalf("decode import result (%d values): %v; %s", len(result.Data.Applied), err, importRes.Body.String())
	}
}

func TestPreferencesWebSaveAlwaysRedirectsAndResetPreservesCredentials(t *testing.T) {
	s := newTestServer(t)
	r := httptest.NewRequest(http.MethodPost, "/server/preferences", strings.NewReader("theme=invalid&consent_form=1"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})
	r.AddCookie(&http.Cookie{Name: ownerTokenCookieName, Value: "credential"})
	r.AddCookie(&http.Cookie{Name: "notice_dismissed", Value: "yes"})
	w := httptest.NewRecorder()
	s.handlePreferencesSavePage(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("invalid web save status = %d", w.Code)
	}

	reset := httptest.NewRequest(http.MethodPost, "/server/preferences", strings.NewReader("action=reset"))
	reset.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reset.AddCookie(&http.Cookie{Name: ownerTokenCookieName, Value: "credential"})
	reset.AddCookie(&http.Cookie{Name: "notice_dismissed", Value: "yes"})
	resetRes := httptest.NewRecorder()
	s.handlePreferencesSavePage(resetRes, reset)
	if resetRes.Code != http.StatusSeeOther || resetRes.Header().Get("Clear-Site-Data") != `"storage"` {
		t.Fatalf("reset response = %d, Clear-Site-Data=%q", resetRes.Code, resetRes.Header().Get("Clear-Site-Data"))
	}
	for _, cookie := range resetRes.Result().Cookies() {
		if cookie.Name == ownerTokenCookieName {
			t.Fatal("reset cleared owner credential cookie")
		}
	}
}

func TestPreferencesHubRendersRegisteredPagesInOrder(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "https://example.test/server/preferences", nil)
	res := httptest.NewRecorder()
	s.handlePreferencesPage(res, req)
	body := res.Body.String()
	if res.Code != http.StatusOK {
		t.Fatalf("preferences page status = %d", res.Code)
	}
	last := -1
	for _, entry := range s.registeredPages("preferences") {
		if count := strings.Count(body, `href="`+entry.Path+`"`); count != 1 {
			t.Fatalf("registered page %q appears %d times", entry.Path, count)
		}
		position := strings.Index(body, `href="`+entry.Path+`"`)
		if position <= last {
			t.Fatalf("registered page %q is out of order", entry.Path)
		}
		last = position
	}
}
