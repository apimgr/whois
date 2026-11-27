package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccentStylesheetValidatesAndMaintainsContrast(t *testing.T) {
	for _, value := range []string{"#bd93f9", "#0969da", "#00FF00"} {
		if !accentStylesheetURL(value) {
			t.Errorf("accentStylesheetURL(%q) = false", value)
		}
	}
	for _, value := range []string{"", "0969da", "#fff", "#gggggg", "red", "##123456"} {
		if accentStylesheetURL(value) {
			t.Errorf("accentStylesheetURL(%q) = true", value)
		}
	}

	base, ok := parseHexColor("#0969da")
	if !ok {
		t.Fatal("failed to parse test accent")
	}
	dark := accentWithContrast(base, rgbColor{40.0 / 255, 42.0 / 255, 54.0 / 255}, true)
	light := accentWithContrast(base, rgbColor{1, 1, 1}, false)
	if got := contrastRatio(dark, rgbColor{40.0 / 255, 42.0 / 255, 54.0 / 255}); got < 4.5 {
		t.Errorf("dark accent contrast = %.2f, want at least 4.5", got)
	}
	if got := contrastRatio(light, rgbColor{1, 1, 1}); got < 4.5 {
		t.Errorf("light accent contrast = %.2f, want at least 4.5", got)
	}
}

func TestAccentCSSHandlerAndPageLink(t *testing.T) {
	s := newTestServer(t)
	s.config.Web.UI.Accent = "#0969da"
	handler := s.setupRoutes()
	page := httptest.NewRecorder()
	pageRequest := httptest.NewRequest(http.MethodGet, "/about", nil)
	pageRequest.Header.Set("Accept", "text/html")
	handler.ServeHTTP(page, pageRequest)
	pageBody := page.Body.String()
	publicCSS := strings.Index(pageBody, "/static/css/public.css?")
	accentCSS := strings.Index(pageBody, "/static/css/accent.css?")
	if page.Code != http.StatusOK || publicCSS < 0 || accentCSS <= publicCSS {
		t.Fatalf("page status/order = %d/%d/%d", page.Code, publicCSS, accentCSS)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/static/css/accent.css", nil)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "--color-primary:") || !strings.Contains(response.Body.String(), "html.theme-light") {
		t.Fatalf("accent CSS response = %d %q", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") == "" || response.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("accent CSS cache headers = %#v", response.Header())
	}

	conditional := httptest.NewRequest(http.MethodGet, "/static/css/accent.css", nil)
	conditional.Header.Set("If-None-Match", response.Header().Get("ETag"))
	conditionalResponse := httptest.NewRecorder()
	handler.ServeHTTP(conditionalResponse, conditional)
	if conditionalResponse.Code != http.StatusNotModified {
		t.Fatalf("conditional accent CSS status = %d, want 304", conditionalResponse.Code)
	}
}

func TestAccentCSSHandlerOmitsInvalidConfiguration(t *testing.T) {
	s := newTestServer(t)
	s.config.Web.UI.Accent = "not-a-color"
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/static/css/accent.css", nil)
	s.handleAccentCSS(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("invalid accent CSS status = %d, want 404", response.Code)
	}
}
