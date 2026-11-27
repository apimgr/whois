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

func TestAccentTokensUseCommonStylesheet(t *testing.T) {
	s := newTestServer(t)
	s.config.Web.UI.Accent = "#0969da"
	handler := s.setupRoutes()
	page := httptest.NewRecorder()
	pageRequest := httptest.NewRequest(http.MethodGet, "/about", nil)
	pageRequest.Header.Set("Accept", "text/html")
	handler.ServeHTTP(page, pageRequest)
	pageBody := page.Body.String()
	commonCSS := strings.Index(pageBody, "/static/css/common.css?")
	componentsCSS := strings.Index(pageBody, "/static/css/components.css?")
	publicCSS := strings.Index(pageBody, "/static/css/public.css?")
	if page.Code != http.StatusOK || commonCSS < 0 || componentsCSS <= commonCSS || publicCSS <= componentsCSS || strings.Contains(pageBody, "accent.css") || strings.Contains(pageBody, "notifications.css") {
		t.Fatalf("page stylesheet links/order are invalid: %d/%d/%d", commonCSS, componentsCSS, publicCSS)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/static/css/common.css", nil)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "@layer tokens") || !strings.Contains(response.Body.String(), "--color-primary:") || !strings.Contains(response.Body.String(), "html.theme-light") {
		t.Fatalf("common CSS accent tokens = %d %q", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") == "" || response.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("accent CSS cache headers = %#v", response.Header())
	}

	conditional := httptest.NewRequest(http.MethodGet, "/static/css/common.css", nil)
	conditional.Header.Set("If-None-Match", response.Header().Get("ETag"))
	conditionalResponse := httptest.NewRecorder()
	handler.ServeHTTP(conditionalResponse, conditional)
	if conditionalResponse.Code != http.StatusNotModified {
		t.Fatalf("conditional accent CSS status = %d, want 304", conditionalResponse.Code)
	}
}

func TestAccentTokensIgnoreInvalidConfiguration(t *testing.T) {
	if got := accentTokenCSS("not-a-color"); got != "" {
		t.Fatalf("invalid accent tokens = %q", got)
	}
}
