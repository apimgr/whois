package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNotificationsCSSUsesComponentsStylesheet(t *testing.T) {
	s := newTestServer(t)
	s.config.Notifications.WebUI.Duration = 0
	s.config.Notifications.WebUI.WarningDuration = 9
	handler := s.setupRoutes()

	page := httptest.NewRecorder()
	pageRequest := httptest.NewRequest(http.MethodGet, "/about", nil)
	pageRequest.Header.Set("Accept", "text/html")
	handler.ServeHTTP(page, pageRequest)
	body := page.Body.String()
	commonCSS := strings.Index(body, "/static/css/common.css?")
	componentsCSS := strings.Index(body, "/static/css/components.css?")
	publicCSS := strings.Index(body, "/static/css/public.css?")
	if page.Code != http.StatusOK || commonCSS < 0 || componentsCSS <= commonCSS || publicCSS <= componentsCSS || strings.Contains(body, "notifications.css") {
		t.Fatalf("page stylesheet order = %d/%d/%d", commonCSS, componentsCSS, publicCSS)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/static/css/components.css", nil)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "@layer components") || !strings.Contains(response.Body.String(), "--toast-duration:0s") || !strings.Contains(response.Body.String(), "--toast-duration-warning:9s") {
		t.Fatalf("components CSS response = %d %q", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") == "" || response.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("components CSS cache headers = %#v", response.Header())
	}

	conditional := httptest.NewRequest(http.MethodGet, "/static/css/components.css", nil)
	conditional.Header.Set("If-None-Match", response.Header().Get("ETag"))
	conditionalResponse := httptest.NewRecorder()
	handler.ServeHTTP(conditionalResponse, conditional)
	if conditionalResponse.Code != http.StatusNotModified {
		t.Fatalf("conditional components CSS status = %d, want 304", conditionalResponse.Code)
	}
}

func TestToastScriptUsesConfiguredDurationsWithoutInlineStyles(t *testing.T) {
	s := newTestServer(t)
	handler := s.setupRoutes()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/static/js/app.js", nil))
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "durationSeconds(body.dataset.toastDuration,3)") || !strings.Contains(body, "durationSeconds(body.dataset.toastWarningDuration,5)") {
		t.Fatalf("toast script response = %d; configured duration parsing is missing", response.Code)
	}
	if strings.Contains(body, "container.style.setProperty('--toast-duration'") || strings.Contains(body, "container.style.setProperty('--toast-duration-warning'") {
		t.Fatal("toast script writes configured style inline instead of using the served stylesheet")
	}
}

func TestNotificationsCSSClampsNegativeDurationsToManualDismiss(t *testing.T) {
	s := newTestServer(t)
	s.config.Notifications.WebUI.Duration = -1
	s.config.Notifications.WebUI.WarningDuration = -5
	want := "@layer components{.toast{--toast-duration:0s;--toast-duration-warning:0s}}\n"
	if got := notificationsCSSContent(s); got != want {
		t.Fatalf("negative notification duration CSS = %q, want %q", got, want)
	}
}
