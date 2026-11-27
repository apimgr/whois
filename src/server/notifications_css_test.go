package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNotificationsCSSUsesConfiguredDurationsAndPageLink(t *testing.T) {
	s := newTestServer(t)
	s.config.Notifications.WebUI.Duration = 0
	s.config.Notifications.WebUI.WarningDuration = 9
	handler := s.setupRoutes()

	page := httptest.NewRecorder()
	pageRequest := httptest.NewRequest(http.MethodGet, "/about", nil)
	pageRequest.Header.Set("Accept", "text/html")
	handler.ServeHTTP(page, pageRequest)
	body := page.Body.String()
	publicCSS := strings.Index(body, "/static/css/public.css?")
	notificationsCSS := strings.Index(body, "/static/css/notifications.css?")
	if page.Code != http.StatusOK || publicCSS < 0 || notificationsCSS <= publicCSS {
		t.Fatalf("page status/order = %d/%d/%d", page.Code, publicCSS, notificationsCSS)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/static/css/notifications.css", nil)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "--toast-duration:0s") || !strings.Contains(response.Body.String(), "--toast-duration-warning:9s") {
		t.Fatalf("notifications CSS response = %d %q", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") == "" || response.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("notifications CSS cache headers = %#v", response.Header())
	}

	conditional := httptest.NewRequest(http.MethodGet, "/static/css/notifications.css", nil)
	conditional.Header.Set("If-None-Match", response.Header().Get("ETag"))
	conditionalResponse := httptest.NewRecorder()
	handler.ServeHTTP(conditionalResponse, conditional)
	if conditionalResponse.Code != http.StatusNotModified {
		t.Fatalf("conditional notifications CSS status = %d, want 304", conditionalResponse.Code)
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
	response := httptest.NewRecorder()
	s.handleNotificationsCSS(response, httptest.NewRequest(http.MethodGet, "/static/css/notifications.css", nil))
	if response.Code != http.StatusOK || response.Body.String() != ":root{--toast-duration:0s;--toast-duration-warning:0s}\n" {
		t.Fatalf("negative notification durations response = %d %q", response.Code, response.Body.String())
	}
}
