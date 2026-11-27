package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apimgr/whois/src/common/constants"
)

func TestOfflineCacheSignalOnlyMarksSharedHTML(t *testing.T) {
	server := newTestServer(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>public</html>"))
	})
	handler := server.offlineCacheSignal(next)

	request := httptest.NewRequest(http.MethodGet, "/server/about", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := response.Header().Get("X-Offline-Cache"); got != "public" {
		t.Fatalf("public HTML signal = %q, want public", got)
	}

	buildCookieRequest := httptest.NewRequest(http.MethodGet, "/server/about", nil)
	buildCookieRequest.AddCookie(&http.Cookie{Name: constants.InternalName + "_build", Value: "build"})
	buildCookieResponse := httptest.NewRecorder()
	handler.ServeHTTP(buildCookieResponse, buildCookieRequest)
	if got := buildCookieResponse.Header().Get("X-Offline-Cache"); got != "public" {
		t.Fatalf("build-cookie HTML signal = %q, want public", got)
	}

	for _, tc := range []struct {
		name   string
		path   string
		method string
		cookie string
	}{
		{name: "homepage form", path: "/", method: http.MethodGet},
		{name: "own form", path: "/server/contact", method: http.MethodGet},
		{name: "CCPA forms", path: "/server/privacy", method: http.MethodGet},
		{name: "owner page", path: "/server/preferences/tokens", method: http.MethodGet},
		{name: "cookie", path: "/server/about", method: http.MethodGet, cookie: "owner_token=secret"},
		{name: "post", path: "/server/about", method: http.MethodPost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.cookie != "" {
				req.Header.Set("Cookie", tc.cookie)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if got := rr.Header().Get("X-Offline-Cache"); got != "" {
				t.Fatalf("ineligible response signal = %q, want empty", got)
			}
		})
	}
}

func TestOfflineCacheSignalRequiresHTML(t *testing.T) {
	server := newTestServer(t)
	handler := server.offlineCacheSignal(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	request := httptest.NewRequest(http.MethodGet, "/server/about", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := response.Header().Get("X-Offline-Cache"); got != "" {
		t.Fatalf("JSON response signal = %q, want empty", got)
	}
}
