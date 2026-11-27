//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apimgr/whois/src/config"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

func baseURL(t *testing.T) string {
	t.Helper()
	value := strings.TrimRight(os.Getenv("E2E_BASE_URL"), "/")
	if value == "" {
		t.Fatal("E2E_BASE_URL is required")
	}
	return value
}

func TestTier1SSRWHOISAndServerPages(t *testing.T) {
	base := baseURL(t)
	client := &http.Client{Timeout: 10 * time.Second}
	routes := []struct {
		path    string
		content string
	}{
		{"/", "WHOIS lookup"},
		{"/whois", "whois-form"},
		{"/server/about", "About"},
		{"/server/docs", "Documentation"},
		{"/server/contact", "Choose a report type"},
		{"/server/contact?type=abuse", `name="reported_url"`},
		{"/server/contact?type=dmca", `name="copyrighted_work"`},
		{"/server/contact?type=privacy", `name="request_kind"`},
		{"/server/privacy", "Privacy"},
		{"/server/security", "Security"},
		{"/server/security/policy", "Security"},
		{"/server/help", "Help"},
		{"/server/terms", "Terms"},
		{"/server/dpo", "Data Protection"},
		{"/server/healthz", ""},
		{"/server/docs/swagger", "swagger-ui"},
		{"/server/docs/graphql", "gql-form"},
	}
	contactRequest, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/api/v1/server/contact", nil)
	if err != nil {
		t.Fatal(err)
	}
	contactRequest.Header.Set("Accept", "application/json")
	contactResponse, err := client.Do(contactRequest)
	if err != nil {
		t.Fatal(err)
	}
	var contactData struct {
		Data struct {
			SecurityURL string `json:"security_url"`
		} `json:"data"`
	}
	if err := json.NewDecoder(contactResponse.Body).Decode(&contactData); err != nil {
		t.Fatalf("decode contact API response: %v", err)
	}
	if err := contactResponse.Body.Close(); err != nil {
		t.Fatalf("close contact API response: %v", err)
	}
	if contactResponse.StatusCode != http.StatusOK {
		t.Fatalf("contact API status = %d", contactResponse.StatusCode)
	}
	securityURL, err := url.Parse(contactData.Data.SecurityURL)
	if err != nil || securityURL.Query().Get("security_id") == "" {
		t.Fatalf("contact API security URL = %q, err=%v", contactData.Data.SecurityURL, err)
	}
	routes = append(routes, struct {
		path    string
		content string
	}{securityURL.RequestURI(), `name="component"`})
	for _, route := range routes {
		t.Run(route.path, func(t *testing.T) {
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+route.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Accept", "text/html")
			request.Header.Set("User-Agent", "Mozilla/5.0 E2E")
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := response.Body.Close(); err != nil {
					t.Errorf("close %s response: %v", route.path, err)
				}
			}()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", response.StatusCode, body)
			}
			if !strings.Contains(response.Header.Get("Content-Type"), "text/html") {
				t.Fatalf("Content-Type = %q, want HTML", response.Header.Get("Content-Type"))
			}
			html := string(body)
			for _, required := range []string{"<!DOCTYPE html>", "<title>", "lang=", "charset=", "name=\"viewport\"", "<main"} {
				if !strings.Contains(html, required) {
					t.Errorf("SSR response lacks %q", required)
				}
			}
			if route.content != "" && !strings.Contains(html, route.content) {
				t.Errorf("SSR response lacks page content %q", route.content)
			}
		})
	}

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/api/v1/whois/validate/example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close validation response: %v", err)
		}
	}()
	var validation struct {
		OK   bool `json:"ok"`
		Data struct {
			Valid bool   `json:"valid"`
			Type  string `json:"type"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&validation); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !validation.OK || !validation.Data.Valid || validation.Data.Type != "domain" {
		t.Fatalf("domain validation response = %#v, status %d", validation, response.StatusCode)
	}
}

func TestTier1ThemedInternalServerError(t *testing.T) {
	cfg, err := config.LoadServerConfig(os.Getenv("E2E_CONFIG_DIR"))
	if err != nil {
		t.Fatalf("load E2E operator token: %v", err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL(t)+"/debug/error500", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+cfg.ServerToken)
	request.Header.Set("Accept", "text/html")
	request.Header.Set("User-Agent", "Mozilla/5.0 E2E")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close error response: %v", err)
		}
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("debug error status = %d, want 500", response.StatusCode)
	}
	if !strings.Contains(response.Header.Get("Content-Type"), "text/html") || !strings.Contains(string(body), "<main") {
		t.Fatalf("500 response did not render the themed error page")
	}
}

func browserContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	endpoint := strings.TrimRight(os.Getenv("E2E_CDP_URL"), "/")
	if endpoint == "" {
		t.Fatal("E2E_CDP_URL is required")
	}
	var version struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	client := &http.Client{Timeout: 2 * time.Second}
	var connectErr error
	for attempt := 0; attempt < 60; attempt++ {
		response, err := client.Get(endpoint + "/json/version")
		if err == nil {
			connectErr = json.NewDecoder(response.Body).Decode(&version)
			if err := response.Body.Close(); connectErr == nil {
				connectErr = err
			}
			if connectErr == nil && version.WebSocketDebuggerURL != "" {
				break
			}
		} else {
			connectErr = err
		}
		time.Sleep(time.Second)
	}
	if version.WebSocketDebuggerURL == "" {
		t.Fatalf("Chromium did not return a browser WebSocket endpoint: %v", connectErr)
	}
	webSocketURL, err := url.Parse(version.WebSocketDebuggerURL)
	if err != nil {
		t.Fatalf("invalid Chromium WebSocket URL: %v", err)
	}
	httpEndpoint, err := url.Parse(endpoint)
	if err != nil {
		t.Fatalf("invalid Chromium HTTP endpoint: %v", err)
	}
	webSocketURL.Host = httpEndpoint.Host
	ctx, cancel := chromedp.NewRemoteAllocator(t.Context(), webSocketURL.String())
	return ctx, cancel
}

func TestTier2NoJavaScriptWHOISForm(t *testing.T) {
	ctx, cancel := browserContext(t)
	defer cancel()
	ctx, stop := chromedp.NewContext(ctx)
	defer stop()
	var pageText string
	err := chromedp.Run(ctx,
		emulation.SetScriptExecutionDisabled(true),
		chromedp.Navigate(baseURL(t)),
		chromedp.Text("body", &pageText, chromedp.NodeVisible),
		chromedp.WaitVisible(`#whois-form`, chromedp.ByID),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(pageText), "whois lookup") {
		t.Fatalf("no-JavaScript page did not render the WHOIS content: %q", pageText)
	}
}

func TestTier3FullBrowserAssetsThemeAndResponsiveLayout(t *testing.T) {
	ctx, cancel := browserContext(t)
	defer cancel()
	ctx, stop := chromedp.NewContext(ctx)
	defer stop()
	var consoleErrors []string
	var failedRequests []string
	chromedp.ListenTarget(ctx, func(event any) {
		switch value := event.(type) {
		case *runtime.EventExceptionThrown:
			consoleErrors = append(consoleErrors, value.ExceptionDetails.Text)
		case *runtime.EventConsoleAPICalled:
			if value.Type == "error" {
				consoleErrors = append(consoleErrors, fmt.Sprint(value.Args))
			}
		case *network.EventLoadingFailed:
			failedRequests = append(failedRequests, value.ErrorText)
		}
	})
	var initialTheme string
	var nextTheme string
	var pageWidth float64
	var overflowingElements []string
	err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return network.SetCookie("cookie_consent", url.QueryEscape(`{"essential":true,"preferences":true,"analytics":false,"timestamp":1}`)).WithURL(baseURL(t)).Do(ctx)
		}),
		chromedp.Navigate(baseURL(t)),
		chromedp.WaitVisible(`#whois-form`, chromedp.ByID),
		chromedp.Evaluate(`document.documentElement.className`, &initialTheme),
		chromedp.Click(`#theme-toggle`, chromedp.ByID),
		chromedp.WaitVisible(`#whois-form`, chromedp.ByID),
		chromedp.Evaluate(`document.documentElement.className`, &nextTheme),
		chromedp.EmulateViewport(375, 812),
		chromedp.Evaluate(`document.documentElement.scrollWidth`, &pageWidth),
		chromedp.Evaluate(`Array.from(document.querySelectorAll('body *')).filter(el => el.getBoundingClientRect().right > innerWidth + 1).map(el => el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (el.className && typeof el.className === 'string' ? '.' + el.className.trim().replace(/\\s+/g, '.') : '') + ':' + Math.round(el.getBoundingClientRect().right))`, &overflowingElements),
	)
	if err != nil {
		t.Fatal(err)
	}
	if initialTheme == nextTheme {
		t.Errorf("theme control did not change the rendered theme: %q", initialTheme)
	}
	if pageWidth > 375 {
		t.Errorf("375px viewport has horizontal overflow: width %v; elements: %s", pageWidth, strings.Join(overflowingElements, ", "))
	}
	if len(consoleErrors) != 0 {
		t.Errorf("browser console errors: %s", strings.Join(consoleErrors, "; "))
	}
	if len(failedRequests) != 0 {
		t.Errorf("failed browser requests: %s", strings.Join(failedRequests, "; "))
	}
	assertStaticAssetsLoad(t, baseURL(t))
}

func assertStaticAssetsLoad(t *testing.T, base string) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", "text/html")
	request.Header.Set("User-Agent", "Mozilla/5.0 E2E")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close asset index response: %v", err)
		}
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	html := string(body)
	for _, marker := range []string{"href=\"", "src=\""} {
		for rest := html; ; {
			start := strings.Index(rest, marker)
			if start < 0 {
				break
			}
			rest = rest[start+len(marker):]
			end := strings.IndexByte(rest, '"')
			if end < 0 {
				break
			}
			assetPath := rest[:end]
			if strings.HasPrefix(assetPath, "/static/") || assetPath == "/manifest.json" || assetPath == "/sw.js" {
				parsedBase, _ := url.Parse(base)
				assetURL := parsedBase.ResolveReference(&url.URL{Path: assetPath})
				assetResponse, assetErr := http.Get(assetURL.String())
				if assetErr != nil {
					t.Errorf("fetch asset %s: %v", assetPath, assetErr)
				} else {
					if _, err := io.Copy(io.Discard, assetResponse.Body); err != nil {
						t.Errorf("read asset %s: %v", assetPath, err)
					}
					if err := assetResponse.Body.Close(); err != nil {
						t.Errorf("close asset %s: %v", assetPath, err)
					}
					if assetResponse.StatusCode != http.StatusOK {
						t.Errorf("asset %s status = %d, want 200", assetPath, assetResponse.StatusCode)
					}
				}
			}
			rest = rest[end+1:]
		}
	}
	if dir := os.Getenv("E2E_ARTIFACT_DIR"); dir != "" && t.Failed() {
		if err := os.WriteFile(filepath.Join(dir, "home.html"), body, 0600); err != nil {
			t.Errorf("save E2E artifact: %v", err)
		}
	}
}
