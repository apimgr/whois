//go:build e2e

package e2e

import (
	"crypto/tls"
	"crypto/x509"
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
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/security"
	"github.com/chromedp/chromedp"
)

func baseURL(t *testing.T) string {
	t.Helper()
	value := strings.TrimRight(os.Getenv("E2E_BASE_URL"), "/")
	if value == "" {
		t.Fatal("E2E_BASE_URL is required")
	}
	if strings.HasPrefix(value, "https://") {
		caPath := os.Getenv("E2E_TLS_CA")
		pem, err := os.ReadFile(caPath)
		if err != nil {
			t.Fatalf("read E2E TLS CA: %v", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			t.Fatal("E2E TLS CA file contains no usable certificate")
		}
		transport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			t.Fatal("default HTTP transport is not configurable")
		}
		clone := transport.Clone()
		clone.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		http.DefaultTransport = clone
	}
	return value
}

func browserBaseURL(t *testing.T) string {
	t.Helper()
	value := strings.TrimRight(os.Getenv("E2E_BROWSER_BASE_URL"), "/")
	if value == "" {
		t.Fatal("E2E_BROWSER_BASE_URL is required")
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
	fixtureRequest, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/whois?q=fixture.example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	fixtureRequest.Header.Set("Accept", "text/html")
	fixtureResponse, err := client.Do(fixtureRequest)
	if err != nil {
		t.Fatal(err)
	}
	fixtureHTML, err := io.ReadAll(fixtureResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixtureResponse.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if fixtureResponse.StatusCode != http.StatusOK {
		t.Fatalf("fixture WHOIS page status = %d", fixtureResponse.StatusCode)
	}
	for _, value := range []string{"fixture.example.test", "Fixture Test Registrar", "ns1.fixture.example.test"} {
		if !strings.Contains(string(fixtureHTML), value) {
			t.Errorf("SSR WHOIS fixture page omits %q", value)
		}
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
	token, err := config.ReadOperatorToken(os.Getenv("E2E_CONFIG_DIR"))
	if err != nil {
		t.Fatalf("load E2E operator token: %v", err)
	}
	if token == "" {
		t.Fatal("E2E operator token is empty")
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL(t)+"/debug/error500", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
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

func clickNativeSubmit(ctx context.Context, selector string) error {
	root, err := dom.GetDocument().WithDepth(-1).Do(ctx)
	if err != nil {
		return err
	}
	node, err := dom.QuerySelector(root.NodeID, selector).Do(ctx)
	if err != nil {
		return err
	}
	if node == 0 {
		return fmt.Errorf("native submit control %q is missing", selector)
	}
	box, err := dom.GetBoxModel().WithNodeID(node).Do(ctx)
	if err != nil {
		return err
	}
	if len(box.Content) < 8 {
		return fmt.Errorf("native submit control %q has no content box", selector)
	}
	x := (box.Content[0] + box.Content[2] + box.Content[4] + box.Content[6]) / 4
	y := (box.Content[1] + box.Content[3] + box.Content[5] + box.Content[7]) / 4
	if err := input.DispatchMouseEvent(input.MouseMoved, x, y).Do(ctx); err != nil {
		return err
	}
	if err := input.DispatchMouseEvent(input.MousePressed, x, y).WithButton(input.Left).WithClickCount(1).Do(ctx); err != nil {
		return err
	}
	return input.DispatchMouseEvent(input.MouseReleased, x, y).WithButton(input.Left).WithClickCount(1).Do(ctx)
}

func TestTier2NoJavaScriptWHOISForm(t *testing.T) {
	ctx, cancel := browserContext(t)
	defer cancel()
	ctx, stop := chromedp.NewContext(ctx)
	defer stop()
	ctx, runCancel := context.WithTimeout(ctx, 45*time.Second)
	defer runCancel()
	err := chromedp.Run(ctx,
		network.Enable(),
		security.SetIgnoreCertificateErrors(true),
		emulation.SetScriptExecutionDisabled(true),
		chromedp.Navigate(browserBaseURL(t)),
		chromedp.WaitReady(`#q`, chromedp.ByID),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var lastErr error
			for attempt := 0; attempt < 20; attempt++ {
				root, err := dom.GetDocument().WithDepth(-1).Do(ctx)
				if err == nil {
					var documentHTML string
					documentHTML, err = dom.GetOuterHTML().WithNodeID(root.NodeID).Do(ctx)
					if err == nil {
						for _, expected := range []string{`id="whois-form"`, `action="/whois"`, `method="GET"`, `name="q"`, `type="submit"`} {
							if !strings.Contains(documentHTML, expected) {
								return fmt.Errorf("no-JavaScript WHOIS form omits %s", expected)
							}
						}
						return nil
					}
				}
				lastErr = err
				time.Sleep(50 * time.Millisecond)
			}
			return fmt.Errorf("read no-JavaScript form DOM: %w", lastErr)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		root, err := dom.GetDocument().WithDepth(-1).Do(ctx)
		if err != nil {
			return err
		}
		field, err := dom.QuerySelector(root.NodeID, "#q").Do(ctx)
		if err != nil {
			return err
		}
		if field == 0 {
			return fmt.Errorf("WHOIS query field is missing")
		}
		if err := dom.Focus().WithNodeID(field).Do(ctx); err != nil {
			return err
		}
		if err := input.InsertText("fixture.example.test").Do(ctx); err != nil {
			return err
		}
		button, err := dom.QuerySelector(root.NodeID, `#whois-form button[type="submit"]`).Do(ctx)
		if err != nil {
			return err
		}
		if button == 0 {
			return fmt.Errorf("WHOIS submit button is missing")
		}
		box, err := dom.GetBoxModel().WithNodeID(button).Do(ctx)
		if err != nil {
			return err
		}
		if len(box.Content) < 8 {
			return fmt.Errorf("WHOIS submit button has no content box")
		}
		x := (box.Content[0] + box.Content[2] + box.Content[4] + box.Content[6]) / 4
		y := (box.Content[1] + box.Content[3] + box.Content[5] + box.Content[7]) / 4
		if err := input.DispatchMouseEvent(input.MouseMoved, x, y).Do(ctx); err != nil {
			return err
		}
		if err := input.DispatchMouseEvent(input.MousePressed, x, y).WithButton(input.Left).WithClickCount(1).Do(ctx); err != nil {
			return err
		}
		return input.DispatchMouseEvent(input.MouseReleased, x, y).WithButton(input.Left).WithClickCount(1).Do(ctx)
	})); err != nil {
		t.Fatalf("submit WHOIS query without JavaScript: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	var resultHTML string
	for time.Now().Before(deadline) {
		var frameTree *page.FrameTree
		var frameErr error
		if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
			frameTree, frameErr = page.GetFrameTree().Do(ctx)
			return frameErr
		})); err != nil {
			t.Fatalf("wait for no-JavaScript form navigation: %v", err)
		}
		if frameTree.Frame.URL != "" && strings.Contains(frameTree.Frame.URL, "/whois?q=fixture.example.test") {
			_ = chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
				root, err := dom.GetDocument().WithDepth(-1).Do(ctx)
				if err != nil {
					return err
				}
				resultHTML, err = dom.GetOuterHTML().WithNodeID(root.NodeID).Do(ctx)
				return err
			}))
			if strings.Contains(resultHTML, "Fixture Test Registrar") {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(resultHTML, "Fixture Test Registrar") {
		t.Fatalf("no-JavaScript WHOIS form did not render fixture result; current URL/result: %q / %q", func() string {
			var tree *page.FrameTree
			_ = chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
				var err error
				tree, err = page.GetFrameTree().Do(ctx)
				return err
			}))
			if tree == nil {
				return "unavailable"
			}
			return tree.Frame.URL
		}(), resultHTML)
	}
	for _, value := range []string{"fixture.example.test", "Fixture Test Registrar", "ns1.fixture.example.test"} {
		if !strings.Contains(resultHTML, value) {
			t.Errorf("no-JavaScript WHOIS result omits %q", value)
		}
	}
	tokensURL := browserBaseURL(t) + "/server/preferences/tokens"
	if err := chromedp.Run(ctx, chromedp.Navigate(tokensURL), chromedp.WaitReady(`#owner-token`, chromedp.ByID)); err != nil {
		t.Fatalf("open no-JavaScript owner-token page: %v", err)
	}
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		return clickNativeSubmit(ctx, `form[action="/server/preferences/token/create"] button[type="submit"]`)
	})); err != nil {
		t.Fatalf("issue owner token through the no-JavaScript form: %v", err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitReady(`#primary-heading`, chromedp.ByID)); err != nil {
		t.Fatalf("wait for no-JavaScript token issue redirect: %v", err)
	}
	var cookies []*network.Cookie
	err = chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		cookies, err = network.GetCookies().WithURLs([]string{tokensURL}).Do(ctx)
		return err
	}))
	if err != nil {
		t.Fatalf("read owner cookies after no-JavaScript issue: %v", err)
	}
	var ownerCookie *network.Cookie
	for _, cookie := range cookies {
		if strings.HasPrefix(cookie.Name, "caswhois_owner_token_") {
			ownerCookie = cookie
			break
		}
	}
	if ownerCookie == nil || !ownerCookie.HTTPOnly || ownerCookie.SameSite != network.CookieSameSiteStrict || !strings.HasPrefix(ownerCookie.Value, "own_") {
		t.Fatal("no-JavaScript token issue did not set the expected HttpOnly, SameSite=Strict owner cookie")
	}
	var tokenPage string
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		root, err := dom.GetDocument().WithDepth(-1).Do(ctx)
		if err != nil {
			return err
		}
		tokenPage, err = dom.GetOuterHTML().WithNodeID(root.NodeID).Do(ctx)
		return err
	})); err != nil {
		t.Fatalf("read issued token page: %v", err)
	}
	if !strings.Contains(tokenPage, ownerCookie.Value) {
		t.Fatal("no-JavaScript issue redirect did not display the token once")
	}
	if err := chromedp.Run(ctx, chromedp.Navigate(tokensURL), chromedp.WaitReady(`#primary-heading`, chromedp.ByID)); err != nil {
		t.Fatalf("reload owner-token page: %v", err)
	}
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		root, err := dom.GetDocument().WithDepth(-1).Do(ctx)
		if err != nil {
			return err
		}
		tokenPage, err = dom.GetOuterHTML().WithNodeID(root.NodeID).Do(ctx)
		return err
	})); err != nil {
		t.Fatalf("read masked owner-token page: %v", err)
	}
	if strings.Contains(tokenPage, ownerCookie.Value) || !strings.Contains(tokenPage, ownerCookie.Value[len(ownerCookie.Value)-4:]) {
		t.Fatal("owner-token page did not mask the token after its one-time issue display")
	}
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		return clickNativeSubmit(ctx, `form[action="/server/preferences/token/reveal"] button[type="submit"]`)
	})); err != nil {
		t.Fatalf("reveal owner token without JavaScript: %v", err)
	}
	if err := chromedp.Run(ctx, chromedp.WaitReady(`#primary-heading`, chromedp.ByID)); err != nil {
		t.Fatalf("wait for no-JavaScript token reveal: %v", err)
	}
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		root, err := dom.GetDocument().WithDepth(-1).Do(ctx)
		if err != nil {
			return err
		}
		tokenPage, err = dom.GetOuterHTML().WithNodeID(root.NodeID).Do(ctx)
		return err
	})); err != nil {
		t.Fatalf("read revealed owner-token page: %v", err)
	}
	if !strings.Contains(tokenPage, ownerCookie.Value) {
		t.Fatal("no-JavaScript reveal did not display the primary token")
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
			if value.Type == "error" || value.Type == "warning" {
				messages := make([]string, 0, len(value.Args))
				for _, arg := range value.Args {
					message := arg.Description
					if message == "" && len(arg.Value) > 0 {
						message = string(arg.Value)
					}
					messages = append(messages, message)
				}
				consoleErrors = append(consoleErrors, strings.Join(messages, " "))
			}
		case *network.EventLoadingFailed:
			failedRequests = append(failedRequests, value.ErrorText)
		}
	})
	var initialTheme string
	var nextTheme string
	var pageWidth float64
	var overflowingElements []string
	var fixtureResult string
	err := chromedp.Run(ctx,
		network.Enable(),
		security.SetIgnoreCertificateErrors(true),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return network.SetCookie("cookie_consent", url.QueryEscape(`{"essential":true,"preferences":true,"analytics":false,"timestamp":1}`)).WithURL(browserBaseURL(t)).Do(ctx)
		}),
		chromedp.Navigate(browserBaseURL(t)),
		chromedp.WaitVisible(`#whois-form`, chromedp.ByID),
		chromedp.Evaluate(`document.documentElement.className`, &initialTheme),
		chromedp.Click(`#theme-toggle`, chromedp.ByID),
		chromedp.WaitVisible(`#whois-form`, chromedp.ByID),
		chromedp.Evaluate(`document.documentElement.className`, &nextTheme),
		chromedp.EmulateViewport(375, 812),
		chromedp.Evaluate(`document.documentElement.scrollWidth`, &pageWidth),
		chromedp.Evaluate(`Array.from(document.querySelectorAll('body *')).filter(el => el.getBoundingClientRect().right > innerWidth + 1).map(el => el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (el.className && typeof el.className === 'string' ? '.' + el.className.trim().replace(/\\s+/g, '.') : '') + ':' + Math.round(el.getBoundingClientRect().right))`, &overflowingElements),
		chromedp.SendKeys(`#q`, "fixture.example.test", chromedp.ByID),
		chromedp.Click(`#whois-form button[type=submit]`, chromedp.ByQuery),
		chromedp.WaitVisible(`#js-result`, chromedp.ByID),
		chromedp.Text(`#r-raw`, &fixtureResult, chromedp.ByID),
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
	for _, value := range []string{"Fixture Test Registrar", "ns1.fixture.example.test"} {
		if !strings.Contains(fixtureResult, value) {
			t.Errorf("full-browser WHOIS result omits %q: %q", value, fixtureResult)
		}
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
				parsedAsset, parseErr := url.Parse(assetPath)
				if parseErr != nil {
					t.Errorf("parse asset URL %q: %v", assetPath, parseErr)
					continue
				}
				assetURL := parsedBase.ResolveReference(parsedAsset)
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
