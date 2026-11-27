package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/apimgr/whois/src/security"
	htmlparse "golang.org/x/net/html"
)

func TestSecurityPagesAndAPIAreAvailable(t *testing.T) {
	s := newTestServer(t)
	handler := s.setupRoutes()

	for _, path := range []string{"/server/security", "/server/security/policy", "/server/security/thanks", "/api/v1/server/security", "/api/v1/server/security/policy", "/api/v1/server/security/thanks", "/api/v1/server/about"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want %d: %s", path, recorder.Code, http.StatusOK, recorder.Body.String())
			}
			if strings.HasPrefix(path, "/server/") && !strings.Contains(recorder.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("GET %s content type = %q, want HTML", path, recorder.Header().Get("Content-Type"))
			}
		})
	}
}

func TestSecurityAPIListsConfiguredDisclosureChannels(t *testing.T) {
	s := newTestServer(t)
	s.config.Pages.Contact.Enabled = false
	s.config.Contact.Security.Email = "security@example.test"
	req := httptest.NewRequest(http.MethodGet, "https://whois.example.test/api/v1/server/security", nil)
	recorder := httptest.NewRecorder()
	s.handleSecurityAPI(recorder, req)

	var response struct {
		Data struct {
			Contacts []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"contacts"`
			ReportURL string `json:"report_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Data.Contacts) != 3 {
		t.Fatalf("contacts = %#v, want GitHub, instance form, and email channels", response.Data.Contacts)
	}
	if response.Data.Contacts[0].Type != "github" || response.Data.Contacts[0].Value != "https://github.com/apimgr/whois/security/advisories/new" {
		t.Errorf("first contact = %#v, want GitHub reporting channel", response.Data.Contacts[0])
	}
	if response.Data.Contacts[1].Type != "form" || !strings.HasPrefix(response.Data.Contacts[1].Value, "http://whois.example.test/server/contact?security_id=") {
		t.Errorf("second contact = %#v, want generated instance report URL", response.Data.Contacts[1])
	}
	if response.Data.Contacts[2].Type != "email" || response.Data.Contacts[2].Value != "mailto:security@example.test" {
		t.Errorf("third contact = %#v, want configured email channel", response.Data.Contacts[2])
	}
	if response.Data.ReportURL != "" {
		t.Errorf("report_url = %q, want omitted while the contact form is disabled", response.Data.ReportURL)
	}
}

func TestContactDisabledReturnsNotFound(t *testing.T) {
	s := newTestServer(t)
	s.config.Pages.Contact.Enabled = false
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(method, "/server/contact", nil)
		recorder := httptest.NewRecorder()
		s.handleContactPage(recorder, req)
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s /server/contact status = %d, want %d", method, recorder.Code, http.StatusNotFound)
		}
	}
}

func TestRegisteredServerPagesUseSharedShell(t *testing.T) {
	s := newTestServer(t)
	s.config.Pages.About.Content = "# Operator about text\n\n## About section"
	s.config.Pages.Privacy.Content = "# Operator privacy text\n\n## Privacy section"
	s.config.Pages.Terms.Content = "# Operator terms text\n\n## Terms section"
	s.config.Pages.Help.Content = "# Operator help text\n\n## Help section"
	s.config.Privacy.Content.DataCollection = "# Collection text\n\n## Collection detail"
	s.config.Web.Security.Policy = "# Reporting policy\n\n## Policy detail"
	handler := s.setupRoutes()
	trackingID := "sec_0123456789abcdef"
	statusToken := "one-time-test-status-token"
	if err := s.database.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO security_reports (tracking_id,id_window,severity,component,body_enc,body_alg,token_hash) VALUES (?,?,?,?,?,?,?)`, trackingID, 1, "low", "test", []byte("encrypted"), "aes-256-gcm", security.HashToken(statusToken))
		return err
	}); err != nil {
		t.Fatalf("seed public security report status page: %v", err)
	}
	paths := []string{
		"/", "/server/about", "/server/docs", "/server/docs/swagger",
		"/server/docs/graphql", "/server/privacy", "/server/contact", "/server/preferences",
		"/server/help", "/server/terms",
		"/server/dpo", "/server/security", "/server/security/policy", "/server/security/thanks", "/server/healthz",
		"/server/security/report/" + trackingID + "?token=" + statusToken,
	}
	for _, entry := range serverPageRegistry {
		paths = append(paths, entry.Path)
	}
	registeredHubs := map[string]string{}
	for _, entry := range serverPageRegistry {
		registeredHubs[entry.Path] = "/server/" + entry.Hub
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Accept", "text/html")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d: %s", path, recorder.Code, recorder.Body.String())
			}
			if strings.HasPrefix(path, "/server/security/report/") && (recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Referrer-Policy") != "no-referrer") {
				t.Fatalf("status-link security headers: Cache-Control=%q Referrer-Policy=%q", recorder.Header().Get("Cache-Control"), recorder.Header().Get("Referrer-Policy"))
			}
			body := recorder.Body.String()
			assertRenderedPageConformance(t, path, body)
			if hub, isSubPage := registeredHubs[path]; isSubPage {
				if count := strings.Count(body, `class="breadcrumb"`); count != 1 || !strings.Contains(body, `class="breadcrumb" aria-label="Breadcrumb"><a href="`+hub+`"`) {
					t.Errorf("%s must have one breadcrumb to %s", path, hub)
				}
			} else if path == "/server/preferences" || path == "/server/help" {
				if strings.Contains(body, `class="breadcrumb"`) {
					t.Errorf("hub %s must not have a breadcrumb", path)
				}
			}
			for _, check := range []struct {
				name  string
				count int
			}{
				{name: "main landmark", count: strings.Count(body, "<main")},
				{name: "page title", count: strings.Count(body, "<h1")},
				{name: "shared header", count: strings.Count(body, `<header class="header">`)},
				{name: "main skip link", count: strings.Count(body, `href="#main-content"`)},
				{name: "navigation skip link", count: strings.Count(body, `href="#navigation"`)},
			} {
				if check.count != 1 {
					t.Errorf("%s count = %d, want 1", check.name, check.count)
				}
			}
			bannerIndex := strings.Index(body, `class="site-banner`)
			if strings.Index(body, `href="#main-content"`) > strings.Index(body, `href="#navigation"`) || (bannerIndex >= 0 && strings.Index(body, `href="#navigation"`) > bannerIndex) {
				t.Error("skip links do not precede site announcements")
			}
		})
	}
}

func TestConfiguredHeaderFragmentFollowsHeaderActions(t *testing.T) {
	s := newTestServer(t)
	s.config.Branding.Content.Header = `<span>Operator notice</span>`
	req := httptest.NewRequest(http.MethodGet, "/server/about", nil)
	req.Header.Set("Accept", "text/html")
	recorder := httptest.NewRecorder()
	s.setupRoutes().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /server/about status = %d: %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	actions := strings.Index(body, `class="header-actions"`)
	fragment := strings.Index(body, `<div class="header-branding"><span>Operator notice</span></div>`)
	headerEnd := strings.Index(body, "</header>")
	if actions < 0 || fragment <= actions || headerEnd <= fragment {
		t.Fatalf("configured header fragment is not after actions inside the shared header: %s", body)
	}
}

func TestConfiguredAPIVersionAppearsInPagesAndDiscoveryContent(t *testing.T) {
	s := newTestServer(t)
	s.config.APIVersion = "v9"
	handler := s.setupRoutes()
	for _, path := range []string{"/", "/whois", "/server/docs"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Accept", "text/html")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "/api/v9") {
			t.Errorf("GET %s did not render the configured API version: status=%d", path, response.Code)
		}
	}
	for _, path := range []string{"/llms.txt", "/api/autodiscover"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "v9") {
			t.Errorf("GET %s did not expose the configured API version: status=%d", path, response.Code)
		}
		if path == "/llms.txt" && strings.Contains(response.Body.String(), "/api/v1") {
			t.Error("llms.txt contains the default API version instead of the configured version")
		}
	}
}

func TestPageRegistryDrivesHubAndHelpJSON(t *testing.T) {
	s := newTestServer(t)
	handler := s.setupRoutes()
	for _, entry := range serverPageRegistry {
		if entry.Enabled != nil && !entry.Enabled(s) {
			continue
		}
		t.Run(entry.Path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, entry.Path, nil)
			req.Header.Set("Accept", "text/html")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusOK || !strings.Contains(recorder.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("registered page %s returned %d %q", entry.Path, recorder.Code, recorder.Header().Get("Content-Type"))
			}

			hubPath := "/server/" + entry.Hub
			hubRecorder := httptest.NewRecorder()
			handler.ServeHTTP(hubRecorder, httptest.NewRequest(http.MethodGet, hubPath, nil))
			link := `href="` + entry.Path + `"`
			if count := strings.Count(hubRecorder.Body.String(), link); count != 1 {
				t.Errorf("hub %s has %d links to registered page %s; want exactly one", hubPath, count, entry.Path)
			}
			if entry.Hub == "help" {
				apiRecorder := httptest.NewRecorder()
				handler.ServeHTTP(apiRecorder, httptest.NewRequest(http.MethodGet, "/api/v1/server/help", nil))
				if apiRecorder.Code != http.StatusOK || !strings.Contains(apiRecorder.Body.String(), entry.Path) {
					t.Errorf("help API does not list registered page %s", entry.Path)
				}
			}
		})
	}
}

func TestStatusErrorsUseThemedSharedShellAndRecoveryFallback(t *testing.T) {
	s := newTestServer(t)
	statuses := []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable}
	for _, status := range statuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			handler := s.recoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, http.StatusText(status), status)
			}))
			req := httptest.NewRequest(http.MethodGet, "/server/test-error", nil)
			req.Header.Set("Accept", "text/html")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != status || !strings.Contains(recorder.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("error response = %d %q; want themed HTML status %d", recorder.Code, recorder.Header().Get("Content-Type"), status)
			}
			assertRenderedPageConformance(t, req.URL.Path, recorder.Body.String())
		})
	}

	panicHandler := s.recoveryMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("test panic") }))
	panicRequest := httptest.NewRequest(http.MethodGet, "/server/panic", nil)
	panicRequest.Header.Set("Accept", "text/html")
	panicRecorder := httptest.NewRecorder()
	panicHandler.ServeHTTP(panicRecorder, panicRequest)
	if panicRecorder.Code != http.StatusInternalServerError || !strings.Contains(panicRecorder.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("panic fallback response = %d %q", panicRecorder.Code, panicRecorder.Body.String())
	}
	assertRenderedPageConformance(t, panicRequest.URL.Path, panicRecorder.Body.String())
}

func assertRenderedPageConformance(t *testing.T, path, body string) {
	t.Helper()
	if regexp.MustCompile(`(?i)<style\b|\sstyle\s*=`).MatchString(body) {
		t.Errorf("%s rendered inline CSS", path)
	}
	if regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(body) {
		t.Errorf("%s rendered an inline event handler", path)
	}
	formPattern := regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form\s*>`)
	for _, match := range formPattern.FindAllStringSubmatch(body, -1) {
		if strings.Contains(strings.ToLower(match[1]), "method=\"post\"") && !strings.Contains(match[2], `name="csrf_token"`) {
			t.Errorf("%s has a POST form without a CSRF token", path)
		}
	}
	scriptPattern := regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script\s*>`)
	for _, match := range scriptPattern.FindAllStringSubmatch(body, -1) {
		attributes := strings.ToLower(match[1])
		if strings.Contains(attributes, "src=") || strings.Contains(attributes, "application/ld+json") {
			continue
		}
		if strings.TrimSpace(match[2]) != "" {
			t.Errorf("%s rendered executable inline script content", path)
		}
	}
	doc, err := htmlparse.Parse(strings.NewReader(body))
	if err != nil {
		t.Errorf("%s rendered invalid HTML: %v", path, err)
		return
	}
	counts := map[string]int{}
	var walk func(*htmlparse.Node, *htmlparse.Node)
	walk = func(node, parent *htmlparse.Node) {
		if node.Type == htmlparse.ElementNode {
			counts[node.Data]++
			switch node.Data {
			case "img":
				if _, ok := htmlAttribute(node, "alt"); !ok {
					t.Errorf("%s has an image without alt text", path)
				}
			case "input", "select", "textarea":
				typeValue, _ := htmlAttribute(node, "type")
				if node.Data == "input" && strings.EqualFold(typeValue, "hidden") {
					break
				}
				if !hasAccessibleFormLabel(doc, node) {
					t.Errorf("%s has an unlabeled %s control", path, node.Data)
				}
			case "table":
				if !hasDescendantTag(node, "thead") {
					t.Errorf("%s has a table without a thead", path)
				}
				if !hasAncestorClass(parent, "table-wrapper") {
					t.Errorf("%s has a table outside .table-wrapper", path)
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child, node)
		}
	}
	walk(doc, nil)
	if counts["main"] != 1 || counts["h1"] != 1 {
		t.Errorf("%s has %d main landmarks and %d h1 headings; want one each", path, counts["main"], counts["h1"])
	}
	if strings.HasPrefix(path, "/server/") {
		assertSectionCardConformance(t, path, doc)
	}
	assertHeaderConformance(t, path, doc)
}

func assertSectionCardConformance(t *testing.T, path string, doc *htmlparse.Node) {
	t.Helper()
	var visit func(*htmlparse.Node)
	visit = func(node *htmlparse.Node) {
		if node.Type == htmlparse.ElementNode {
			classes, _ := htmlAttribute(node, "class")
			if strings.Contains(" "+strings.Join(strings.Fields(classes), " ")+" ", " section-card ") {
				if hasAncestorClass(node.Parent, "section-card") {
					t.Errorf("%s has a section card nested inside another section card", path)
				}
				labelID, ok := htmlAttribute(node, "aria-labelledby")
				if !ok || strings.TrimSpace(labelID) == "" {
					t.Errorf("%s has a section card without aria-labelledby", path)
				} else if !hasLabeledCardHeading(node, labelID) {
					t.Errorf("%s section card label %q does not identify one of its h2 headings", path, labelID)
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(doc)
}

func hasLabeledCardHeading(card *htmlparse.Node, labelID string) bool {
	headingCount := 0
	matchingHeadingCount := 0
	var visit func(*htmlparse.Node)
	visit = func(node *htmlparse.Node) {
		if node.Type == htmlparse.ElementNode && node.Data == "h2" {
			headingCount++
			if id, ok := htmlAttribute(node, "id"); ok && id == labelID {
				matchingHeadingCount++
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(card)
	return headingCount == 1 && matchingHeadingCount == 1
}

func htmlAttribute(node *htmlparse.Node, key string) (string, bool) {
	for _, attr := range node.Attr {
		if attr.Key == key {
			return attr.Val, true
		}
	}
	return "", false
}

func hasAccessibleFormLabel(doc, control *htmlparse.Node) bool {
	if value, ok := htmlAttribute(control, "aria-label"); ok && strings.TrimSpace(value) != "" {
		return true
	}
	if value, ok := htmlAttribute(control, "aria-labelledby"); ok && strings.TrimSpace(value) != "" {
		return true
	}
	if id, ok := htmlAttribute(control, "id"); ok {
		var found bool
		var findLabel func(*htmlparse.Node)
		findLabel = func(node *htmlparse.Node) {
			if node.Type == htmlparse.ElementNode && node.Data == "label" {
				if target, exists := htmlAttribute(node, "for"); exists && target == id {
					found = true
				}
			}
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				findLabel(child)
			}
		}
		findLabel(doc)
		if found {
			return true
		}
	}
	for parent := control.Parent; parent != nil; parent = parent.Parent {
		if parent.Type == htmlparse.ElementNode && parent.Data == "label" {
			return true
		}
	}
	return false
}

func hasDescendantTag(node *htmlparse.Node, tag string) bool {
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == htmlparse.ElementNode && child.Data == tag || hasDescendantTag(child, tag) {
			return true
		}
	}
	return false
}

func hasAncestorClass(node *htmlparse.Node, className string) bool {
	for ; node != nil; node = node.Parent {
		if node.Type != htmlparse.ElementNode {
			continue
		}
		classes, _ := htmlAttribute(node, "class")
		for _, class := range strings.Fields(classes) {
			if class == className {
				return true
			}
		}
	}
	return false
}

func assertHeaderConformance(t *testing.T, path string, doc *htmlparse.Node) {
	t.Helper()
	var header *htmlparse.Node
	var visit func(*htmlparse.Node)
	visit = func(node *htmlparse.Node) {
		if node.Type == htmlparse.ElementNode && node.Data == "header" {
			classes, _ := htmlAttribute(node, "class")
			if strings.Contains(" "+classes+" ", " header ") {
				header = node
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(doc)
	if header == nil {
		t.Errorf("%s is missing the shared header", path)
		return
	}
	counts := map[string]int{}
	for child := header.FirstChild; child != nil; child = child.NextSibling {
		if child.Type != htmlparse.ElementNode {
			continue
		}
		if child.Data != "a" && child.Data != "nav" && child.Data != "label" && child.Data != "div" {
			t.Errorf("%s header has disallowed direct child <%s>", path, child.Data)
		}
		classes, _ := htmlAttribute(child, "class")
		for _, class := range strings.Fields(classes) {
			if class == "header-actions" || class == "header-branding" {
				counts[class]++
			}
		}
	}
	if counts["header-actions"] != 1 || counts["header-branding"] > 1 {
		t.Errorf("%s header has %d actions blocks and %d configured fragments", path, counts["header-actions"], counts["header-branding"])
	}
}

func TestRateLimitCountersAreBufferedAndPersistedWithoutClientIdentity(t *testing.T) {
	s := newTestServer(t)
	key := "203.0.113.45"
	for attempt := 0; attempt < 2; attempt++ {
		if !s.allowRateLimit(context.Background(), "test", s.ratelimit, key, 2, time.Minute, true) {
			t.Fatalf("attempt %d was unexpectedly rejected", attempt+1)
		}
	}
	if s.allowRateLimit(context.Background(), "test", s.ratelimit, key, 2, time.Minute, true) {
		t.Fatal("request beyond the configured limit was allowed")
	}
	var pendingCount int
	if err := s.database.Read().QueryRow(`SELECT COUNT(*) FROM rate_limit_events`).Scan(&pendingCount); err != nil {
		t.Fatalf("check rate-limit buffer before flush: %v", err)
	}
	if pendingCount != 0 {
		t.Fatalf("rate-limit events were written before the flush: %d", pendingCount)
	}
	if err := s.flushHotCounters(context.Background()); err != nil {
		t.Fatalf("flush hot counters: %v", err)
	}
	var storedKey string
	if err := s.database.Read().QueryRow(`SELECT event_key FROM rate_limit_events LIMIT 1`).Scan(&storedKey); err != nil {
		t.Fatalf("read persisted rate-limit event: %v", err)
	}
	if storedKey == key || strings.Contains(storedKey, key) {
		t.Fatalf("rate-limit storage exposed the client key: %q", storedKey)
	}
}
