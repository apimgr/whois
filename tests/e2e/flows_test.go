//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTier1LanguageSwitchAndOpenAPIParity(t *testing.T) {
	base := baseURL(t)
	client := &http.Client{Timeout: 10 * time.Second}
	fetch := func(path, accept string) (*http.Response, []byte) {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Accept", accept)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		return response, body
	}

	englishResponse, english := fetch("/", "text/html")
	spanishResponse, spanish := fetch("/?lang=es", "text/html")
	if englishResponse.StatusCode != http.StatusOK || spanishResponse.StatusCode != http.StatusOK {
		t.Fatalf("language page statuses: en=%d es=%d", englishResponse.StatusCode, spanishResponse.StatusCode)
	}
	if !strings.Contains(string(english), `lang="en"`) || !strings.Contains(string(spanish), `lang="es"`) {
		t.Fatalf("language switch did not update SSR lang attributes")
	}
	if string(english) == string(spanish) {
		t.Fatal("language switch did not change rendered page")
	}

	openAPIResponse, openAPI := fetch("/api/swagger", "application/json")
	if openAPIResponse.StatusCode != http.StatusOK {
		t.Fatalf("OpenAPI status = %d", openAPIResponse.StatusCode)
	}
	var document struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openAPI, &document); err != nil {
		t.Fatalf("decode OpenAPI document: %v", err)
	}
	for _, path := range []string{"/api/v1/whois/validate/{query}", "/api/v1/whois/search", "/api/v1/whois/domain/{domain}"} {
		if _, ok := document.Paths[path]; !ok {
			t.Errorf("OpenAPI document omits project route %s", path)
		}
	}
}

func TestTier1OwnerTokenLifecycleAndMCP(t *testing.T) {
	base := baseURL(t)
	client := &http.Client{Timeout: 10 * time.Second}
	request := func(method, path, token, body string, mcp bool) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Accept", "application/json")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if mcp {
			req.Header.Set("MCP-Protocol-Version", "2026-07-28")
			req.Header.Set("Mcp-Method", "tools/call")
			req.Header.Set("Mcp-Name", "getHealth")
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, data
	}

	status, body := request(http.MethodGet, "/api/v1/server/preferences/tokens", "", "", false)
	if status != http.StatusUnauthorized {
		t.Fatalf("owner token list without credentials status = %d, want 401", status)
	}
	status, body = request(http.MethodPost, "/api/v1/server/preferences/tokens/primary", "", "", false)
	if status != http.StatusCreated {
		t.Fatalf("primary token issue status = %d, want 201", status)
	}
	var issued struct {
		Data struct {
			OwnerToken string `json:"owner_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &issued); err != nil || issued.Data.OwnerToken == "" {
		t.Fatalf("primary token issue response did not contain an owner token (decode error: %v)", err)
	}
	primary := issued.Data.OwnerToken
	status, _ = request(http.MethodPost, "/api/v1/server/preferences/tokens/primary", primary, "", false)
	if status != http.StatusConflict {
		t.Fatalf("primary token issue with an existing owner status = %d, want 409", status)
	}
	status, body = request(http.MethodGet, "/api/v1/server/preferences/tokens", primary, "", false)
	if status != http.StatusOK || strings.Contains(string(body), primary) {
		t.Fatalf("owner token list status = %d or exposed the raw primary token", status)
	}
	status, body = request(http.MethodPost, "/api/v1/server/preferences/tokens", primary, `{"name":"e2e-reader","scope":"read"}`, false)
	if status != http.StatusCreated {
		t.Fatalf("linked token creation status = %d, want 201", status)
	}
	var linked struct {
		Data struct {
			ID    string `json:"id"`
			Token string `json:"linked_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &linked); err != nil || linked.Data.ID == "" || linked.Data.Token == "" {
		t.Fatalf("linked token response is incomplete (decode error: %v)", err)
	}
	status, body = request(http.MethodPost, "/api/v1/server/preferences/tokens", primary, `{"name":"e2e-secondary","scope":"read-write"}`, false)
	if status != http.StatusCreated {
		t.Fatalf("second linked token creation status = %d, want 201", status)
	}
	var secondary struct {
		Data struct {
			ID    string `json:"id"`
			Token string `json:"linked_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &secondary); err != nil || secondary.Data.ID == "" || secondary.Data.Token == "" {
		t.Fatalf("second linked token response is incomplete (decode error: %v)", err)
	}
	status, body = request(http.MethodPost, "/api/v1/server/preferences/tokens/"+linked.Data.ID+"/reveal", primary, "", false)
	if status != http.StatusOK || !strings.Contains(string(body), linked.Data.Token) {
		t.Fatalf("linked token reveal status = %d or did not return the requested token", status)
	}
	status, _ = request(http.MethodPatch, "/api/v1/server/preferences/tokens/"+linked.Data.ID, primary, `{"name":"e2e-renamed","expires":"never"}`, false)
	if status != http.StatusOK {
		t.Fatalf("linked token rename/expiry update status = %d, want 200", status)
	}
	status, body = request(http.MethodPost, "/api/v1/server/preferences/tokens/"+linked.Data.ID+"/rotate", primary, "", false)
	if status != http.StatusOK {
		t.Fatalf("linked token rotation status = %d, want 200", status)
	}
	var rotatedLinked struct {
		Data struct {
			Token string `json:"linked_token"`
			Name  string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &rotatedLinked); err != nil || rotatedLinked.Data.Token == "" || rotatedLinked.Data.Token == linked.Data.Token || rotatedLinked.Data.Name != "e2e-renamed" {
		t.Fatalf("linked token rotation did not preserve identity (decode error: %v)", err)
	}
	status, _ = request(http.MethodGet, "/api/v1/server/preferences/tokens", linked.Data.Token, "", false)
	if status != http.StatusUnauthorized {
		t.Fatalf("rotated linked token remains valid: status = %d, want 401", status)
	}
	status, body = request(http.MethodGet, "/api/v1/server/preferences/tokens", primary, "", false)
	if status != http.StatusOK || !strings.Contains(string(body), "e2e-renamed") || !strings.Contains(string(body), "e2e-secondary") {
		t.Fatalf("token list did not retain renamed and independent linked tokens (status %d)", status)
	}

	mcpBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"getHealth","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	for _, credential := range []struct {
		name   string
		token  string
		status int
	}{{name: "primary", token: primary, status: http.StatusOK}, {name: "linked", token: rotatedLinked.Data.Token, status: http.StatusOK}, {name: "secondary linked", token: secondary.Data.Token, status: http.StatusOK}, {name: "missing", status: http.StatusUnauthorized}} {
		status, result := request(http.MethodPost, "/api/v1/server/mcp", credential.token, mcpBody, true)
		if status != credential.status {
			t.Errorf("MCP tools/call with %s token status = %d, want %d", credential.name, status, credential.status)
		} else if credential.token != "" && !strings.Contains(string(result), `"isError":false`) {
			t.Errorf("MCP tools/call with %s token did not succeed", credential.name)
		}
	}

	status, body = request(http.MethodPost, "/api/v1/server/preferences/tokens/primary/rotate", primary, "", false)
	if status != http.StatusOK {
		t.Fatalf("primary token rotation status = %d, want 200", status)
	}
	var rotated struct {
		Data struct {
			OwnerToken string `json:"owner_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &rotated); err != nil || rotated.Data.OwnerToken == "" || rotated.Data.OwnerToken == primary {
		t.Fatalf("primary token rotation did not return a replacement (decode error: %v)", err)
	}
	status, _ = request(http.MethodGet, "/api/v1/server/preferences/tokens", primary, "", false)
	if status != http.StatusUnauthorized {
		t.Errorf("rotated primary token remains valid: status = %d, want 401", status)
	}
	status, _ = request(http.MethodGet, "/api/v1/server/preferences/tokens", rotated.Data.OwnerToken, "", false)
	if status != http.StatusOK {
		t.Errorf("replacement primary token status = %d, want 200", status)
	}
	status, _ = request(http.MethodGet, "/api/v1/server/preferences/tokens", rotatedLinked.Data.Token, "", false)
	if status != http.StatusForbidden {
		t.Errorf("primary rotation invalidated or promoted linked token: status = %d, want 403", status)
	}
	status, _ = request(http.MethodDelete, "/api/v1/server/preferences/tokens/"+linked.Data.ID, rotated.Data.OwnerToken, "", false)
	if status != http.StatusOK {
		t.Errorf("linked token revoke status = %d, want 200", status)
	}
	status, _ = request(http.MethodPost, "/api/v1/server/mcp", rotatedLinked.Data.Token, mcpBody, true)
	if status != http.StatusUnauthorized {
		t.Errorf("revoked linked token MCP status = %d, want 401", status)
	}
	status, _ = request(http.MethodPost, "/api/v1/server/mcp", secondary.Data.Token, mcpBody, true)
	if status != http.StatusOK {
		t.Errorf("revoking one linked token invalidated another token: MCP status = %d, want 200", status)
	}
}

func TestTier2SSRInternalLinkCrawlAndCSRFRejection(t *testing.T) {
	base := baseURL(t)
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	fetchHTML := func(path string) (*http.Response, error) {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "text/html")
		return client.Do(request)
	}
	response, err := fetchHTML("/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("home page status = %d", response.StatusCode)
	}
	seen := map[string]bool{"/": true}
	queue := []string{"/"}
	for len(queue) > 0 {
		page := queue[0]
		queue = queue[1:]
		var source []byte
		if page == "/" {
			source = body
		} else {
			pageResponse, pageErr := fetchHTML(page)
			if pageErr != nil {
				t.Errorf("fetch internal page %s: %v", page, pageErr)
				continue
			}
			source, pageErr = io.ReadAll(pageResponse.Body)
			if closeErr := pageResponse.Body.Close(); closeErr != nil {
				t.Errorf("close %s response: %v", page, closeErr)
			}
			if pageErr != nil || pageResponse.StatusCode < 200 || pageResponse.StatusCode >= 400 {
				t.Errorf("internal link %s returned status %d (read error: %v)", page, pageResponse.StatusCode, pageErr)
				continue
			}
		}
		for rest := string(source); ; {
			start := strings.Index(rest, `href="`)
			if start < 0 {
				break
			}
			rest = rest[start+6:]
			end := strings.IndexByte(rest, '"')
			if end < 0 {
				break
			}
			href := rest[:end]
			rest = rest[end+1:]
			parsed, parseErr := url.Parse(href)
			if parseErr != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") || parsed.Path == "/" || strings.HasPrefix(parsed.Path, "/static/") {
				continue
			}
			path := parsed.RequestURI()
			if !seen[path] {
				seen[path] = true
				queue = append(queue, path)
			}
		}
	}
	if len(seen) < 5 {
		t.Errorf("internal link crawl visited only %d pages", len(seen))
	}

	form := url.Values{"theme": {"dark"}}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/server/preferences", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	csrfResponse, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer csrfResponse.Body.Close()
	if csrfResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without CSRF token status = %d, want 403", csrfResponse.StatusCode)
	}
}
