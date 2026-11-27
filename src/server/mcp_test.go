package server

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apimgr/whois/src/config"
)

func TestMCPRequiresBearerAndFiltersOperatorTools(t *testing.T) {
	s := newTestServer(t)
	key, err := config.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	s.config.Security.EncryptionKey = key
	_, token, err := s.issuePrimaryToken(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	handler := s.setupRoutes()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`

	unauthorized := httptest.NewRequest(http.MethodPost, "/api/v1/server/mcp", strings.NewReader(body))
	unauthorized.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	unauthorized.Header.Set("Mcp-Method", "tools/list")
	unauthorizedResult := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResult, unauthorized)
	if unauthorizedResult.Code != http.StatusUnauthorized || unauthorizedResult.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("missing-token response = %d, %q", unauthorizedResult.Code, unauthorizedResult.Body.String())
	}

	authorized := httptest.NewRequest(http.MethodPost, "/api/v1/server/mcp", strings.NewReader(body))
	authorized.Header.Set("Authorization", "Bearer "+token)
	authorized.Header.Set("Accept", "application/json")
	authorized.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	authorized.Header.Set("Mcp-Method", "tools/list")
	authorizedResult := httptest.NewRecorder()
	handler.ServeHTTP(authorizedResult, authorized)
	if authorizedResult.Code != http.StatusOK {
		t.Fatalf("owner-token tools/list status = %d, body=%s", authorizedResult.Code, authorizedResult.Body.String())
	}
	var response struct {
		Result struct {
			Tools []mcpTool `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(authorizedResult.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Result.Tools) == 0 {
		t.Fatal("tools/list returned no public WHOIS tools")
	}
	for _, tool := range response.Result.Tools {
		if tool.Name == "bulkLookup" || tool.Name == "listBackups" || tool.Name == "listSchedulerTasks" {
			t.Fatalf("owner token received operator-only tool %q", tool.Name)
		}
	}
	callBody := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"getHealth","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	callRequest := httptest.NewRequest(http.MethodPost, "/api/mcp", strings.NewReader(callBody))
	callRequest.Header.Set("Authorization", "Bearer "+token)
	callRequest.Header.Set("Accept", "application/json")
	callRequest.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	callRequest.Header.Set("Mcp-Method", "tools/call")
	callRequest.Header.Set("Mcp-Name", "getHealth")
	callResponse := httptest.NewRecorder()
	handler.ServeHTTP(callResponse, callRequest)
	if callResponse.Code != http.StatusOK || !strings.Contains(callResponse.Body.String(), `"isError":false`) {
		t.Fatalf("health tool call response = %d, %s", callResponse.Code, callResponse.Body.String())
	}
}

func TestMCPToolDiscoveryUsesConfiguredAPIVersion(t *testing.T) {
	s := newTestServer(t)
	s.config.APIVersion = "v9"
	request := httptest.NewRequest(http.MethodGet, "http://whois.example.test/", nil)
	tools := s.mcpTools(request, false)
	if len(tools) == 0 {
		t.Fatal("configured API version yielded no MCP tools")
	}
}

func TestMCPRejectsUnsupportedProtocolBeforeHeaderMismatch(t *testing.T) {
	s := newTestServer(t)
	key, err := config.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	s.config.Security.EncryptionKey = key
	_, token, err := s.issuePrimaryToken(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	handler := s.setupRoutes()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	req.Header.Set("Mcp-Method", "initialize")
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, req)
	if result.Code != http.StatusBadRequest || !strings.Contains(result.Body.String(), "Unsupported protocol version") {
		t.Fatalf("unsupported protocol response = %d, %s", result.Code, result.Body.String())
	}
}

func TestMCPHelpAPIUsesLiveToolsAndRequestURL(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "https://whois.example.test/api/v1/server/help/mcp", nil)
	rec := httptest.NewRecorder()
	s.handleMCPHelpAPI(rec, req)
	var response struct {
		Data struct {
			Enabled bool     `json:"enabled"`
			URL     string   `json:"url"`
			Aliases []string `json:"aliases"`
			Auth    struct {
				Scheme string `json:"scheme"`
			} `json:"auth"`
			Tools   []mcpTool `json:"tools"`
			Project string    `json:"project"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode MCP help response: %v", err)
	}
	if !response.Data.Enabled || response.Data.URL != "http://whois.example.test/api/v1/server/mcp" || len(response.Data.Aliases) != 2 {
		t.Fatalf("MCP help endpoint data = %#v", response.Data)
	}
	if response.Data.Auth.Scheme != "Bearer" || response.Data.Project == "" {
		t.Fatalf("MCP help auth/project = %#v", response.Data)
	}
	found := false
	for _, tool := range response.Data.Tools {
		if tool.Name == "whoisLookup" {
			found = true
		}
	}
	if !found {
		t.Fatal("MCP help tools omit live whoisLookup definition")
	}
}

func TestMCPHelpPageCopiesRenderedConnectionSnippets(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "http://whois.example.test/server/help/mcp", nil)
	rec := httptest.NewRecorder()
	s.handleMCPHelpPage(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("MCP help page status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, snippet := range []string{
		`claude mcp add --transport http 'caswhois' 'http://whois.example.test/api/v1/server/mcp' --header "Authorization: Bearer $MCP_TOKEN"`,
		`"mcpServers":{"caswhois":{"type":"http","url":"http://whois.example.test/api/v1/server/mcp","headers":{"Authorization":"Bearer $MCP_TOKEN"}}}`,
		`curl -X POST 'http://whois.example.test/api/v1/server/mcp' -H "Authorization: Bearer $MCP_TOKEN"`,
	} {
		occurrences := strings.Count(html.UnescapeString(body), snippet)
		if occurrences < 2 {
			t.Errorf("MCP help page does not render and copy snippet %q (found %d occurrences)", snippet, occurrences)
		}
	}
}
