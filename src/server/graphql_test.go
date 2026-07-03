package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandleGraphQLMethodNotAllowed verifies GET returns 405.
func TestHandleGraphQLMethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/graphql", nil)
	rr := httptest.NewRecorder()

	s.handleGraphQL(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}

	allow := rr.Header().Get("Allow")
	if allow != "POST" {
		t.Errorf("Allow = %q, want POST", allow)
	}
}

// TestHandleGraphQLInvalidJSON verifies bad JSON returns 400.
func TestHandleGraphQLInvalidJSON(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/graphql", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleGraphQL(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestHandleGraphQLEmptyQuery verifies empty query returns error.
func TestHandleGraphQLEmptyQuery(t *testing.T) {
	s := newTestServer(t)
	body := `{"query": ""}`
	req := httptest.NewRequest(http.MethodPost, "/api/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleGraphQL(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestHandleGraphQLHealthQuery verifies health query works.
func TestHandleGraphQLHealthQuery(t *testing.T) {
	s := newTestServer(t)
	body := `{"query": "{ health { ok status version } }"}`
	req := httptest.NewRequest(http.MethodPost, "/api/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleGraphQL(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}

	var resp GraphQLResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(resp.Errors) > 0 {
		t.Errorf("unexpected errors: %v", resp.Errors)
	}

	if resp.Data == nil {
		t.Error("data is nil, expected health data")
	}
}

// TestHandleGraphQLStatsQuery verifies stats query works.
func TestHandleGraphQLStatsQuery(t *testing.T) {
	s := newTestServer(t)
	body := `{"query": "{ stats { totalRequests } }"}`
	req := httptest.NewRequest(http.MethodPost, "/api/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleGraphQL(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}

	var resp GraphQLResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(resp.Errors) > 0 {
		t.Errorf("unexpected errors: %v", resp.Errors)
	}
}

// TestHandleGraphQLIntrospection verifies __schema introspection works.
func TestHandleGraphQLIntrospection(t *testing.T) {
	s := newTestServer(t)
	body := `{"query": "{ __schema { queryType { name } } }"}`
	req := httptest.NewRequest(http.MethodPost, "/api/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleGraphQL(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}

	var resp GraphQLResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if resp.Data == nil {
		t.Error("data is nil, expected schema data")
	}
}

// TestHandleGraphQLUnknownQuery verifies unknown query returns error.
func TestHandleGraphQLUnknownQuery(t *testing.T) {
	s := newTestServer(t)
	body := `{"query": "{ unknownField }"}`
	req := httptest.NewRequest(http.MethodPost, "/api/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleGraphQL(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (GraphQL returns 200 with errors)", rr.Code)
	}

	var resp GraphQLResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(resp.Errors) == 0 {
		t.Error("expected errors for unknown query")
	}
}

// TestHandleGraphiQL verifies /server/docs/graphql returns HTML.
func TestHandleGraphiQL(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/server/docs/graphql", nil)
	rr := httptest.NewRecorder()

	s.handleGraphiQL(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "graphiql") {
		t.Error("HTML should contain graphiql reference")
	}

	if !strings.Contains(body, "/api/graphql") {
		t.Error("HTML should reference /api/graphql endpoint")
	}
}

// TestHandleGraphQLWhoisMissingQuery verifies whois without query returns error.
func TestHandleGraphQLWhoisMissingQuery(t *testing.T) {
	s := newTestServer(t)
	body := `{"query": "{ whois { query } }"}`
	req := httptest.NewRequest(http.MethodPost, "/api/graphql", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleGraphQL(rr, req)

	var resp GraphQLResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(resp.Errors) == 0 {
		t.Error("expected error for whois without query argument")
	}
}

// TestWriteGraphQLError verifies error response format.
func TestWriteGraphQLError(t *testing.T) {
	s := newTestServer(t)
	rr := httptest.NewRecorder()

	s.writeGraphQLError(rr, http.StatusBadRequest, "Test error")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}

	var resp GraphQLResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(resp.Errors) != 1 {
		t.Errorf("errors count = %d, want 1", len(resp.Errors))
	}

	if resp.Errors[0].Message != "Test error" {
		t.Errorf("error message = %q, want Test error", resp.Errors[0].Message)
	}
}
