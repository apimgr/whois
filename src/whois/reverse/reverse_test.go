package reverse

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- Result struct ---

func TestResult_Fields(t *testing.T) {
	r := Result{Domain: "example.com", Provider: "securitytrails"}
	if r.Domain != "example.com" {
		t.Errorf("Domain = %q, want example.com", r.Domain)
	}
	if r.Provider != "securitytrails" {
		t.Errorf("Provider = %q, want securitytrails", r.Provider)
	}
}

// --- SearchByOwner dispatch ---

func TestSearchByOwner_EmptyProvider(t *testing.T) {
	results, err := SearchByOwner(context.Background(), "", "", "acme", 10)
	if err != nil {
		t.Errorf("empty provider should return nil error, got %v", err)
	}
	if results != nil {
		t.Errorf("empty provider should return nil results, got %v", results)
	}
}

func TestSearchByOwner_NoneProvider(t *testing.T) {
	results, err := SearchByOwner(context.Background(), "none", "", "acme", 10)
	if err != nil {
		t.Errorf("'none' provider should return nil error, got %v", err)
	}
	if results != nil {
		t.Errorf("'none' provider should return nil results, got %v", results)
	}
}

func TestSearchByOwner_UnknownProvider(t *testing.T) {
	_, err := SearchByOwner(context.Background(), "unknownprovider", "key", "acme", 10)
	if err == nil {
		t.Error("unknown provider should return error")
	}
}

func TestSearchByOwner_ProviderCaseInsensitive(t *testing.T) {
	_, err := SearchByOwner(context.Background(), "UNKNOWNPROVIDER", "key", "acme", 10)
	if err == nil {
		t.Error("unknown provider in uppercase should return error")
	}
}

func TestSearchByOwner_DefaultMaxResults(t *testing.T) {
	results, err := SearchByOwner(context.Background(), "none", "", "acme", 0)
	if err != nil {
		t.Errorf("zero maxResults with none provider: %v", err)
	}
	if results != nil {
		t.Errorf("none provider should return nil, got %v", results)
	}
}

func TestSearchByOwner_NegativeMaxResults(t *testing.T) {
	results, err := SearchByOwner(context.Background(), "none", "", "acme", -5)
	if err != nil {
		t.Errorf("negative maxResults with none provider: %v", err)
	}
	if results != nil {
		t.Errorf("none provider should return nil, got %v", results)
	}
}

// --- SecurityTrails ---

func TestSearchByOwner_SecurityTrails_MissingAPIKey(t *testing.T) {
	_, err := SearchByOwner(context.Background(), "securitytrails", "", "acme", 10)
	if err == nil {
		t.Error("securitytrails with empty api_key should return error")
	}
}

func TestSearchByOwner_SecurityTrails_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"records": []map[string]string{
				{"hostname": "example.com"},
				{"hostname": "test.com"},
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	results, err := searchSecurityTrailsWithURL(context.Background(), "testkey", "acme", 10, srv.URL)
	if err != nil {
		t.Fatalf("securitytrails success: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("got %d results, want 2", len(results))
	}
	if results[0].Provider != "securitytrails" {
		t.Errorf("Provider = %q, want securitytrails", results[0].Provider)
	}
}

func TestSearchByOwner_SecurityTrails_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := searchSecurityTrailsWithURL(context.Background(), "badkey", "acme", 10, srv.URL)
	if err == nil {
		t.Error("securitytrails 401 should return error")
	}
}

func TestSearchByOwner_SecurityTrails_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := searchSecurityTrailsWithURL(context.Background(), "key", "acme", 10, srv.URL)
	if err == nil {
		t.Error("securitytrails 500 should return error")
	}
}

func TestSearchByOwner_SecurityTrails_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := searchSecurityTrailsWithURL(context.Background(), "key", "acme", 10, srv.URL)
	if err == nil {
		t.Error("securitytrails bad JSON should return error")
	}
}

func TestSearchByOwner_SecurityTrails_EmailOwner(t *testing.T) {
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		capturedBody = make([]byte, r.ContentLength)
		_, err = r.Body.Read(capturedBody)
		if err != nil && err.Error() != "EOF" {
			t.Errorf("read body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"records":[]}`))
	}))
	defer srv.Close()

	_, err := searchSecurityTrailsWithURL(context.Background(), "key", "user@example.com", 10, srv.URL)
	if err != nil {
		t.Fatalf("securitytrails email owner: %v", err)
	}
}

func TestSearchByOwner_SecurityTrails_MaxResultsRespected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"records": []map[string]string{
				{"hostname": "a.com"},
				{"hostname": "b.com"},
				{"hostname": "c.com"},
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	results, err := searchSecurityTrailsWithURL(context.Background(), "key", "acme", 2, srv.URL)
	if err != nil {
		t.Fatalf("securitytrails max results: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("got %d results, want 2 (maxResults=2)", len(results))
	}
}

func TestSearchByOwner_SecurityTrails_SkipsEmptyHostnames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"records": []map[string]string{
				{"hostname": ""},
				{"hostname": "real.com"},
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	results, err := searchSecurityTrailsWithURL(context.Background(), "key", "acme", 10, srv.URL)
	if err != nil {
		t.Fatalf("securitytrails skip empty: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("got %d results, want 1 (empty hostname skipped)", len(results))
	}
}

// --- Whoxy ---

func TestSearchByOwner_Whoxy_MissingAPIKey(t *testing.T) {
	_, err := SearchByOwner(context.Background(), "whoxy", "", "acme", 10)
	if err == nil {
		t.Error("whoxy with empty api_key should return error")
	}
}

func TestSearchByOwner_Whoxy_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"status_code": 1,
			"search_result": []map[string]string{
				{"domain_name": "acme.com"},
				{"domain_name": "acmecorp.com"},
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	results, err := searchWhoxyWithURL(context.Background(), "testkey", "acme", 10, srv.URL)
	if err != nil {
		t.Fatalf("whoxy success: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("got %d results, want 2", len(results))
	}
	if results[0].Provider != "whoxy" {
		t.Errorf("Provider = %q, want whoxy", results[0].Provider)
	}
}

func TestSearchByOwner_Whoxy_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := searchWhoxyWithURL(context.Background(), "key", "acme", 10, srv.URL)
	if err == nil {
		t.Error("whoxy 500 should return error")
	}
}

func TestSearchByOwner_Whoxy_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := searchWhoxyWithURL(context.Background(), "key", "acme", 10, srv.URL)
	if err == nil {
		t.Error("whoxy bad JSON should return error")
	}
}

func TestSearchByOwner_Whoxy_EmailOwner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !containsParam(r.URL.RawQuery, "email") {
			t.Errorf("email owner should use email filter, got query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"search_result":[]}`))
	}))
	defer srv.Close()

	_, err := searchWhoxyWithURL(context.Background(), "key", "user@example.com", 10, srv.URL)
	if err != nil {
		t.Fatalf("whoxy email owner: %v", err)
	}
}

func TestSearchByOwner_Whoxy_CompanyOwner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !containsParam(r.URL.RawQuery, "company") {
			t.Errorf("company owner should use company filter, got query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"search_result":[]}`))
	}))
	defer srv.Close()

	_, err := searchWhoxyWithURL(context.Background(), "key", "acmecorp", 10, srv.URL)
	if err != nil {
		t.Fatalf("whoxy company owner: %v", err)
	}
}

func TestSearchByOwner_Whoxy_MaxResultsRespected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"search_result": []map[string]string{
				{"domain_name": "a.com"},
				{"domain_name": "b.com"},
				{"domain_name": "c.com"},
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	results, err := searchWhoxyWithURL(context.Background(), "key", "acme", 1, srv.URL)
	if err != nil {
		t.Fatalf("whoxy max results: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("got %d results, want 1 (maxResults=1)", len(results))
	}
}

func TestSearchByOwner_Whoxy_SkipsEmptyDomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"search_result": []map[string]string{
				{"domain_name": ""},
				{"domain_name": "real.com"},
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	results, err := searchWhoxyWithURL(context.Background(), "key", "acme", 10, srv.URL)
	if err != nil {
		t.Fatalf("whoxy skip empty: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("got %d results, want 1 (empty domain skipped)", len(results))
	}
}

// --- ViewDNS ---

func TestSearchByOwner_ViewDNS_MissingAPIKey(t *testing.T) {
	_, err := SearchByOwner(context.Background(), "viewdns", "", "acme", 10)
	if err == nil {
		t.Error("viewdns with empty api_key should return error")
	}
}

func TestSearchByOwner_ViewDNS_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"response": map[string]interface{}{
				"domains": []map[string]string{
					{"name": "example.com"},
					{"name": "example.net"},
				},
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	results, err := searchViewDNSWithURL(context.Background(), "testkey", "acme", 10, srv.URL)
	if err != nil {
		t.Fatalf("viewdns success: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("got %d results, want 2", len(results))
	}
	if results[0].Provider != "viewdns" {
		t.Errorf("Provider = %q, want viewdns", results[0].Provider)
	}
}

func TestSearchByOwner_ViewDNS_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := searchViewDNSWithURL(context.Background(), "key", "acme", 10, srv.URL)
	if err == nil {
		t.Error("viewdns 500 should return error")
	}
}

func TestSearchByOwner_ViewDNS_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := searchViewDNSWithURL(context.Background(), "key", "acme", 10, srv.URL)
	if err == nil {
		t.Error("viewdns bad JSON should return error")
	}
}

func TestSearchByOwner_ViewDNS_MaxResultsRespected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"response": map[string]interface{}{
				"domains": []map[string]string{
					{"name": "a.com"},
					{"name": "b.com"},
					{"name": "c.com"},
				},
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	results, err := searchViewDNSWithURL(context.Background(), "key", "acme", 2, srv.URL)
	if err != nil {
		t.Fatalf("viewdns max results: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("got %d results, want 2 (maxResults=2)", len(results))
	}
}

func TestSearchByOwner_ViewDNS_SkipsEmptyNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"response": map[string]interface{}{
				"domains": []map[string]string{
					{"name": ""},
					{"name": "real.com"},
				},
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	results, err := searchViewDNSWithURL(context.Background(), "key", "acme", 10, srv.URL)
	if err != nil {
		t.Fatalf("viewdns skip empty: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("got %d results, want 1 (empty name skipped)", len(results))
	}
}

// containsParam checks if a raw query string contains a key substring.
func containsParam(rawQuery, key string) bool {
	return strings.Contains(rawQuery, key)
}
