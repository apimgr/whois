package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTorRequestIdentityUsesOnlyLowCircuitID(t *testing.T) {
	var got string
	handler := torRequestHandler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = torRequestIdentity(r)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://example.onion/", nil)
	request.RemoteAddr = "[fd00:1234:5678:9abc:1111:2222:0000:002a]:1234"
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if got != "tor:42" {
		t.Fatalf("circuit identity = %q, want tor:42", got)
	}
}

func TestTorRequestIdentityUsesOpaqueFallbackWithoutAddress(t *testing.T) {
	var got string
	handler := torRequestHandler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = torRequestIdentity(r)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://example.onion/", nil)
	request.RemoteAddr = "not-an-ip"
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if got != "tor" {
		t.Fatalf("identity = %q, want opaque tor sentinel", got)
	}
}

func TestTorRequestIdentityDoesNotChangeClearnetAddress(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if identity, ok := torRequestIdentity(request); ok || identity != "" {
		t.Fatalf("clearnet identity = %q, tor=%v", identity, ok)
	}
}
