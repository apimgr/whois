package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAcceptsPlainTextUsesQualityAndJSONTieBreak(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		want   bool
	}{{"text only", "text/plain", true}, {"json wins tie", "text/plain, application/json", false}, {"json higher quality", "text/plain;q=0.8, application/json;q=0.9", false}, {"text higher quality", "application/json;q=0.5, text/plain;q=0.9", true}, {"wildcard defaults json", "*/*", false}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := acceptsPlainText(test.accept); got != test.want {
				t.Errorf("acceptsPlainText(%q) = %t, want %t", test.accept, got, test.want)
			}
		})
	}
}

func TestAPITextErrorPreservesStatusAndFormat(t *testing.T) {
	handler := apiContentNegotiation(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusBadRequest, APIResponse{OK: false, Error: ErrValidationFailed, Message: "invalid query"})
	}), nil)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	request.Header.Set("Accept", "text/plain")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", got)
	}
	if got := recorder.Body.String(); got != "ERROR: VALIDATION_FAILED: invalid query\n" {
		t.Fatalf("body = %q", got)
	}
}
