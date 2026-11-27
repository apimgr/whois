package server

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFTokenUsesHMACSecretAndGraceKey(t *testing.T) {
	s := newTestServer(t)
	request := httptest.NewRequest(http.MethodGet, "/server/contact", nil)
	response := httptest.NewRecorder()
	token := s.csrfToken(response, request)
	if token == "" || !s.validCSRFToken(request.Context(), token) {
		t.Fatal("issued CSRF token did not validate")
	}
	if s.validCSRFToken(request.Context(), token+"x") {
		t.Fatal("tampered CSRF token was accepted")
	}
	if err := s.database.Write(request.Context(), func(tx *sql.Tx) error {
		return rotateCSRFSecretTx(request.Context(), tx)
	}); err != nil {
		t.Fatal(err)
	}
	if !s.validCSRFToken(request.Context(), token) {
		t.Fatal("previous CSRF secret did not validate within grace")
	}
	request.AddCookie(response.Result().Cookies()[0])
	if got := s.csrfToken(httptest.NewRecorder(), request); got != token {
		t.Fatal("valid grace-period CSRF token was not preserved")
	}
}
