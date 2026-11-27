package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apimgr/whois/src/config"
)

func TestTokenViewCookieIsSignedAndOneUse(t *testing.T) {
	s := newTestServer(t)
	key, err := config.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	s.config.Security.EncryptionKey = key
	_, raw, err := s.issuePrimaryToken(t.Context(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	cookieResponse := httptest.NewRecorder()
	if err := s.setTokenViewCookie(cookieResponse, httptest.NewRequest(http.MethodGet, "/", nil), "primary"); err != nil {
		t.Fatal(err)
	}
	cookie := cookieResponse.Result().Cookies()[0]
	if id, ok := s.verifyTokenViewCookie(t.Context(), cookie.Value); !ok || id != "primary" {
		t.Fatal("signed primary view cookie did not validate")
	}
	tampered := *cookie
	tampered.Value = strings.Replace(tampered.Value, "primary", "unknown", 1)
	if _, ok := s.verifyTokenViewCookie(t.Context(), tampered.Value); ok {
		t.Fatal("tampered view cookie was accepted")
	}
	request := httptest.NewRequest(http.MethodGet, "/server/preferences/tokens", nil)
	request.AddCookie(&http.Cookie{Name: ownerTokenCookieName, Value: raw})
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	s.handleOwnerTokensPage(response, request)
	if !strings.Contains(response.Body.String(), raw) {
		t.Fatal("valid one-use view cookie did not reveal the token")
	}
	cleared := false
	for _, setCookie := range response.Result().Cookies() {
		if setCookie.Name == "caswhois_token_view" && setCookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("one-use view cookie was not cleared")
	}
}

func TestOwnerCookiesOmitSecureForI2PRequests(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://hidden.example/", nil)
	r = r.WithContext(context.WithValue(r.Context(), i2pRequestContextKey{}, true))
	response := httptest.NewRecorder()
	setOwnerCookie(response, r, "owner-token", 60)
	if got := response.Result().Cookies()[0].Secure; got {
		t.Fatal("owner cookie must omit Secure on I2P")
	}

	s := newTestServer(t)
	key, err := config.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	s.config.Security.EncryptionKey = key
	response = httptest.NewRecorder()
	if err := s.setTokenViewCookie(response, r, "primary"); err != nil {
		t.Fatal(err)
	}
	if got := response.Result().Cookies()[0].Secure; got {
		t.Fatal("token-view cookie must omit Secure on I2P")
	}
}

func TestOwnerCookieSlidesOnSuccessfulTokenPageUse(t *testing.T) {
	s := newTestServer(t)
	key, err := config.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	s.config.Security.EncryptionKey = key
	_, raw, err := s.issuePrimaryToken(t.Context(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/server/preferences/tokens/linked/update", nil)
	request.AddCookie(&http.Cookie{Name: ownerTokenCookieName, Value: raw})
	response := httptest.NewRecorder()
	wrapped := s.refreshOwnerCookie(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusSeeOther)
	}))
	wrapped.ServeHTTP(response, request)
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == ownerTokenCookieName && cookie.MaxAge == ownerCookieMaxAge(s.config.Tokens.CookieMaxAge) {
			return
		}
	}
	t.Fatal("successful owner-token use did not refresh the owner cookie expiry")
}

func TestOwnerAPIRequestUsesConfiguredAPIVersion(t *testing.T) {
	s := newTestServer(t)
	s.config.APIVersion = "v9"
	r := httptest.NewRequest(http.MethodPost, "/server/preferences/token/rotate", nil)
	request := s.ownerAPIRequest(r, nil, http.MethodPost, "/tokens/rotate", nil)
	if want := "/api/v9/server/preferences/tokens/rotate"; request.URL.Path != want {
		t.Fatalf("owner API path = %q, want %q", request.URL.Path, want)
	}
}
