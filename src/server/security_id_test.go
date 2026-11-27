package server

import (
	"testing"
	"time"
)

func TestSecurityIDWindowAndValidation(t *testing.T) {
	s := newTestServer(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	current, err := s.currentSecurityID(t.Context(), now)
	if err != nil {
		t.Fatalf("currentSecurityID: %v", err)
	}
	if len(current) != 16 {
		t.Fatalf("security id length = %d, want 16", len(current))
	}
	if !s.validSecurityID(t.Context(), current, now) {
		t.Fatal("current security ID was rejected")
	}
	previous := securityIDFor(mustAppSecret(t, s), now.Unix()/securityIDWindowSeconds-1)
	if !s.validSecurityID(t.Context(), previous, now) {
		t.Fatal("previous-window security ID was rejected")
	}
	if s.validSecurityID(t.Context(), current, now.Add(2*time.Duration(securityIDWindowSeconds)*time.Second)) {
		t.Fatal("expired security ID was accepted")
	}
}

func mustAppSecret(t *testing.T, s *Server) []byte {
	t.Helper()
	secret, err := s.database.AppSecret(t.Context(), "installation_secret")
	if err != nil {
		t.Fatalf("read installation secret: %v", err)
	}
	return secret
}
