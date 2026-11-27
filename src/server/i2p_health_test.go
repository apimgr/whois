package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apimgr/whois/src/config"
	"github.com/apimgr/whois/src/i2p"
)

func TestI2PHealthStateContract(t *testing.T) {
	tests := []struct {
		name, state      string
		enabled, running bool
		status, provider string
	}{
		{name: "disabled", state: "disabled", status: "disabled", provider: "none"},
		{name: "missing provider", state: "no_provider", status: "disabled", provider: "none"},
		{name: "starting", state: "starting", enabled: true, status: "starting", provider: "i2pd"},
		{name: "building", state: "building", enabled: true, status: "starting", provider: "sam"},
		{name: "running", state: "running", enabled: true, running: true, status: "healthy", provider: "i2pd"},
		{name: "error", state: "error", enabled: true, status: "unavailable", provider: "sam"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.I2P.Enabled = tt.state != "disabled"
			s := &Server{config: cfg, i2pStatus: tt.state, i2pProvider: i2p.Provider(tt.provider)}
			got := s.buildI2PInfo()
			if got.Enabled != tt.enabled || got.Running != tt.running || got.State != tt.state || got.Status != tt.status || got.Provider != tt.provider {
				t.Fatalf("I2P health=%+v", got)
			}
			if tt.status == "unavailable" {
				checks := ChecksInfo{Database: "ok", Cache: "ok", Disk: "ok", Scheduler: "ok", I2P: "degraded"}
				if status := getOverallStatus(checks); status != "degraded" {
					t.Fatalf("overall status=%q", status)
				}
			}
		})
	}
}

func TestI2PRequestHandlerSanitizesProxyAndOverlayHeaders(t *testing.T) {
	var gotRemote, gotForwarded, gotI2P string
	handler := i2pRequestHandler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotRemote = r.RemoteAddr
		gotForwarded = r.Header.Get("X-Forwarded-Host")
		gotI2P = r.Header.Get("X-I2P-Client")
	}))
	req := httptest.NewRequest(http.MethodGet, "http://host.example/", nil)
	req.Header.Set("X-Forwarded-Host", "attacker.example")
	req.Header.Set("X-I2P-Client", "attacker")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if gotRemote != "127.0.0.2:1" || gotForwarded != "" || gotI2P != "" {
		t.Fatalf("I2P edge identity not isolated: remote=%q forwarded=%q i2p=%q", gotRemote, gotForwarded, gotI2P)
	}
}
