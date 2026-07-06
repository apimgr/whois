package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apimgr/whois/src/config"
)

// ---------------------------------------------------------------------------
// isTrustedPeer / IsTrustedPeer
// ---------------------------------------------------------------------------

// TestIsTrustedPeer_Loopback verifies that loopback IPs are always trusted.
func TestIsTrustedPeer_Loopback(t *testing.T) {
	cases := []string{"127.0.0.1", "127.0.0.2", "::1"}
	for _, ip := range cases {
		if !isTrustedPeer(ip, nil) {
			t.Errorf("isTrustedPeer(%q) = false, want true (loopback)", ip)
		}
	}
}

// TestIsTrustedPeer_RFC1918 verifies that RFC 1918 private ranges are always trusted.
func TestIsTrustedPeer_RFC1918(t *testing.T) {
	cases := []string{
		"10.0.0.1",
		"10.255.255.255",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.0.1",
		"192.168.255.255",
	}
	for _, ip := range cases {
		if !isTrustedPeer(ip, nil) {
			t.Errorf("isTrustedPeer(%q) = false, want true (RFC 1918)", ip)
		}
	}
}

// TestIsTrustedPeer_LinkLocal verifies that link-local IPs are always trusted.
func TestIsTrustedPeer_LinkLocal(t *testing.T) {
	cases := []string{"169.254.0.1", "fe80::1"}
	for _, ip := range cases {
		if !isTrustedPeer(ip, nil) {
			t.Errorf("isTrustedPeer(%q) = false, want true (link-local)", ip)
		}
	}
}

// TestIsTrustedPeer_ULA verifies that IPv6 ULA (fc00::/7) addresses are always trusted.
func TestIsTrustedPeer_ULA(t *testing.T) {
	cases := []string{"fc00::1", "fd00::1", "fdff::1"}
	for _, ip := range cases {
		if !isTrustedPeer(ip, nil) {
			t.Errorf("isTrustedPeer(%q) = false, want true (ULA fc00::/7)", ip)
		}
	}
}

// TestIsTrustedPeer_PublicIP verifies that public IPs are not trusted by default.
func TestIsTrustedPeer_PublicIP(t *testing.T) {
	cases := []string{"8.8.8.8", "203.0.113.1", "2001:db8::1"}
	for _, ip := range cases {
		if isTrustedPeer(ip, nil) {
			t.Errorf("isTrustedPeer(%q) = true, want false (public IP)", ip)
		}
	}
}

// TestIsTrustedPeer_Additional verifies that IPs in the additional list are trusted.
func TestIsTrustedPeer_Additional(t *testing.T) {
	additional := []string{"203.0.113.50", "198.51.100.0/24"}

	if !isTrustedPeer("203.0.113.50", additional) {
		t.Error("isTrustedPeer(additional exact IP) = false, want true")
	}
	if !isTrustedPeer("198.51.100.100", additional) {
		t.Error("isTrustedPeer(additional CIDR match) = false, want true")
	}
	if isTrustedPeer("198.51.101.1", additional) {
		t.Error("isTrustedPeer(outside additional CIDR) = true, want false")
	}
}

// TestIsTrustedPeer_InvalidIP verifies that invalid IP strings are not trusted.
func TestIsTrustedPeer_InvalidIP(t *testing.T) {
	if isTrustedPeer("not-an-ip", nil) {
		t.Error("isTrustedPeer(invalid IP) = true, want false")
	}
	if isTrustedPeer("", nil) {
		t.Error("isTrustedPeer(empty string) = true, want false")
	}
}

// TestIsTrustedPeer_Exported verifies the exported IsTrustedPeer wrapper delegates correctly.
func TestIsTrustedPeer_Exported(t *testing.T) {
	if !IsTrustedPeer("127.0.0.1", nil) {
		t.Error("IsTrustedPeer(loopback) = false, want true")
	}
	if IsTrustedPeer("8.8.8.8", nil) {
		t.Error("IsTrustedPeer(public) = true, want false")
	}
}

// ---------------------------------------------------------------------------
// newURLVarsServer builds a minimal *Server suitable for GetURLVars / BuildURL tests.
// This is separate from newTestServer in handlers_test.go which requires a db and scheduler.
// ---------------------------------------------------------------------------

func newURLVarsServer(cfg *config.ServerConfig) *Server {
	return &Server{config: cfg}
}

func minCfg() *config.ServerConfig {
	return &config.ServerConfig{
		TrustedProxies: config.TrustedProxiesConfig{},
		TLS:            config.TLSConfig{Enabled: false},
	}
}

// ---------------------------------------------------------------------------
// GetURLVars
// ---------------------------------------------------------------------------

// TestGetURLVars_BasicHTTP verifies the simple direct-connection case.
func TestGetURLVars_BasicHTTP(t *testing.T) {
	s := newURLVarsServer(minCfg())
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"
	req.RemoteAddr = "203.0.113.1:12345"

	proto, fqdn, port := s.GetURLVars(req)
	if proto != "http" {
		t.Errorf("proto = %q, want %q", proto, "http")
	}
	if fqdn != "example.com" {
		t.Errorf("fqdn = %q, want %q", fqdn, "example.com")
	}
	if port != "" {
		t.Errorf("port = %q, want empty (standard port)", port)
	}
}

// TestGetURLVars_TLSEnabled verifies proto=https when TLS is enabled and no proxy header.
func TestGetURLVars_TLSEnabled(t *testing.T) {
	cfg := minCfg()
	cfg.TLS = config.TLSConfig{Enabled: true}
	s := newURLVarsServer(cfg)

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Host = "example.com"
	req.RemoteAddr = "8.8.8.8:12345"

	proto, _, _ := s.GetURLVars(req)
	if proto != "https" {
		t.Errorf("proto = %q, want %q", proto, "https")
	}
}

// TestGetURLVars_TrustedProxyHeaders verifies that proxy headers are honored
// when the peer IP is trusted (loopback).
func TestGetURLVars_TrustedProxyHeaders(t *testing.T) {
	s := newURLVarsServer(minCfg())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "internal.host"
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-Host", "public.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Port", "8443")

	proto, fqdn, port := s.GetURLVars(req)
	if proto != "https" {
		t.Errorf("proto = %q, want %q", proto, "https")
	}
	if fqdn != "public.example.com" {
		t.Errorf("fqdn = %q, want %q", fqdn, "public.example.com")
	}
	if port != "8443" {
		t.Errorf("port = %q, want %q", port, "8443")
	}
}

// TestGetURLVars_UntrustedProxyHeaders verifies that proxy headers are ignored
// when the peer IP is public (untrusted).
func TestGetURLVars_UntrustedProxyHeaders(t *testing.T) {
	s := newURLVarsServer(minCfg())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "real.host"
	req.RemoteAddr = "203.0.113.1:9000"
	req.Header.Set("X-Forwarded-Host", "attacker.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Port", "443")

	proto, fqdn, port := s.GetURLVars(req)
	if fqdn != "real.host" {
		t.Errorf("fqdn = %q, want %q (r.Host, not XFH)", fqdn, "real.host")
	}
	if proto != "http" {
		t.Errorf("proto = %q, want %q (no TLS, XFP not trusted)", proto, "http")
	}
	if port != "" {
		t.Errorf("port = %q, want empty (XFPort not trusted)", port)
	}
}

// TestGetURLVars_StandardPortsStripped verifies that :80 and :443 are never returned.
func TestGetURLVars_StandardPortsStripped(t *testing.T) {
	s := newURLVarsServer(minCfg())

	for _, hostPort := range []string{"example.com:80", "example.com:443"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = hostPort
		req.RemoteAddr = "203.0.113.1:9000"

		_, fqdn, port := s.GetURLVars(req)
		if fqdn != "example.com" {
			t.Errorf("Host=%q: fqdn = %q, want %q", hostPort, fqdn, "example.com")
		}
		if port != "" {
			t.Errorf("Host=%q: port = %q, want empty (standard port stripped)", hostPort, port)
		}
	}
}

// TestGetURLVars_TorPriority verifies that a Tor onion request bypasses all
// other resolution and returns proto=http, fqdn=onionAddr, port="" (AI.md PART 12).
func TestGetURLVars_TorPriority(t *testing.T) {
	cfg := minCfg()
	cfg.Tor = config.TorConfig{OnionAddress: "testhiddenservice.onion"}
	s := newURLVarsServer(cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "testhiddenservice.onion"
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "clearnet.example.com")

	proto, fqdn, port := s.GetURLVars(req)
	if proto != "http" {
		t.Errorf("Tor request: proto = %q, want %q", proto, "http")
	}
	if fqdn != "testhiddenservice.onion" {
		t.Errorf("Tor request: fqdn = %q, want %q", fqdn, "testhiddenservice.onion")
	}
	if port != "" {
		t.Errorf("Tor request: port = %q, want empty", port)
	}
}

// TestGetURLVars_ConfigFQDNFallback verifies that config.FQDN is used when
// r.Host is empty and no proxy headers are set.
func TestGetURLVars_ConfigFQDNFallback(t *testing.T) {
	cfg := minCfg()
	cfg.FQDN = "configured.example.com"
	s := newURLVarsServer(cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = ""
	req.RemoteAddr = "8.8.8.8:9000"

	_, fqdn, _ := s.GetURLVars(req)
	if fqdn != "configured.example.com" {
		t.Errorf("fqdn = %q, want %q (config fallback)", fqdn, "configured.example.com")
	}
}

// TestGetURLVars_XForwardedSsl verifies X-Forwarded-Ssl: on sets proto=https.
func TestGetURLVars_XForwardedSsl(t *testing.T) {
	s := newURLVarsServer(minCfg())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "example.com"
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-Ssl", "on")

	proto, _, _ := s.GetURLVars(req)
	if proto != "https" {
		t.Errorf("proto = %q, want %q", proto, "https")
	}
}

// ---------------------------------------------------------------------------
// BuildURL
// ---------------------------------------------------------------------------

// TestBuildURL_NoPort verifies BuildURL produces scheme://host/path with no port.
func TestBuildURL_NoPort(t *testing.T) {
	s := newURLVarsServer(minCfg())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "example.com"
	req.RemoteAddr = "8.8.8.8:1234"

	got := s.BuildURL(req, "/api/v1/health")
	want := "http://example.com/api/v1/health"
	if got != want {
		t.Errorf("BuildURL = %q, want %q", got, want)
	}
}

// TestBuildURL_WithPort verifies BuildURL includes the port when non-standard.
func TestBuildURL_WithPort(t *testing.T) {
	s := newURLVarsServer(minCfg())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "example.com:8080"
	req.RemoteAddr = "8.8.8.8:1234"

	got := s.BuildURL(req, "/path")
	want := "http://example.com:8080/path"
	if got != want {
		t.Errorf("BuildURL = %q, want %q", got, want)
	}
}

// TestBuildURL_StandardPortStripped verifies that :80 is stripped from the URL.
func TestBuildURL_StandardPortStripped(t *testing.T) {
	s := newURLVarsServer(minCfg())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "example.com:80"
	req.RemoteAddr = "8.8.8.8:1234"

	got := s.BuildURL(req, "/foo")
	want := "http://example.com/foo"
	if got != want {
		t.Errorf("BuildURL = %q, want %q", got, want)
	}
}

// TestBuildURL_Tor verifies BuildURL returns an http:// onion URL for Tor requests.
func TestBuildURL_Tor(t *testing.T) {
	cfg := minCfg()
	cfg.Tor = config.TorConfig{OnionAddress: "myhiddenservice.onion"}
	s := newURLVarsServer(cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "myhiddenservice.onion"
	req.RemoteAddr = "127.0.0.1:1234"

	got := s.BuildURL(req, "/api/v1/whois")
	want := "http://myhiddenservice.onion/api/v1/whois"
	if got != want {
		t.Errorf("BuildURL (Tor) = %q, want %q", got, want)
	}
}
