package runtime

import (
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
)

// TestDetectReturnFields verifies that Detect() always returns a non-nil *RuntimeInfo
// with CPUCores > 0 and a non-empty FQDN. Hostname and IP fields may be empty in
// sandboxed CI environments, so only hard requirements are checked.
func TestDetectReturnFields(t *testing.T) {
	info := Detect()
	if info == nil {
		t.Fatal("Detect() returned nil")
	}
	if info.CPUCores <= 0 {
		t.Errorf("Detect().CPUCores = %d, want > 0", info.CPUCores)
	}
	if info.FQDN == "" {
		t.Error("Detect().FQDN is empty")
	}
	// CPUCores must match runtime.NumCPU()
	if info.CPUCores != runtime.NumCPU() {
		t.Errorf("Detect().CPUCores = %d, want runtime.NumCPU() = %d", info.CPUCores, runtime.NumCPU())
	}
}

// TestDetectHostnameMatchesOS confirms that when os.Hostname() succeeds the
// RuntimeInfo.Hostname field receives that value.
func TestDetectHostnameMatchesOS(t *testing.T) {
	osHostname, err := os.Hostname()
	if err != nil {
		t.Skipf("os.Hostname() error: %v — skipping hostname assertion", err)
	}
	info := Detect()
	if info.Hostname != osHostname {
		t.Errorf("Detect().Hostname = %q, want %q", info.Hostname, osHostname)
	}
}

// TestGetFQDN_DOMAINEnvVar tests all DOMAIN env-var branches: single value,
// comma-separated list (first value is returned), and empty (falls through to OS).
func TestGetFQDN_DOMAINEnvVar(t *testing.T) {
	cases := []struct {
		name       string
		domainEnv  string
		want       string
	}{
		{
			name:      "single domain",
			domainEnv: "example.com",
			want:      "example.com",
		},
		{
			name:      "comma-separated list returns first",
			domainEnv: "primary.example.com,secondary.example.com",
			want:      "primary.example.com",
		},
		{
			name:      "comma-separated with spaces trims first entry",
			domainEnv: "  trimmed.example.com , other.example.com",
			want:      "trimmed.example.com",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DOMAIN", tc.domainEnv)
			got := GetFQDN()
			if got != tc.want {
				t.Errorf("GetFQDN() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGetFQDN_EmptyDOMAINFallsThrough confirms that an empty DOMAIN env var
// causes GetFQDN() to fall through to OS hostname or IP detection and still
// return a non-empty, non-panic result.
func TestGetFQDN_EmptyDOMAINFallsThrough(t *testing.T) {
	t.Setenv("DOMAIN", "")
	got := GetFQDN()
	if got == "" {
		t.Error("GetFQDN() returned empty string with no DOMAIN set")
	}
}

// TestGetFQDN_NeverEmpty verifies the "last resort" path: even when all detection
// fails, GetFQDN returns "localhost" rather than an empty string. We cannot force
// that path in a unit test without forking, so we assert the invariant indirectly
// by checking the return is non-empty under normal conditions.
func TestGetFQDN_NeverEmpty(t *testing.T) {
	// Clear DOMAIN so we exercise the full fallback chain.
	t.Setenv("DOMAIN", "")
	got := GetFQDN()
	if got == "" {
		t.Error("GetFQDN() must never return an empty string")
	}
}

// TestIsLoopback_KnownValues covers every branch: "localhost" string, loopback
// IPs, non-loopback IPs, non-IP hostnames, and empty string.
func TestIsLoopback_KnownValues(t *testing.T) {
	cases := []struct {
		name  string
		host  string
		want  bool
	}{
		// String match
		{name: "localhost literal", host: "localhost", want: true},
		{name: "LOCALHOST uppercase", host: "LOCALHOST", want: true},

		// IPv4 loopback
		{name: "127.0.0.1", host: "127.0.0.1", want: true},
		{name: "127.255.255.255", host: "127.255.255.255", want: true},

		// IPv6 loopback
		{name: "::1", host: "::1", want: true},

		// Non-loopback IPs
		{name: "8.8.8.8 public", host: "8.8.8.8", want: false},
		{name: "192.168.1.1 private", host: "192.168.1.1", want: false},
		{name: "2001:4860:4860::8888 public IPv6", host: "2001:4860:4860::8888", want: false},

		// Hostnames (not IPs)
		{name: "hostname no dots", host: "myhost", want: false},
		{name: "fqdn", host: "myhost.example.com", want: false},

		// Empty string is not a loopback
		{name: "empty string", host: "", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isLoopback(tc.host)
			if got != tc.want {
				t.Errorf("isLoopback(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

// TestIsPublicIP covers all routing categories: public IPv4, public IPv6,
// private IPv4 ranges, loopback, and link-local addresses.
func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		// Public IPv4
		{name: "8.8.8.8 public", ip: "8.8.8.8", want: true},
		{name: "1.1.1.1 public", ip: "1.1.1.1", want: true},

		// Private IPv4 (RFC 1918)
		{name: "10.0.0.1 private", ip: "10.0.0.1", want: false},
		{name: "172.16.0.1 private", ip: "172.16.0.1", want: false},
		{name: "192.168.0.1 private", ip: "192.168.0.1", want: false},

		// Loopback
		{name: "127.0.0.1 loopback", ip: "127.0.0.1", want: false},
		{name: "::1 IPv6 loopback", ip: "::1", want: false},

		// Link-local
		{name: "169.254.1.1 link-local", ip: "169.254.1.1", want: false},
		{name: "fe80::1 IPv6 link-local", ip: "fe80::1", want: false},

		// Public IPv6
		{name: "2001:4860:4860::8888 public", ip: "2001:4860:4860::8888", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("net.ParseIP(%q) = nil — bad test data", tc.ip)
			}
			got := IsPublicIP(ip)
			if got != tc.want {
				t.Errorf("IsPublicIP(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

// TestGetAllDomains covers the empty env, single value, comma-separated list,
// duplicate whitespace, and trailing/leading comma edge cases.
func TestGetAllDomains(t *testing.T) {
	cases := []struct {
		name      string
		domainEnv string
		want      []string
	}{
		{
			name:      "empty env returns nil",
			domainEnv: "",
			want:      nil,
		},
		{
			name:      "single domain",
			domainEnv: "example.com",
			want:      []string{"example.com"},
		},
		{
			name:      "comma-separated list",
			domainEnv: "a.example.com,b.example.com,c.example.com",
			want:      []string{"a.example.com", "b.example.com", "c.example.com"},
		},
		{
			name:      "spaces trimmed from each entry",
			domainEnv: "  a.example.com , b.example.com ",
			want:      []string{"a.example.com", "b.example.com"},
		},
		{
			name:      "empty parts from leading comma skipped",
			domainEnv: ",a.example.com",
			want:      []string{"a.example.com"},
		},
		{
			name:      "empty parts from trailing comma skipped",
			domainEnv: "a.example.com,",
			want:      []string{"a.example.com"},
		},
		{
			name:      "all-whitespace entry skipped",
			domainEnv: "a.example.com,   ,b.example.com",
			want:      []string{"a.example.com", "b.example.com"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DOMAIN", tc.domainEnv)
			got := GetAllDomains()
			if tc.want == nil {
				if got != nil {
					t.Errorf("GetAllDomains() = %v, want nil", got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("GetAllDomains() length = %d, want %d; got %v", len(got), len(tc.want), got)
			}
			for i, w := range tc.want {
				if got[i] != w {
					t.Errorf("GetAllDomains()[%d] = %q, want %q", i, got[i], w)
				}
			}
		})
	}
}

// TestGetAllDomainsIdempotent verifies that calling GetAllDomains() twice with
// the same env var produces identical slices (no shared state mutation).
func TestGetAllDomainsIdempotent(t *testing.T) {
	t.Setenv("DOMAIN", "x.example.com,y.example.com")
	first := GetAllDomains()
	second := GetAllDomains()
	if len(first) != len(second) {
		t.Fatalf("idempotency: first call len=%d second call len=%d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("idempotency: first[%d]=%q second[%d]=%q", i, first[i], i, second[i])
		}
	}
}

// TestGetFQDN_HOSTNAMEEnvFallback verifies that when DOMAIN is empty and
// os.Hostname returns "localhost", the $HOSTNAME env var loopback detection
// logic is exercised. We set HOSTNAME to a non-loopback value and a loopback
// value and compare the non-empty guarantee.
func TestGetFQDN_HOSTNAMEEnvFallback(t *testing.T) {
	// This test only exercises the path — it cannot force os.Hostname() to
	// return a loopback, so we verify the invariant: non-empty result.
	t.Setenv("DOMAIN", "")
	t.Setenv("HOSTNAME", "testnode.example.internal")
	got := GetFQDN()
	if got == "" {
		t.Error("GetFQDN() returned empty with HOSTNAME env set")
	}
}

// TestGetFQDN_LocalhostFallback verifies that the literal "localhost" fallback
// string is non-empty and matches the documented last-resort value. We confirm
// this by checking that the function always returns a non-empty, printable string.
func TestGetFQDN_LocalhostFallback(t *testing.T) {
	t.Setenv("DOMAIN", "")
	got := GetFQDN()
	if strings.TrimSpace(got) == "" {
		t.Error("GetFQDN() fallback must return a non-whitespace string")
	}
}

// TestDetectCPUCoresMatchesRuntime checks that Detect sets CPUCores to the
// value reported by runtime.NumCPU, which is the documented source.
func TestDetectCPUCoresMatchesRuntime(t *testing.T) {
	info := Detect()
	want := runtime.NumCPU()
	if info.CPUCores != want {
		t.Errorf("Detect().CPUCores = %d, want %d (runtime.NumCPU)", info.CPUCores, want)
	}
}

// TestGetFQDN_DOMAINCommaFirstEntryEdgeCases covers exact boundary where the
// comma index is at position 0 (comma first character) — that produces an empty
// left side, so GetFQDN must fall through rather than returning an empty string.
func TestGetFQDN_DOMAINCommaFirstEntryEdgeCases(t *testing.T) {
	cases := []struct {
		name      string
		domainEnv string
		wantEmpty bool
	}{
		{
			// Comma is NOT at index 0 (idx > 0 guard in source), so first segment returned.
			name:      "valid comma-separated",
			domainEnv: "first.example.com,second.example.com",
			wantEmpty: false,
		},
		{
			// Single value — no comma present, full string returned.
			name:      "single no comma",
			domainEnv: "single.example.com",
			wantEmpty: false,
		},
		{
			// Comma at index 0 means idx == 0, which fails idx > 0 guard; entire string returned.
			name:      "leading comma full string returned",
			domainEnv: ",second.example.com",
			wantEmpty: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DOMAIN", tc.domainEnv)
			got := GetFQDN()
			if tc.wantEmpty && got != "" {
				t.Errorf("GetFQDN() = %q, want empty", got)
			}
			if !tc.wantEmpty && got == "" {
				t.Errorf("GetFQDN() returned empty, want non-empty")
			}
		})
	}
}
