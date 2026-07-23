package ratelimit

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestNewDefaults verifies that zero/negative constructor arguments are clamped
// to their documented defaults (60 req / 1 min).
func TestNewDefaults(t *testing.T) {
	cases := []struct {
		name     string
		requests int
		duration time.Duration
		wantReqs int
		wantDur  time.Duration
	}{
		{
			name:     "zero requests uses default 60",
			requests: 0,
			duration: time.Minute,
			wantReqs: 60,
			wantDur:  time.Minute,
		},
		{
			name:     "negative requests uses default 60",
			requests: -5,
			duration: time.Minute,
			wantReqs: 60,
			wantDur:  time.Minute,
		},
		{
			name:     "zero duration uses default 1m",
			requests: 10,
			duration: 0,
			wantReqs: 10,
			wantDur:  time.Minute,
		},
		{
			name:     "negative duration uses default 1m",
			requests: 10,
			duration: -time.Second,
			wantReqs: 10,
			wantDur:  time.Minute,
		},
		{
			name:     "both zero uses both defaults",
			requests: 0,
			duration: 0,
			wantReqs: 60,
			wantDur:  time.Minute,
		},
		{
			name:     "positive values preserved",
			requests: 100,
			duration: 5 * time.Minute,
			wantReqs: 100,
			wantDur:  5 * time.Minute,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := New(tc.requests, tc.duration)
			defer l.Close()

			s := l.Stats()
			if s.Requests != tc.wantReqs {
				t.Errorf("Requests = %d, want %d", s.Requests, tc.wantReqs)
			}
			if s.Duration != tc.wantDur {
				t.Errorf("Duration = %v, want %v", s.Duration, tc.wantDur)
			}
		})
	}
}

// TestAllowBasic verifies the core happy path: requests within limit are
// allowed, the (n+1)th request in the same window is denied.
func TestAllowBasic(t *testing.T) {
	l := New(3, time.Minute)
	defer l.Close()

	const key = "client-a"

	if !l.Allow(key) {
		t.Error("Allow(key) [1/3] = false, want true")
	}
	if !l.Allow(key) {
		t.Error("Allow(key) [2/3] = false, want true")
	}
	if !l.Allow(key) {
		t.Error("Allow(key) [3/3] = false, want true")
	}

	if l.Allow(key) {
		t.Error("Allow(key) [4/3] = true, want false (over limit)")
	}
}

// TestAllowIndependentKeys confirms two different keys do not share quota.
func TestAllowIndependentKeys(t *testing.T) {
	l := New(1, time.Minute)
	defer l.Close()

	if !l.Allow("keyA") {
		t.Error("Allow(keyA) [1/1] = false, want true")
	}
	if l.Allow("keyA") {
		t.Error("Allow(keyA) [2/1] = true, want false")
	}

	if !l.Allow("keyB") {
		t.Error("Allow(keyB) [1/1] = false, want true — independent quota")
	}
}

// TestAllowWindowExpiry confirms that requests are allowed again once the
// window duration has elapsed.
func TestAllowWindowExpiry(t *testing.T) {
	window := 50 * time.Millisecond
	l := New(1, window)
	defer l.Close()

	const key = "expiry-key"

	if !l.Allow(key) {
		t.Fatal("first allow before expiry failed")
	}
	if l.Allow(key) {
		t.Fatal("second allow before expiry should be denied")
	}

	time.Sleep(window + 10*time.Millisecond)

	if !l.Allow(key) {
		t.Error("Allow after window expiry = false, want true")
	}
}

// TestAllowEmptyKey exercises the degenerate key "" — it must behave like any
// other key (uses its own quota bucket).
func TestAllowEmptyKey(t *testing.T) {
	l := New(2, time.Minute)
	defer l.Close()

	if !l.Allow("") {
		t.Error("Allow(\"\") [1/2] = false, want true")
	}
	if !l.Allow("") {
		t.Error("Allow(\"\") [2/2] = false, want true")
	}
	if l.Allow("") {
		t.Error("Allow(\"\") [3/2] = true, want false")
	}
}

// TestAllowSingleRequest verifies a limiter with limit=1 allows exactly one
// request per window.
func TestAllowSingleRequest(t *testing.T) {
	l := New(1, time.Hour)
	defer l.Close()

	if !l.Allow("x") {
		t.Error("first allow with limit=1 failed")
	}
	for i := 0; i < 5; i++ {
		if l.Allow("x") {
			t.Errorf("allow #%d after limit=1 exhausted returned true", i+2)
		}
	}
}

// TestStatsWindowCount checks that Stats() reports the number of active keys.
func TestStatsWindowCount(t *testing.T) {
	l := New(10, time.Minute)
	defer l.Close()

	l.Allow("alpha")
	l.Allow("beta")
	l.Allow("gamma")

	s := l.Stats()
	if s.TotalKeys != 3 {
		t.Errorf("Stats().TotalKeys = %d, want 3", s.TotalKeys)
	}
	if s.WindowCount != 3 {
		t.Errorf("Stats().WindowCount = %d, want 3", s.WindowCount)
	}
	if s.Requests != 10 {
		t.Errorf("Stats().Requests = %d, want 10", s.Requests)
	}
	if s.Duration != time.Minute {
		t.Errorf("Stats().Duration = %v, want 1m", s.Duration)
	}
}

// TestStatsEmptyLimiter confirms Stats() on a fresh limiter has zero keys.
func TestStatsEmptyLimiter(t *testing.T) {
	l := New(5, time.Minute)
	defer l.Close()

	s := l.Stats()
	if s.TotalKeys != 0 {
		t.Errorf("Stats().TotalKeys on empty limiter = %d, want 0", s.TotalKeys)
	}
}

// TestGetKeyDelegatesToGetClientIP verifies GetKey returns the same value as
// GetClientIP for the same request.
func TestGetKeyDelegatesToGetClientIP(t *testing.T) {
	l := New(10, time.Minute)
	defer l.Close()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.1:1234"

	got := l.GetKey(r)
	want := GetClientIP(r)
	if got != want {
		t.Errorf("GetKey = %q, GetClientIP = %q — must match", got, want)
	}
}

// TestGetClientIPRemoteAddr verifies that RemoteAddr is used when no proxy
// headers are present.
func TestGetClientIPRemoteAddr(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{
			name:       "host:port format",
			remoteAddr: "203.0.113.7:54321",
			want:       "203.0.113.7",
		},
		{
			name:       "IPv6 host:port format",
			remoteAddr: "[2001:db8::1]:8080",
			want:       "2001:db8::1",
		},
		{
			name:       "bare IP without port",
			remoteAddr: "10.0.0.1",
			want:       "10.0.0.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr

			got := GetClientIP(r)
			if got != tc.want {
				t.Errorf("GetClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGetClientIPXForwardedFor verifies the first IP in X-Forwarded-For takes
// priority over RemoteAddr.
func TestGetClientIPXForwardedFor(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "single IP",
			header: "198.51.100.1",
			want:   "198.51.100.1",
		},
		{
			name:   "multiple IPs — first returned",
			header: "198.51.100.1, 10.0.0.1, 172.16.0.1",
			want:   "198.51.100.1",
		},
		{
			name:   "leading whitespace trimmed",
			header: "  203.0.113.5  , 10.1.1.1",
			want:   "203.0.113.5",
		},
		{
			name:   "tab-separated whitespace trimmed",
			header: "\t198.51.100.9\t,10.0.0.2",
			want:   "198.51.100.9",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = "127.0.0.1:9999"
			r.Header.Set("X-Forwarded-For", tc.header)

			got := GetClientIP(r)
			if got != tc.want {
				t.Errorf("GetClientIP with XFF %q = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

// TestGetClientIPXRealIP verifies X-Real-IP takes priority over RemoteAddr but
// yields to X-Forwarded-For.
func TestGetClientIPXRealIP(t *testing.T) {
	cases := []struct {
		name    string
		xRealIP string
		xff     string
		want    string
	}{
		{
			name:    "X-Real-IP used when no XFF",
			xRealIP: "192.0.2.55",
			xff:     "",
			want:    "192.0.2.55",
		},
		{
			name:    "XFF takes priority over X-Real-IP",
			xRealIP: "192.0.2.55",
			xff:     "198.51.100.3",
			want:    "198.51.100.3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = "127.0.0.1:1111"
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xRealIP != "" {
				r.Header.Set("X-Real-IP", tc.xRealIP)
			}

			got := GetClientIP(r)
			if got != tc.want {
				t.Errorf("GetClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestParseXForwardedForEdgeCases exercises the internal header parser directly
// via table-driven cases, covering empty, single, multi, and whitespace inputs.
func TestParseXForwardedForEdgeCases(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   []string
	}{
		{
			name:   "empty header",
			header: "",
			want:   nil,
		},
		{
			name:   "single IP",
			header: "1.2.3.4",
			want:   []string{"1.2.3.4"},
		},
		{
			name:   "two IPs",
			header: "1.2.3.4,5.6.7.8",
			want:   []string{"1.2.3.4", "5.6.7.8"},
		},
		{
			name:   "three IPs with spaces",
			header: "1.2.3.4, 5.6.7.8, 9.10.11.12",
			want:   []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"},
		},
		{
			name:   "leading and trailing spaces each entry",
			header: "  1.1.1.1  ,  2.2.2.2  ",
			want:   []string{"1.1.1.1", "2.2.2.2"},
		},
		{
			name:   "trailing comma produces no phantom entry",
			header: "1.2.3.4,",
			want:   []string{"1.2.3.4"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseXForwardedFor(tc.header)
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d (got %v)", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestCleanupExpired directly exercises cleanupExpired by creating a limiter
// with a very short duration, adding a key, letting it expire, and then calling
// cleanupExpired; the key should be removed.
func TestCleanupExpired(t *testing.T) {
	dur := 20 * time.Millisecond
	l := New(5, dur)
	defer l.Close()

	l.Allow("to-expire")

	s := l.Stats()
	if s.TotalKeys != 1 {
		t.Fatalf("expected 1 key before expiry, got %d", s.TotalKeys)
	}

	time.Sleep(dur*2 + 10*time.Millisecond)
	l.cleanupExpired()

	s = l.Stats()
	if s.TotalKeys != 0 {
		t.Errorf("TotalKeys after cleanup = %d, want 0", s.TotalKeys)
	}
}

// TestCleanupExpiredKeepsActiveWindows confirms cleanupExpired does not evict
// keys whose windows have not yet expired.
func TestCleanupExpiredKeepsActiveWindows(t *testing.T) {
	l := New(5, time.Hour)
	defer l.Close()

	l.Allow("active-key")
	l.cleanupExpired()

	s := l.Stats()
	if s.TotalKeys != 1 {
		t.Errorf("active key removed during cleanup, TotalKeys = %d, want 1", s.TotalKeys)
	}
}

// TestCloseSafety verifies that Close() can be called and the limiter stops
// accepting work without panic.
func TestCloseSafety(t *testing.T) {
	l := New(5, time.Minute)
	l.Allow("before-close")
	l.Close()
}

// TestConcurrentAllow exercises Allow() under concurrent load to detect data
// races (run with -race).  With limit=100 we expect exactly 100 allows out of
// 200 concurrent goroutines sharing the same key.
func TestConcurrentAllow(t *testing.T) {
	const limit = 100
	const goroutines = 200

	l := New(limit, time.Hour)
	defer l.Close()

	var wg sync.WaitGroup
	allowed := make(chan bool, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			allowed <- l.Allow("shared-key")
		}()
	}
	wg.Wait()
	close(allowed)

	count := 0
	for a := range allowed {
		if a {
			count++
		}
	}

	if count != limit {
		t.Errorf("concurrent allow count = %d, want %d", count, limit)
	}
}

// TestConcurrentIndependentKeys stresses the lock path with many different keys
// simultaneously to detect any race on the windows map.
func TestConcurrentIndependentKeys(t *testing.T) {
	l := New(1, time.Hour)
	defer l.Close()

	const goroutines = 50
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		key := fmt.Sprintf("key-%d", i)
		go func(k string) {
			defer wg.Done()
			l.Allow(k)
		}(key)
	}
	wg.Wait()

	s := l.Stats()
	if s.TotalKeys != goroutines {
		t.Errorf("TotalKeys = %d, want %d", s.TotalKeys, goroutines)
	}
}

// TestAllowIdempotentAfterDeny verifies that a key that has been denied is still
// denied on subsequent calls within the same window (not reset by denial).
func TestAllowIdempotentAfterDeny(t *testing.T) {
	l := New(1, time.Hour)
	defer l.Close()

	l.Allow("key")

	for i := 0; i < 3; i++ {
		if l.Allow("key") {
			t.Errorf("Allow after exhaustion on attempt %d returned true", i+1)
		}
	}
}

// TestAllowNewWindowResetsCount checks that a new window starts the counter at
// 1 (not 0), so the full limit is usable in each window.
func TestAllowNewWindowResetsCount(t *testing.T) {
	dur := 30 * time.Millisecond
	l := New(2, dur)
	defer l.Close()

	l.Allow("k")
	l.Allow("k")

	if l.Allow("k") {
		t.Fatal("third allow before expiry should be denied")
	}

	time.Sleep(dur + 10*time.Millisecond)

	if !l.Allow("k") {
		t.Error("first allow after new window = false, want true")
	}
	if !l.Allow("k") {
		t.Error("second allow after new window = false, want true")
	}
	if l.Allow("k") {
		t.Error("third allow in new window = true, want false")
	}
}
