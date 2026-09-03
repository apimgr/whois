package cache

import (
	"context"
	"testing"
	"time"
)

// TestErrNotFound_Error covers the error message format for ErrNotFound.
func TestErrNotFound_Error(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want string
	}{
		{name: "simple key", key: "foo", want: "cache: key not found: foo"},
		{name: "empty key", key: "", want: "cache: key not found: "},
		{name: "whois key", key: "whois:example.com", want: "cache: key not found: whois:example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &ErrNotFound{Key: tc.key}
			if got := e.Error(); got != tc.want {
				t.Errorf("ErrNotFound{%q}.Error() = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

// TestIsNotFound checks that IsNotFound correctly identifies *ErrNotFound errors
// and returns false for nil or other error types.
func TestIsNotFound(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "ErrNotFound pointer", err: &ErrNotFound{Key: "k"}, want: true},
		{name: "nil error", err: nil, want: false},
		{name: "other error type", err: context.DeadlineExceeded, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsNotFound(tc.err); got != tc.want {
				t.Errorf("IsNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestKeyPrefix verifies prefix concatenation and the empty-prefix passthrough.
func TestKeyPrefix(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		key    string
		want   string
	}{
		{name: "normal prefix", prefix: "ns", key: "foo", want: "ns:foo"},
		{name: "empty prefix returns key", prefix: "", key: "foo", want: "foo"},
		{name: "empty key with prefix", prefix: "ns", key: "", want: "ns:"},
		{name: "both empty", prefix: "", key: "", want: ""},
		{name: "nested prefix", prefix: "a:b", key: "c", want: "a:b:c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := KeyPrefix(tc.prefix, tc.key); got != tc.want {
				t.Errorf("KeyPrefix(%q, %q) = %q, want %q", tc.prefix, tc.key, got, tc.want)
			}
		})
	}
}

// TestWHOISKey and TestWHOISFailureKey verify the key generation helpers.
func TestWHOISKey(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  string
	}{
		{name: "domain", query: "example.com", want: "whois:example.com"},
		{name: "IP", query: "8.8.8.8", want: "whois:8.8.8.8"},
		{name: "empty", query: "", want: "whois:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := WHOISKey(tc.query); got != tc.want {
				t.Errorf("WHOISKey(%q) = %q, want %q", tc.query, got, tc.want)
			}
		})
	}
}

func TestWHOISFailureKey(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  string
	}{
		{name: "domain", query: "example.com", want: "whois:failure:example.com"},
		{name: "IP", query: "1.2.3.4", want: "whois:failure:1.2.3.4"},
		{name: "empty", query: "", want: "whois:failure:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := WHOISFailureKey(tc.query); got != tc.want {
				t.Errorf("WHOISFailureKey(%q) = %q, want %q", tc.query, got, tc.want)
			}
		})
	}
}

// TestDefaultTTLs verifies the TTL values match the spec (domain 24h, IP/ASN 7d, failure 5m).
func TestDefaultTTLs(t *testing.T) {
	if DefaultTTLs.Domain != 24*time.Hour {
		t.Errorf("DefaultTTLs.Domain = %v, want 24h", DefaultTTLs.Domain)
	}
	if DefaultTTLs.IP != 7*24*time.Hour {
		t.Errorf("DefaultTTLs.IP = %v, want 168h", DefaultTTLs.IP)
	}
	if DefaultTTLs.ASN != 7*24*time.Hour {
		t.Errorf("DefaultTTLs.ASN = %v, want 168h", DefaultTTLs.ASN)
	}
	if DefaultTTLs.Failure != 5*time.Minute {
		t.Errorf("DefaultTTLs.Failure = %v, want 5m", DefaultTTLs.Failure)
	}
}

// newTestCache returns a MemoryCache with a very large max size and a slow
// cleanup interval so tests are not affected by background eviction.
func newTestCache() *MemoryCache {
	mc := NewMemoryCache(100*1024*1024, time.Hour)
	return mc
}

// TestNewMemoryCache_Defaults verifies that zero/negative constructor args are
// clamped to sane defaults instead of producing a broken cache.
func TestNewMemoryCache_Defaults(t *testing.T) {
	mc := NewMemoryCache(0, 0)
	defer mc.Close()
	if mc.maxSize != 100*1024*1024 {
		t.Errorf("maxSize default: got %d, want %d", mc.maxSize, 100*1024*1024)
	}
	if mc.cleanupInt != 5*time.Minute {
		t.Errorf("cleanupInt default: got %v, want 5m", mc.cleanupInt)
	}
}

// TestMemoryCache_SetGet covers the fundamental get-after-set and miss cases.
func TestMemoryCache_SetGet(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	cases := []struct {
		name    string
		key     string
		value   []byte
		ttl     time.Duration
		wantVal []byte
		wantErr bool
	}{
		{name: "simple set-get", key: "k1", value: []byte("hello"), ttl: time.Minute, wantVal: []byte("hello")},
		{name: "binary value", key: "k2", value: []byte{0x00, 0xff, 0xab}, ttl: time.Minute, wantVal: []byte{0x00, 0xff, 0xab}},
		{name: "empty value", key: "k3", value: []byte{}, ttl: time.Minute, wantVal: []byte{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := mc.Set(ctx, tc.key, tc.value, tc.ttl); err != nil {
				t.Fatalf("Set unexpected error: %v", err)
			}
			got, err := mc.Get(ctx, tc.key)
			if err != nil {
				t.Fatalf("Get unexpected error: %v", err)
			}
			if string(got) != string(tc.wantVal) {
				t.Errorf("Get(%q) = %v, want %v", tc.key, got, tc.wantVal)
			}
		})
	}
}

// TestMemoryCache_Get_Miss verifies Get returns ErrNotFound for absent keys.
func TestMemoryCache_Get_Miss(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	_, err := mc.Get(ctx, "does-not-exist")
	if err == nil {
		t.Fatal("Get on missing key expected error, got nil")
	}
	if !IsNotFound(err) {
		t.Errorf("Get on missing key: expected ErrNotFound, got %T: %v", err, err)
	}
}

// TestMemoryCache_Get_Expired verifies that an expired item is treated as a miss.
func TestMemoryCache_Get_Expired(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	if err := mc.Set(ctx, "exp", []byte("data"), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	// Wait for TTL to lapse.
	time.Sleep(5 * time.Millisecond)

	_, err := mc.Get(ctx, "exp")
	if err == nil {
		t.Fatal("Get on expired key expected ErrNotFound, got nil")
	}
	if !IsNotFound(err) {
		t.Errorf("expected ErrNotFound, got %T: %v", err, err)
	}
}

// TestMemoryCache_Set_ZeroTTL verifies that a zero/negative TTL is replaced by
// the 1-hour default so the item is retrievable immediately after Set.
func TestMemoryCache_Set_ZeroTTL(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	if err := mc.Set(ctx, "z", []byte("v"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := mc.Get(ctx, "z"); err != nil {
		t.Errorf("Get after Set with zero TTL should succeed (default 1h): %v", err)
	}
}

// TestMemoryCache_Delete verifies that a key is gone after Delete.
func TestMemoryCache_Delete(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	if err := mc.Set(ctx, "del", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := mc.Delete(ctx, "del"); err != nil {
		t.Fatalf("Delete unexpected error: %v", err)
	}
	if _, err := mc.Get(ctx, "del"); !IsNotFound(err) {
		t.Errorf("Get after Delete should return ErrNotFound, got %v", err)
	}
}

// TestMemoryCache_Delete_NonExistent verifies deleting an absent key is a no-op.
func TestMemoryCache_Delete_NonExistent(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	if err := mc.Delete(ctx, "ghost"); err != nil {
		t.Errorf("Delete on absent key unexpected error: %v", err)
	}
}

// TestMemoryCache_Clear verifies that Clear removes all items.
func TestMemoryCache_Clear(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	keys := []string{"a", "b", "c"}
	for _, k := range keys {
		if err := mc.Set(ctx, k, []byte(k), time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if err := mc.Clear(ctx); err != nil {
		t.Fatalf("Clear unexpected error: %v", err)
	}
	for _, k := range keys {
		if _, err := mc.Get(ctx, k); !IsNotFound(err) {
			t.Errorf("Get(%q) after Clear should return ErrNotFound, got %v", k, err)
		}
	}
}

// TestMemoryCache_Exists covers present, absent, and expired key cases.
func TestMemoryCache_Exists(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	if err := mc.Set(ctx, "live", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := mc.Set(ctx, "soon", []byte("v"), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)

	cases := []struct {
		name string
		key  string
		want bool
	}{
		{name: "live key exists", key: "live", want: true},
		{name: "absent key", key: "nope", want: false},
		{name: "expired key", key: "soon", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mc.Exists(ctx, tc.key)
			if err != nil {
				t.Fatalf("Exists(%q) unexpected error: %v", tc.key, err)
			}
			if got != tc.want {
				t.Errorf("Exists(%q) = %v, want %v", tc.key, got, tc.want)
			}
		})
	}
}

// TestMemoryCache_GetMulti verifies that GetMulti returns hits and silently
// omits misses (both absent and expired keys).
func TestMemoryCache_GetMulti(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	if err := mc.Set(ctx, "m1", []byte("one"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := mc.Set(ctx, "m2", []byte("two"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := mc.Set(ctx, "mx", []byte("exp"), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)

	result, err := mc.GetMulti(ctx, []string{"m1", "m2", "mx", "missing"})
	if err != nil {
		t.Fatalf("GetMulti unexpected error: %v", err)
	}
	if string(result["m1"]) != "one" {
		t.Errorf("GetMulti[m1] = %q, want \"one\"", result["m1"])
	}
	if string(result["m2"]) != "two" {
		t.Errorf("GetMulti[m2] = %q, want \"two\"", result["m2"])
	}
	if _, ok := result["mx"]; ok {
		t.Error("GetMulti: expired key mx should not appear in result")
	}
	if _, ok := result["missing"]; ok {
		t.Error("GetMulti: absent key missing should not appear in result")
	}
}

// TestMemoryCache_GetMulti_Empty exercises the empty-key-slice path.
func TestMemoryCache_GetMulti_Empty(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	result, err := mc.GetMulti(ctx, []string{})
	if err != nil {
		t.Fatalf("GetMulti(empty) unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("GetMulti(empty) = %v, want empty map", result)
	}
}

// TestMemoryCache_SetMulti verifies that all items written by SetMulti are
// retrievable and that zero TTL defaults to 1 hour.
func TestMemoryCache_SetMulti(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	items := map[string][]byte{
		"x": []byte("X"),
		"y": []byte("Y"),
	}
	if err := mc.SetMulti(ctx, items, time.Minute); err != nil {
		t.Fatalf("SetMulti unexpected error: %v", err)
	}
	for k, want := range items {
		got, err := mc.Get(ctx, k)
		if err != nil {
			t.Errorf("Get(%q) after SetMulti unexpected error: %v", k, err)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("Get(%q) = %q, want %q", k, got, want)
		}
	}
}

// TestMemoryCache_SetMulti_ZeroTTL verifies that zero TTL in SetMulti
// defaults to 1 hour (items are immediately retrievable).
func TestMemoryCache_SetMulti_ZeroTTL(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	if err := mc.SetMulti(ctx, map[string][]byte{"z": []byte("v")}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := mc.Get(ctx, "z"); err != nil {
		t.Errorf("Get after SetMulti with zero TTL should succeed: %v", err)
	}
}

// TestMemoryCache_Stats_HitRate verifies hit-rate calculation, key count,
// and that uptime is non-negative.
func TestMemoryCache_Stats_HitRate(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	// Populate two keys; perform two hits and one miss.
	if err := mc.Set(ctx, "s1", []byte("v1"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := mc.Set(ctx, "s2", []byte("v2"), time.Minute); err != nil {
		t.Fatal(err)
	}
	mc.Get(ctx, "s1")
	mc.Get(ctx, "s2")
	mc.Get(ctx, "absent")

	stats, err := mc.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats unexpected error: %v", err)
	}
	if stats.Hits != 2 {
		t.Errorf("Stats.Hits = %d, want 2", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("Stats.Misses = %d, want 1", stats.Misses)
	}
	wantRate := float64(2) / float64(3)
	if stats.HitRate != wantRate {
		t.Errorf("Stats.HitRate = %v, want %v", stats.HitRate, wantRate)
	}
	if stats.Keys != 2 {
		t.Errorf("Stats.Keys = %d, want 2", stats.Keys)
	}
	if stats.Uptime < 0 {
		t.Errorf("Stats.Uptime = %v, want >= 0", stats.Uptime)
	}
}

// TestMemoryCache_Stats_ZeroHitRate verifies that HitRate is 0 when there are
// no accesses (avoids divide-by-zero).
func TestMemoryCache_Stats_ZeroHitRate(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	stats, err := mc.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats unexpected error: %v", err)
	}
	if stats.HitRate != 0 {
		t.Errorf("Stats.HitRate on fresh cache = %v, want 0", stats.HitRate)
	}
	if stats.Keys != 0 {
		t.Errorf("Stats.Keys on fresh cache = %d, want 0", stats.Keys)
	}
	if stats.AvgItemSize != 0 {
		t.Errorf("Stats.AvgItemSize on fresh cache = %d, want 0", stats.AvgItemSize)
	}
}

// TestMemoryCache_Stats_AvgItemSize verifies the average item size is computed
// when the cache has at least one item.
func TestMemoryCache_Stats_AvgItemSize(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	if err := mc.Set(ctx, "key", []byte("value"), time.Minute); err != nil {
		t.Fatal(err)
	}
	stats, err := mc.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// key="key" (3 bytes) + value="value" (5 bytes) = 8 bytes / 1 key = 8
	if stats.AvgItemSize != 8 {
		t.Errorf("Stats.AvgItemSize = %d, want 8", stats.AvgItemSize)
	}
}

// TestMemoryCache_Close verifies that Close returns nil and that the cleanup
// goroutine stops (channel is closed once; subsequent Close would panic — so we
// call it exactly once).
func TestMemoryCache_Close(t *testing.T) {
	mc := newTestCache()
	if err := mc.Close(); err != nil {
		t.Errorf("Close() unexpected error: %v", err)
	}
}

// TestMemoryCache_Overwrite verifies that setting the same key twice replaces
// the value rather than duplicating it.
func TestMemoryCache_Overwrite(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	if err := mc.Set(ctx, "ow", []byte("first"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := mc.Set(ctx, "ow", []byte("second"), time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err := mc.Get(ctx, "ow")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Errorf("Get after overwrite = %q, want \"second\"", got)
	}

	// Only one key should be registered.
	stats, _ := mc.Stats(ctx)
	if stats.Keys != 1 {
		t.Errorf("Stats.Keys after overwrite = %d, want 1", stats.Keys)
	}
}

// TestMemoryCache_Eviction_WhenFull verifies that when the cache is at capacity
// an eviction occurs and the new item is still stored.
func TestMemoryCache_Eviction_WhenFull(t *testing.T) {
	// Max size: 10 bytes — small enough to trigger eviction.
	mc := NewMemoryCache(10, time.Hour)
	defer mc.Close()
	ctx := context.Background()

	// "k1" + "AAAAAAA" = 3 + 7 = 10 bytes — exactly fills the cache.
	if err := mc.Set(ctx, "k1", []byte("AAAAAAA"), time.Minute); err != nil {
		t.Fatal(err)
	}
	// Writing a second item must trigger eviction since we are at capacity.
	if err := mc.Set(ctx, "k2", []byte("BB"), time.Minute); err != nil {
		t.Fatalf("Set after capacity should not fail: %v", err)
	}
	// k2 must be present.
	if _, err := mc.Get(ctx, "k2"); err != nil {
		t.Errorf("Get(k2) after eviction-triggered set: %v", err)
	}
	// At least one eviction counter should have been incremented.
	stats, _ := mc.Stats(ctx)
	if stats.Evictions < 1 {
		t.Errorf("Stats.Evictions = %d, want >= 1 after capacity overflow", stats.Evictions)
	}
}

// TestMemoryCache_EvictOldest_PreferExpired verifies that evictOldest removes
// an expired item first before touching a live one.
func TestMemoryCache_EvictOldest_PreferExpired(t *testing.T) {
	// Max size just big enough for one item so the second triggers eviction.
	mc := NewMemoryCache(8, time.Hour)
	defer mc.Close()
	ctx := context.Background()

	// Write an expired item.
	if err := mc.Set(ctx, "exp", []byte("val"), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)

	// Write a live item; evictOldest should remove the expired one.
	if err := mc.Set(ctx, "live", []byte("ok"), time.Minute); err != nil {
		t.Fatalf("Set with expired item present should not error: %v", err)
	}
	if _, err := mc.Get(ctx, "live"); err != nil {
		t.Errorf("live key should survive after eviction: %v", err)
	}
}

// TestMemoryCache_cleanup exercises the internal cleanup() method directly by
// checking that expired items are removed and the eviction counter increments.
func TestMemoryCache_cleanup(t *testing.T) {
	mc := newTestCache()
	defer mc.Close()
	ctx := context.Background()

	if err := mc.Set(ctx, "gone", []byte("v"), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)

	mc.cleanup()

	if exists, _ := mc.Exists(ctx, "gone"); exists {
		t.Error("cleanup should have removed expired key 'gone'")
	}
	stats, _ := mc.Stats(ctx)
	if stats.Evictions < 1 {
		t.Errorf("Stats.Evictions = %d, want >= 1 after cleanup", stats.Evictions)
	}
}

// TestMemoryCache_ImplementsInterface verifies MemoryCache satisfies the Cache
// interface at compile time.
func TestMemoryCache_ImplementsInterface(t *testing.T) {
	var _ Cache = (*MemoryCache)(nil)
}
