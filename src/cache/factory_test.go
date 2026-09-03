package cache

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestNew_DefaultsToMemory verifies that an empty or "memory" type builds a
// MemoryCache (AI.md PART 12: "memory (default)").
func TestNew_DefaultsToMemory(t *testing.T) {
	for _, typ := range []string{"", "memory", "MEMORY", " memory "} {
		c, err := New(context.Background(), Config{Type: typ})
		if err != nil {
			t.Fatalf("New(Type=%q): unexpected error: %v", typ, err)
		}
		defer c.Close()
		if _, ok := c.(*MemoryCache); !ok {
			t.Errorf("New(Type=%q): got %T, want *MemoryCache", typ, c)
		}
	}
}

// TestNew_None verifies that type "none" builds a NoopCache (AI.md PART 12:
// "Type: none (disabled)").
func TestNew_None(t *testing.T) {
	c, err := New(context.Background(), Config{Type: "none"})
	if err != nil {
		t.Fatalf("New(Type=none): unexpected error: %v", err)
	}
	defer c.Close()
	if _, ok := c.(*NoopCache); !ok {
		t.Errorf("New(Type=none): got %T, want *NoopCache", c)
	}
}

// TestNew_UnsupportedType verifies an unrecognized type returns a clear
// error rather than silently defaulting to a working backend.
func TestNew_UnsupportedType(t *testing.T) {
	_, err := New(context.Background(), Config{Type: "memcache"})
	if err == nil {
		t.Fatal("New(Type=memcache): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported cache type") {
		t.Errorf("New(Type=memcache) error = %v, want %q", err, "unsupported cache type")
	}
}

// TestNew_ValkeyAndRedisDispatchToRedisBackend verifies both "valkey" and
// "redis" type values attempt to build a RedisCache — since neither backend
// is reachable in the test environment, only the dispatch/error path is
// verified, not a live round-trip (AI.md PART 9: Valkey is a
// Redis-protocol-compatible fork).
func TestNew_ValkeyAndRedisDispatchToRedisBackend(t *testing.T) {
	for _, typ := range []string{"valkey", "redis"} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := New(ctx, Config{
			Type:    typ,
			Host:    "127.0.0.1",
			Port:    1,
			Timeout: "500ms",
		})
		cancel()
		if err == nil {
			t.Fatalf("New(Type=%q) with unreachable backend: expected error, got nil", typ)
		}
		if !strings.Contains(err.Error(), "ping redis") {
			t.Errorf("New(Type=%q) error = %v, want wrapped %q", typ, err, "ping redis")
		}
	}
}

// TestNew_InvalidTimeoutFallsBackToDefault verifies a malformed Timeout
// string does not abort construction — it only affects the redis dial
// timeout, so the resulting error must still come from the ping stage.
func TestNew_InvalidTimeoutFallsBackToDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := New(ctx, Config{
		Type:    "redis",
		Host:    "127.0.0.1",
		Port:    1,
		Timeout: "not-a-duration",
	})
	if err == nil {
		t.Fatal("New with invalid timeout string: expected ping error, got nil")
	}
	if !strings.Contains(err.Error(), "ping redis") {
		t.Errorf("New error = %v, want wrapped %q", err, "ping redis")
	}
}
