package cache

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestRedisCache_ImplementsInterface verifies RedisCache satisfies the Cache
// interface at compile time.
func TestRedisCache_ImplementsInterface(t *testing.T) {
	var _ Cache = (*RedisCache)(nil)
}

// TestNewRedisCache_UnreachableAddress verifies that construction fails with a
// wrapped ping error when the configured host/port is unreachable. No live
// Redis/Valkey server is required or assumed to exist in the test environment.
func TestNewRedisCache_UnreachableAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := NewRedisCache(ctx, RedisOptions{
		Host:    "127.0.0.1",
		Port:    1,
		Timeout: 500 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("NewRedisCache with unreachable address: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "ping redis") {
		t.Errorf("NewRedisCache error = %v, want wrapped %q", err, "ping redis")
	}
}

// TestNewRedisCache_MalformedURL verifies that an invalid URL is rejected
// before any network connection is attempted.
func TestNewRedisCache_MalformedURL(t *testing.T) {
	_, err := NewRedisCache(context.Background(), RedisOptions{
		URL: "://not-a-valid-url",
	})
	if err == nil {
		t.Fatal("NewRedisCache with malformed URL: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "parse redis url") {
		t.Errorf("NewRedisCache error = %v, want wrapped %q", err, "parse redis url")
	}
}

// TestNewRedisCache_URLTakesPrecedence verifies a well-formed but unreachable
// redis:// URL is parsed successfully and fails only at the ping stage, not
// at the parse stage — confirming URL parsing itself is not the failure.
func TestNewRedisCache_URLTakesPrecedence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := NewRedisCache(ctx, RedisOptions{
		URL:     "redis://127.0.0.1:1/0",
		Timeout: 500 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("NewRedisCache with unreachable URL: expected error, got nil")
	}
	if strings.Contains(err.Error(), "parse redis url") {
		t.Errorf("NewRedisCache error = %v, expected ping failure not parse failure", err)
	}
	if !strings.Contains(err.Error(), "ping redis") {
		t.Errorf("NewRedisCache error = %v, want wrapped %q", err, "ping redis")
	}
}
