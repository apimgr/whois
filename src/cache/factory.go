package cache

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Config holds the backend-agnostic settings needed to build a Cache
// (mirrors config.CacheConfig — AI.md PART 12 — server.cache.*).
type Config struct {
	// Type is one of: none, memory (default), valkey, redis.
	Type          string
	URL           string
	Host          string
	Port          int
	Username      string
	Password      string
	DB            int
	TLS           bool
	TLSSkipVerify bool
	PoolSize      int
	MinIdle       int
	Timeout       string
	Prefix        string
}

// New builds a Cache implementation from Config (AI.md PART 9 — Caching).
// Defaults to the in-process memory backend when Type is empty or "memory".
// "valkey" and "redis" both use the Redis-wire-protocol backend, since
// Valkey is a Redis-protocol-compatible fork (AI.md PART 9 cache drivers
// table: "valkey ... Preferred, open-source Redis fork").
func New(ctx context.Context, cfg Config) (Cache, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Type)) {
	case "", "memory":
		return NewMemoryCache(100*1024*1024, 5*time.Minute), nil
	case "valkey", "redis":
		timeout := 5 * time.Second
		if cfg.Timeout != "" {
			if d, err := time.ParseDuration(cfg.Timeout); err == nil {
				timeout = d
			}
		}
		return NewRedisCache(ctx, RedisOptions{
			URL:           cfg.URL,
			Host:          cfg.Host,
			Port:          cfg.Port,
			Username:      cfg.Username,
			Password:      cfg.Password,
			DB:            cfg.DB,
			TLS:           cfg.TLS,
			TLSSkipVerify: cfg.TLSSkipVerify,
			PoolSize:      cfg.PoolSize,
			MinIdle:       cfg.MinIdle,
			Timeout:       timeout,
			Prefix:        cfg.Prefix,
		})
	case "none":
		return NewNoopCache(), nil
	default:
		return nil, fmt.Errorf("unsupported cache type: %s (use none, memory, valkey, or redis)", cfg.Type)
	}
}
