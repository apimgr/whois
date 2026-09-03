package cache

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCache implements Cache using a Valkey or Redis backend
// (github.com/redis/go-redis/v9 — wire-compatible with both).
type RedisCache struct {
	client    *redis.Client
	prefix    string
	startTime time.Time
	hits      int64
	misses    int64
	evictions int64
}

// RedisOptions configures a RedisCache connection.
type RedisOptions struct {
	// URL takes precedence over Host/Port/Username/Password/DB when set.
	// Format: redis://user:password@host:port/db or valkey://...
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
	Timeout       time.Duration
	Prefix        string
}

// NewRedisCache creates a Valkey/Redis-backed cache and verifies connectivity.
func NewRedisCache(ctx context.Context, opts RedisOptions) (*RedisCache, error) {
	var redisOpts *redis.Options

	if opts.URL != "" {
		parsed, err := redis.ParseURL(opts.URL)
		if err != nil {
			return nil, fmt.Errorf("parse redis url: %w", err)
		}
		redisOpts = parsed
	} else {
		redisOpts = &redis.Options{
			Addr:     fmt.Sprintf("%s:%d", opts.Host, opts.Port),
			Username: opts.Username,
			Password: opts.Password,
			DB:       opts.DB,
		}
	}

	if opts.PoolSize > 0 {
		redisOpts.PoolSize = opts.PoolSize
	}
	if opts.MinIdle > 0 {
		redisOpts.MinIdleConns = opts.MinIdle
	}
	if opts.Timeout > 0 {
		redisOpts.DialTimeout = opts.Timeout
		redisOpts.ReadTimeout = opts.Timeout
		redisOpts.WriteTimeout = opts.Timeout
	}
	if opts.TLS {
		redisOpts.TLSConfig = &tls.Config{
			InsecureSkipVerify: opts.TLSSkipVerify,
		}
	}

	client := redis.NewClient(redisOpts)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return &RedisCache{
		client:    client,
		prefix:    opts.Prefix,
		startTime: time.Now(),
	}, nil
}

// key applies the configured prefix to a cache key.
func (rc *RedisCache) key(k string) string {
	return KeyPrefix(rc.prefix, k)
}

// Get retrieves a value from cache
func (rc *RedisCache) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := rc.client.Get(ctx, rc.key(key)).Bytes()
	if err != nil {
		if err == redis.Nil {
			rc.misses++
			return nil, &ErrNotFound{Key: key}
		}
		return nil, fmt.Errorf("redis get: %w", err)
	}
	rc.hits++
	return val, nil
}

// Set stores a value in cache with TTL
func (rc *RedisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	if err := rc.client.Set(ctx, rc.key(key), value, ttl).Err(); err != nil {
		return fmt.Errorf("redis set: %w", err)
	}
	return nil
}

// Delete removes a value from cache
func (rc *RedisCache) Delete(ctx context.Context, key string) error {
	if err := rc.client.Del(ctx, rc.key(key)).Err(); err != nil {
		return fmt.Errorf("redis delete: %w", err)
	}
	return nil
}

// Clear removes all values from cache under the configured prefix.
// A prefix is required for Clear to avoid flushing an entire shared database;
// when no prefix is set, FlushDB is used.
func (rc *RedisCache) Clear(ctx context.Context) error {
	if rc.prefix == "" {
		if err := rc.client.FlushDB(ctx).Err(); err != nil {
			return fmt.Errorf("redis flushdb: %w", err)
		}
		return nil
	}

	iter := rc.client.Scan(ctx, 0, rc.prefix+":*", 0).Iterator()
	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("redis scan: %w", err)
	}
	if len(keys) == 0 {
		return nil
	}
	if err := rc.client.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("redis clear: %w", err)
	}
	return nil
}

// Exists checks if a key exists in cache
func (rc *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	n, err := rc.client.Exists(ctx, rc.key(key)).Result()
	if err != nil {
		return false, fmt.Errorf("redis exists: %w", err)
	}
	return n > 0, nil
}

// GetMulti retrieves multiple values from cache
func (rc *RedisCache) GetMulti(ctx context.Context, keys []string) (map[string][]byte, error) {
	result := make(map[string][]byte)
	if len(keys) == 0 {
		return result, nil
	}

	prefixed := make([]string, len(keys))
	for i, k := range keys {
		prefixed[i] = rc.key(k)
	}

	vals, err := rc.client.MGet(ctx, prefixed...).Result()
	if err != nil {
		return nil, fmt.Errorf("redis mget: %w", err)
	}

	for i, v := range vals {
		if v == nil {
			rc.misses++
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		result[keys[i]] = []byte(s)
		rc.hits++
	}

	return result, nil
}

// SetMulti stores multiple values in cache
func (rc *RedisCache) SetMulti(ctx context.Context, items map[string][]byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}

	pipe := rc.client.Pipeline()
	for key, value := range items {
		pipe.Set(ctx, rc.key(key), value, ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis setmulti: %w", err)
	}
	return nil
}

// Stats returns cache statistics
func (rc *RedisCache) Stats(ctx context.Context) (*Stats, error) {
	total := rc.hits + rc.misses
	hitRate := float64(0)
	if total > 0 {
		hitRate = float64(rc.hits) / float64(total)
	}

	var keys int64
	if rc.prefix != "" {
		iter := rc.client.Scan(ctx, 0, rc.prefix+":*", 0).Iterator()
		for iter.Next(ctx) {
			keys++
		}
	} else if dbSize, err := rc.client.DBSize(ctx).Result(); err == nil {
		keys = dbSize
	}

	return &Stats{
		Hits:      rc.hits,
		Misses:    rc.misses,
		Evictions: rc.evictions,
		Keys:      keys,
		HitRate:   hitRate,
		Uptime:    time.Since(rc.startTime),
	}, nil
}

// Close closes the cache connection
func (rc *RedisCache) Close() error {
	return rc.client.Close()
}
