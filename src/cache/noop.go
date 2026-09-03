package cache

import (
	"context"
	"time"
)

// NoopCache implements Cache as a fully disabled cache (server.cache.type:
// none — AI.md PART 12: "Type: none (disabled)"). Every read misses and
// every write is discarded; callers still get a working Cache value so they
// never need a nil check.
type NoopCache struct {
	startTime time.Time
}

// NewNoopCache creates a disabled cache.
func NewNoopCache() *NoopCache {
	return &NoopCache{startTime: time.Now()}
}

// Get always reports a miss.
func (nc *NoopCache) Get(ctx context.Context, key string) ([]byte, error) {
	return nil, &ErrNotFound{Key: key}
}

// Set discards the value.
func (nc *NoopCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return nil
}

// Delete is a no-op.
func (nc *NoopCache) Delete(ctx context.Context, key string) error {
	return nil
}

// Clear is a no-op.
func (nc *NoopCache) Clear(ctx context.Context) error {
	return nil
}

// Exists always reports false.
func (nc *NoopCache) Exists(ctx context.Context, key string) (bool, error) {
	return false, nil
}

// GetMulti always returns an empty result.
func (nc *NoopCache) GetMulti(ctx context.Context, keys []string) (map[string][]byte, error) {
	return map[string][]byte{}, nil
}

// SetMulti discards the values.
func (nc *NoopCache) SetMulti(ctx context.Context, items map[string][]byte, ttl time.Duration) error {
	return nil
}

// Stats reports zeroed statistics.
func (nc *NoopCache) Stats(ctx context.Context) (*Stats, error) {
	return &Stats{Uptime: time.Since(nc.startTime)}, nil
}

// Close is a no-op.
func (nc *NoopCache) Close() error {
	return nil
}
