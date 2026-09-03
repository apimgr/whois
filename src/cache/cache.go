package cache

import (
	"context"
	"time"
)

// Cache defines the interface for caching implementations
type Cache interface {
	// Get retrieves a value from cache
	Get(ctx context.Context, key string) ([]byte, error)

	// Set stores a value in cache with TTL
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete removes a value from cache
	Delete(ctx context.Context, key string) error

	// Clear removes all values from cache
	Clear(ctx context.Context) error

	// Exists checks if a key exists in cache
	Exists(ctx context.Context, key string) (bool, error)

	// GetMulti retrieves multiple values from cache
	GetMulti(ctx context.Context, keys []string) (map[string][]byte, error)

	// SetMulti stores multiple values in cache
	SetMulti(ctx context.Context, items map[string][]byte, ttl time.Duration) error

	// Stats returns cache statistics
	Stats(ctx context.Context) (*Stats, error)

	// Close closes the cache connection
	Close() error
}

// Stats represents cache statistics
type Stats struct {
	Hits        int64         `json:"hits"`
	Misses      int64         `json:"misses"`
	Evictions   int64         `json:"evictions"`
	Size        int64         `json:"size"`
	Keys        int64         `json:"keys"`
	HitRate     float64       `json:"hit_rate"`
	Memory      int64         `json:"memory_bytes"`
	AvgItemSize int64         `json:"avg_item_size"`
	Uptime      time.Duration `json:"uptime"`
}

// ErrNotFound is returned when a key is not found in cache
type ErrNotFound struct {
	Key string
}

func (e *ErrNotFound) Error() string {
	return "cache: key not found: " + e.Key
}

// IsNotFound checks if error is ErrNotFound
func IsNotFound(err error) bool {
	_, ok := err.(*ErrNotFound)
	return ok
}

// DefaultTTLs defines default cache TTL values per content type
var DefaultTTLs = struct {
	Domain  time.Duration
	IP      time.Duration
	ASN     time.Duration
	Failure time.Duration
}{
	Domain:  24 * time.Hour,
	IP:      7 * 24 * time.Hour,
	ASN:     7 * 24 * time.Hour,
	Failure: 5 * time.Minute,
}

// KeyPrefix generates cache key with prefix
func KeyPrefix(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + ":" + key
}

// WHOISKey generates cache key for WHOIS query
func WHOISKey(query string) string {
	return "whois:" + query
}

// WHOISFailureKey generates cache key for failed WHOIS query
func WHOISFailureKey(query string) string {
	return "whois:failure:" + query
}
