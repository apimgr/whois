package cache

import (
	"context"
	"sync"
	"time"
)

// MemoryCache implements Cache interface using in-memory storage
type MemoryCache struct {
	mu         sync.RWMutex
	items      map[string]*cacheItem
	stats      *Stats
	startTime  time.Time
	maxSize    int64
	cleanupInt time.Duration
	stopClean  chan struct{}
}

// cacheItem represents a cached item with expiration
type cacheItem struct {
	value      []byte
	expiration time.Time
}

// NewMemoryCache creates a new in-memory cache
func NewMemoryCache(maxSize int64, cleanupInterval time.Duration) *MemoryCache {
	if maxSize <= 0 {
		maxSize = 100 * 1024 * 1024
	}
	if cleanupInterval <= 0 {
		cleanupInterval = 5 * time.Minute
	}

	mc := &MemoryCache{
		items:      make(map[string]*cacheItem),
		stats:      &Stats{},
		startTime:  time.Now(),
		maxSize:    maxSize,
		cleanupInt: cleanupInterval,
		stopClean:  make(chan struct{}),
	}

	go mc.cleanupLoop()

	return mc
}

// Get retrieves a value from cache
func (mc *MemoryCache) Get(ctx context.Context, key string) ([]byte, error) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	item, found := mc.items[key]
	if !found {
		mc.stats.Misses++
		return nil, &ErrNotFound{Key: key}
	}

	if time.Now().After(item.expiration) {
		mc.stats.Misses++
		return nil, &ErrNotFound{Key: key}
	}

	mc.stats.Hits++
	return item.value, nil
}

// Set stores a value in cache with TTL
func (mc *MemoryCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()

	currentSize := mc.currentSize()
	newItemSize := int64(len(key) + len(value))

	if currentSize+newItemSize > mc.maxSize {
		mc.evictOldest()
	}

	mc.items[key] = &cacheItem{
		value:      value,
		expiration: time.Now().Add(ttl),
	}

	return nil
}

// Delete removes a value from cache
func (mc *MemoryCache) Delete(ctx context.Context, key string) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	delete(mc.items, key)
	return nil
}

// Clear removes all values from cache
func (mc *MemoryCache) Clear(ctx context.Context) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.items = make(map[string]*cacheItem)
	return nil
}

// Exists checks if a key exists in cache
func (mc *MemoryCache) Exists(ctx context.Context, key string) (bool, error) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	item, found := mc.items[key]
	if !found {
		return false, nil
	}

	if time.Now().After(item.expiration) {
		return false, nil
	}

	return true, nil
}

// GetMulti retrieves multiple values from cache
func (mc *MemoryCache) GetMulti(ctx context.Context, keys []string) (map[string][]byte, error) {
	result := make(map[string][]byte)

	mc.mu.RLock()
	defer mc.mu.RUnlock()

	now := time.Now()
	for _, key := range keys {
		if item, found := mc.items[key]; found && now.Before(item.expiration) {
			result[key] = item.value
			mc.stats.Hits++
		} else {
			mc.stats.Misses++
		}
	}

	return result, nil
}

// SetMulti stores multiple values in cache
func (mc *MemoryCache) SetMulti(ctx context.Context, items map[string][]byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()

	expiration := time.Now().Add(ttl)
	for key, value := range items {
		mc.items[key] = &cacheItem{
			value:      value,
			expiration: expiration,
		}
	}

	return nil
}

// Stats returns cache statistics
func (mc *MemoryCache) Stats(ctx context.Context) (*Stats, error) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	totalHits := mc.stats.Hits + mc.stats.Misses
	hitRate := float64(0)
	if totalHits > 0 {
		hitRate = float64(mc.stats.Hits) / float64(totalHits)
	}

	size := mc.currentSize()
	keys := int64(len(mc.items))
	avgSize := int64(0)
	if keys > 0 {
		avgSize = size / keys
	}

	return &Stats{
		Hits:        mc.stats.Hits,
		Misses:      mc.stats.Misses,
		Evictions:   mc.stats.Evictions,
		Size:        size,
		Keys:        keys,
		HitRate:     hitRate,
		Memory:      size,
		AvgItemSize: avgSize,
		Uptime:      time.Since(mc.startTime),
	}, nil
}

// Close closes the cache (stops cleanup loop)
func (mc *MemoryCache) Close() error {
	close(mc.stopClean)
	return nil
}

// currentSize calculates current cache size in bytes
func (mc *MemoryCache) currentSize() int64 {
	var size int64
	for key, item := range mc.items {
		size += int64(len(key) + len(item.value))
	}
	return size
}

// evictOldest removes oldest expired items
func (mc *MemoryCache) evictOldest() {
	now := time.Now()
	var oldestKey string
	var oldestTime time.Time

	for key, item := range mc.items {
		if now.After(item.expiration) {
			delete(mc.items, key)
			mc.stats.Evictions++
			return
		}

		if oldestTime.IsZero() || item.expiration.Before(oldestTime) {
			oldestKey = key
			oldestTime = item.expiration
		}
	}

	if oldestKey != "" {
		delete(mc.items, oldestKey)
		mc.stats.Evictions++
	}
}

// cleanupLoop periodically removes expired items
func (mc *MemoryCache) cleanupLoop() {
	ticker := time.NewTicker(mc.cleanupInt)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mc.cleanup()
		case <-mc.stopClean:
			return
		}
	}
}

// cleanup removes all expired items
func (mc *MemoryCache) cleanup() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	now := time.Now()
	for key, item := range mc.items {
		if now.After(item.expiration) {
			delete(mc.items, key)
			mc.stats.Evictions++
		}
	}
}
