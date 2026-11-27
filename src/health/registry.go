// Package health provides cached, ordered checks for runtime data sets and
// optional dependencies.
package health

import (
	"sync"
	"time"
)

const refreshInterval = time.Minute

type CheckFunc func() string

type Result struct {
	Key      string
	Critical bool
	Status   string
}

type entry struct {
	key      string
	critical bool
	check    CheckFunc
	status   string
}

var registry = struct {
	sync.RWMutex
	entries []*entry
	byKey   map[string]*entry
}{byKey: make(map[string]*entry)}

var refreshOnce sync.Once

// Register adds or replaces a check while preserving the first registration
// position for its key. The initial result is cached before returning.
func Register(key string, critical bool, check CheckFunc) {
	if key == "" || check == nil {
		return
	}
	result := validStatus(check())
	registry.Lock()
	if existing := registry.byKey[key]; existing != nil {
		existing.critical = critical
		existing.check = check
		existing.status = result
	} else {
		registered := &entry{key: key, critical: critical, check: check, status: result}
		registry.entries = append(registry.entries, registered)
		registry.byKey[key] = registered
	}
	registry.Unlock()
	refreshOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(refreshInterval)
			defer ticker.Stop()
			for range ticker.C {
				Refresh()
			}
		}()
	})
}

// Refresh updates all cached results. It is called periodically and after a
// data set reload or update.
func Refresh() {
	registry.RLock()
	type checkSnapshot struct {
		entry *entry
		check CheckFunc
	}
	checks := make([]checkSnapshot, 0, len(registry.entries))
	for _, item := range registry.entries {
		checks = append(checks, checkSnapshot{entry: item, check: item.check})
	}
	registry.RUnlock()
	for _, check := range checks {
		status := validStatus(check.check())
		registry.Lock()
		check.entry.status = status
		registry.Unlock()
	}
}

// Snapshot returns the cached results in registration order. It never invokes
// a check or touches the filesystem or network.
func Snapshot() []Result {
	registry.RLock()
	defer registry.RUnlock()
	results := make([]Result, 0, len(registry.entries))
	for _, check := range registry.entries {
		results = append(results, Result{Key: check.key, Critical: check.critical, Status: check.status})
	}
	return results
}

func validStatus(status string) string {
	switch status {
	case "ok", "degraded", "error":
		return status
	default:
		return "error"
	}
}
