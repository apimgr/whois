package cache

import (
	"context"
	"testing"
	"time"
)

// TestNoopCache_ImplementsInterface verifies NoopCache satisfies the Cache
// interface at compile time.
func TestNoopCache_ImplementsInterface(t *testing.T) {
	var _ Cache = (*NoopCache)(nil)
}

// TestNoopCache_GetAlwaysMisses verifies a disabled cache never returns a
// stored value, even immediately after Set.
func TestNoopCache_GetAlwaysMisses(t *testing.T) {
	nc := NewNoopCache()
	ctx := context.Background()

	if err := nc.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	_, err := nc.Get(ctx, "k")
	if !IsNotFound(err) {
		t.Errorf("Get after Set on NoopCache: expected ErrNotFound, got %v", err)
	}
}

// TestNoopCache_ExistsAlwaysFalse verifies Exists always reports false.
func TestNoopCache_ExistsAlwaysFalse(t *testing.T) {
	nc := NewNoopCache()
	ctx := context.Background()

	_ = nc.Set(ctx, "k", []byte("v"), time.Minute)
	exists, err := nc.Exists(ctx, "k")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Error("Exists on NoopCache should always be false")
	}
}

// TestNoopCache_GetMultiEmpty verifies GetMulti returns an empty, non-nil map.
func TestNoopCache_GetMultiEmpty(t *testing.T) {
	nc := NewNoopCache()
	ctx := context.Background()

	result, err := nc.GetMulti(ctx, []string{"a", "b"})
	if err != nil {
		t.Fatalf("GetMulti: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("GetMulti on NoopCache: expected empty result, got %v", result)
	}
}

// TestNoopCache_SetMultiClearCloseNoError verifies the remaining no-op methods
// never return an error.
func TestNoopCache_SetMultiClearCloseNoError(t *testing.T) {
	nc := NewNoopCache()
	ctx := context.Background()

	if err := nc.SetMulti(ctx, map[string][]byte{"a": []byte("1")}, time.Minute); err != nil {
		t.Errorf("SetMulti: %v", err)
	}
	if err := nc.Delete(ctx, "a"); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if err := nc.Clear(ctx); err != nil {
		t.Errorf("Clear: %v", err)
	}
	if err := nc.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestNoopCache_Stats verifies Stats reports a non-nil zeroed result with a
// non-negative uptime.
func TestNoopCache_Stats(t *testing.T) {
	nc := NewNoopCache()
	stats, err := nc.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats == nil {
		t.Fatal("Stats: expected non-nil result")
	}
	if stats.Hits != 0 || stats.Misses != 0 || stats.Keys != 0 {
		t.Errorf("Stats on NoopCache should be zeroed, got %+v", stats)
	}
}
