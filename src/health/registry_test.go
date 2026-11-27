package health

import (
	"sync/atomic"
	"testing"
)

func TestRegistryCachesResultsAndPreservesRegistrationOrder(t *testing.T) {
	var calls atomic.Int32
	Register("test_dataset_first", false, func() string {
		calls.Add(1)
		return "ok"
	})
	Register("test_dataset_second", true, func() string { return "error" })
	if calls.Load() != 1 {
		t.Fatalf("initial check calls = %d, want 1", calls.Load())
	}
	results := Snapshot()
	if calls.Load() != 1 {
		t.Fatalf("snapshot ran a check; calls = %d", calls.Load())
	}
	first := -1
	second := -1
	for index, result := range results {
		switch result.Key {
		case "test_dataset_first":
			first = index
			if result.Status != "ok" || result.Critical {
				t.Errorf("first result = %+v", result)
			}
		case "test_dataset_second":
			second = index
			if result.Status != "error" || !result.Critical {
				t.Errorf("second result = %+v", result)
			}
		}
	}
	if first < 0 || second <= first {
		t.Fatalf("registration order indices = %d, %d", first, second)
	}
	Refresh()
	if calls.Load() != 2 {
		t.Fatalf("refresh calls = %d, want 2", calls.Load())
	}
}
