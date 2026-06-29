package whois

import (
	"testing"
)

func TestNewLookupService(t *testing.T) {
	dataDir := t.TempDir()
	svc := NewLookupService(dataDir, nil)

	if svc == nil {
		t.Fatal("NewLookupService returned nil")
	}

	// Should not have RDAP data yet (no bootstrap files)
	if svc.HasRDAPData() {
		t.Error("HasRDAPData() = true before loading bootstrap")
	}
}

func TestLookupService_LoadBootstrap_Empty(t *testing.T) {
	dataDir := t.TempDir()
	svc := NewLookupService(dataDir, nil)

	// Load from empty directory should succeed
	if err := svc.LoadBootstrap(); err != nil {
		t.Errorf("LoadBootstrap() error = %v", err)
	}

	// Still no data
	if svc.HasRDAPData() {
		t.Error("HasRDAPData() = true after loading empty dir")
	}
}

func TestParseASNNumber(t *testing.T) {
	tests := []struct {
		input string
		want  uint32
	}{
		{"15169", 15169},
		{"AS15169", 15169},
		{"as15169", 15169},
		{"  AS15169  ", 15169},
		{"0", 0},
		{"invalid", 0},
		{"", 0},
	}

	for _, tt := range tests {
		got := parseASNNumber(tt.input)
		if got != tt.want {
			t.Errorf("parseASNNumber(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}
