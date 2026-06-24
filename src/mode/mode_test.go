package mode

import (
	"testing"
)

// TestModeConstants verifies the string values of the Mode constants.
func TestModeConstants(t *testing.T) {
	if Production != "production" {
		t.Errorf("Production = %q, want %q", Production, "production")
	}
	if Development != "development" {
		t.Errorf("Development = %q, want %q", Development, "development")
	}
}

// TestIsValid_Production confirms Production is valid.
func TestIsValid_Production(t *testing.T) {
	if !IsValid(Production) {
		t.Error("IsValid(Production) = false, want true")
	}
}

// TestIsValid_Development confirms Development is valid.
func TestIsValid_Development(t *testing.T) {
	if !IsValid(Development) {
		t.Error("IsValid(Development) = false, want true")
	}
}

// TestIsValid_Invalid confirms unknown strings are not valid.
func TestIsValid_Invalid(t *testing.T) {
	cases := []string{"", "staging", "test", "PRODUCTION", "Production"}
	for _, c := range cases {
		if IsValid(Mode(c)) {
			t.Errorf("IsValid(%q) = true, want false", c)
		}
	}
}

// TestMode_String verifies String() returns the underlying string value.
func TestMode_String(t *testing.T) {
	cases := []struct {
		mode Mode
		want string
	}{
		{Production, "production"},
		{Development, "development"},
		{Mode("custom"), "custom"},
	}
	for _, tc := range cases {
		got := tc.mode.String()
		if got != tc.want {
			t.Errorf("Mode(%q).String() = %q, want %q", tc.mode, got, tc.want)
		}
	}
}
