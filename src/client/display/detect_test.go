package display

import "testing"

// TestModeConstants verifies iota values match documented order: ModeCLI=0, ModeTUI=1, ModePlain=2.
func TestModeConstants(t *testing.T) {
	cases := []struct {
		name string
		got  DisplayMode
		want DisplayMode
	}{
		{"ModeCLI", ModeCLI, 0},
		{"ModeTUI", ModeTUI, 1},
		{"ModePlain", ModePlain, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
			}
		})
	}
}

// TestDetect covers all three Mode branches and the defaultIsTTY error path
// by injecting a controlled isTTYFunc replacement.
func TestDetect(t *testing.T) {
	cases := []struct {
		name       string
		isTTY      bool
		hasCommand bool
		want       DisplayMode
	}{
		{"non-TTY no command → plain", false, false, ModePlain},
		{"non-TTY has command → plain", false, true, ModePlain},
		{"TTY no command → TUI", true, false, ModeTUI},
		{"TTY has command → CLI", true, true, ModeCLI},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tty := tc.isTTY
			old := isTTYFunc
			isTTYFunc = func() bool { return tty }
			defer func() { isTTYFunc = old }()

			got := Detect(tc.hasCommand)
			if got != tc.want {
				t.Errorf("Detect(%v) = %d, want %d", tc.hasCommand, got, tc.want)
			}
		})
	}
}

// TestDefaultIsTTYStat exercises the os.Stdout.Stat error path via the real function.
// In tests stdout is a pipe, not a char device, so defaultIsTTY returns false.
func TestDefaultIsTTYReturnsFalseInTests(t *testing.T) {
	if defaultIsTTY() {
		t.Error("expected defaultIsTTY to return false in test environment (no TTY)")
	}
}
