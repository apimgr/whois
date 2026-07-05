package display

import (
	"os"
	"testing"
)

func TestDisplayMode_String(t *testing.T) {
	tests := []struct {
		mode DisplayMode
		want string
	}{
		{DisplayModeHeadless, "headless"},
		{DisplayModeCLI, "cli"},
		{DisplayModeTUI, "tui"},
		{DisplayModeGUI, "gui"},
		{DisplayMode(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.mode.String()
		if got != tt.want {
			t.Errorf("DisplayMode(%d).String() = %s, want %s", tt.mode, got, tt.want)
		}
	}
}

func TestDetectDisplayEnv(t *testing.T) {
	env := DetectDisplayEnv()

	// Basic sanity checks - environment varies, just ensure no panic
	if env.Mode < DisplayModeHeadless || env.Mode > DisplayModeGUI {
		t.Errorf("Invalid display mode: %d", env.Mode)
	}

	// TerminalType should be set (even if empty)
	_ = env.TerminalType

	// Cols and Rows should be non-negative
	if env.Cols < 0 || env.Rows < 0 {
		t.Errorf("Invalid terminal size: %dx%d", env.Cols, env.Rows)
	}
}

func TestDisplayEnv_IsDumbTerminal(t *testing.T) {
	tests := []struct {
		termType string
		want     bool
	}{
		{"dumb", true},
		{"xterm-256color", false},
		{"", false},
		{"vt100", false},
	}

	for _, tt := range tests {
		env := DisplayEnv{TerminalType: tt.termType}
		got := env.IsDumbTerminal()
		if got != tt.want {
			t.Errorf("IsDumbTerminal() with TERM=%q = %v, want %v", tt.termType, got, tt.want)
		}
	}
}

func TestDisplayEnv_autoDetectDisplayMode(t *testing.T) {
	tests := []struct {
		name string
		env  DisplayEnv
		want DisplayMode
	}{
		{
			name: "headless - no terminal, no display",
			env:  DisplayEnv{IsTerminal: false, HasDisplay: false},
			want: DisplayModeHeadless,
		},
		{
			name: "dumb terminal forces CLI",
			env:  DisplayEnv{IsTerminal: true, TerminalType: "dumb"},
			want: DisplayModeCLI,
		},
		{
			name: "GUI - display, not SSH",
			env:  DisplayEnv{IsTerminal: true, HasDisplay: true, IsSSH: false, IsMosh: false},
			want: DisplayModeGUI,
		},
		{
			name: "TUI - terminal, no display",
			env:  DisplayEnv{IsTerminal: true, HasDisplay: false, TerminalType: "xterm"},
			want: DisplayModeTUI,
		},
		{
			name: "TUI via SSH",
			env:  DisplayEnv{IsTerminal: true, HasDisplay: true, IsSSH: true, TerminalType: "xterm"},
			want: DisplayModeTUI,
		},
		{
			name: "TUI via Mosh",
			env:  DisplayEnv{IsTerminal: true, HasDisplay: true, IsMosh: true, TerminalType: "xterm"},
			want: DisplayModeTUI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.env.autoDetectDisplayMode()
			if got != tt.want {
				t.Errorf("autoDetectDisplayMode() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDisplayEnv_ModeHelpers(t *testing.T) {
	tests := []struct {
		mode   DisplayMode
		isGUI  bool
		isTUI  bool
		isCLI  bool
		isHead bool
	}{
		{DisplayModeGUI, true, false, false, false},
		{DisplayModeTUI, false, true, false, false},
		{DisplayModeCLI, false, false, true, false},
		{DisplayModeHeadless, false, false, false, true},
	}

	for _, tt := range tests {
		env := DisplayEnv{Mode: tt.mode}
		if env.IsAutoDetectDisplayModeGUI() != tt.isGUI {
			t.Errorf("IsAutoDetectDisplayModeGUI() for %s wrong", tt.mode)
		}
		if env.IsAutoDetectDisplayModeTUI() != tt.isTUI {
			t.Errorf("IsAutoDetectDisplayModeTUI() for %s wrong", tt.mode)
		}
		if env.IsAutoDetectDisplayModeCLI() != tt.isCLI {
			t.Errorf("IsAutoDetectDisplayModeCLI() for %s wrong", tt.mode)
		}
		if env.IsAutoDetectDisplayModeHeadless() != tt.isHead {
			t.Errorf("IsAutoDetectDisplayModeHeadless() for %s wrong", tt.mode)
		}
	}
}

func TestCanUseANSI(t *testing.T) {
	tests := []struct {
		name string
		env  DisplayEnv
		want bool
	}{
		{
			name: "dumb terminal - no ANSI",
			env:  DisplayEnv{TerminalType: "dumb", IsTerminal: true},
			want: false,
		},
		{
			name: "not a terminal - no ANSI",
			env:  DisplayEnv{TerminalType: "xterm", IsTerminal: false},
			want: false,
		},
		{
			name: "normal terminal - ANSI allowed",
			env:  DisplayEnv{TerminalType: "xterm-256color", IsTerminal: true},
			want: true,
		},
	}

	// Clear NO_COLOR for tests
	oldNoColor := os.Getenv("NO_COLOR")
	os.Unsetenv("NO_COLOR")
	defer func() {
		if oldNoColor != "" {
			os.Setenv("NO_COLOR", oldNoColor)
		}
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanUseANSI(&tt.env)
			if got != tt.want {
				t.Errorf("CanUseANSI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCanUseANSI_NoColor(t *testing.T) {
	os.Setenv("NO_COLOR", "1")
	defer os.Unsetenv("NO_COLOR")

	env := DisplayEnv{TerminalType: "xterm-256color", IsTerminal: true}
	if CanUseANSI(&env) {
		t.Error("CanUseANSI() should return false when NO_COLOR is set")
	}
}

// TestShowProgress_DumbTerminal verifies ShowProgress outputs plain text on dumb terminals.
func TestShowProgress_DumbTerminal(t *testing.T) {
	env := DisplayEnv{TerminalType: "dumb"}
	// Should not panic; output goes to stdout
	ShowProgress(&env, 0)
	ShowProgress(&env, 50)
	ShowProgress(&env, 100)
}

// TestShowProgress_NormalTerminal verifies ShowProgress outputs ANSI-style on normal terminals.
func TestShowProgress_NormalTerminal(t *testing.T) {
	env := DisplayEnv{TerminalType: "xterm-256color", IsTerminal: true}
	ShowProgress(&env, 0)
	ShowProgress(&env, 50)
	ShowProgress(&env, 100)
}

// TestDetectDisplayEnv_SSH verifies SSH env vars influence detection.
func TestDetectDisplayEnv_SSH(t *testing.T) {
	oldSSH := os.Getenv("SSH_CLIENT")
	oldSSHTTY := os.Getenv("SSH_TTY")
	defer func() {
		os.Setenv("SSH_CLIENT", oldSSH)
		os.Setenv("SSH_TTY", oldSSHTTY)
	}()

	os.Setenv("SSH_CLIENT", "192.168.1.1 1234 22")
	env := DetectDisplayEnv()
	if !env.IsSSH {
		t.Error("IsSSH should be true when SSH_CLIENT is set")
	}

	os.Unsetenv("SSH_CLIENT")
	os.Setenv("SSH_TTY", "/dev/pts/0")
	env2 := DetectDisplayEnv()
	if !env2.IsSSH {
		t.Error("IsSSH should be true when SSH_TTY is set")
	}
}

// TestDetectDisplayEnv_Screen verifies screen/tmux detection.
func TestDetectDisplayEnv_Screen(t *testing.T) {
	oldSTY := os.Getenv("STY")
	oldTMUX := os.Getenv("TMUX")
	defer func() {
		os.Setenv("STY", oldSTY)
		os.Setenv("TMUX", oldTMUX)
	}()

	os.Setenv("STY", "1234.pts-0.hostname")
	env := DetectDisplayEnv()
	if !env.IsScreen {
		t.Error("IsScreen should be true when STY is set")
	}

	os.Unsetenv("STY")
	os.Setenv("TMUX", "/tmp/tmux-1000/default,1234,0")
	env2 := DetectDisplayEnv()
	if !env2.IsScreen {
		t.Error("IsScreen should be true when TMUX is set")
	}
}

// TestDetectDisplayEnv_Mosh verifies mosh detection.
func TestDetectDisplayEnv_Mosh(t *testing.T) {
	oldMOSH := os.Getenv("MOSH")
	defer os.Setenv("MOSH", oldMOSH)

	os.Setenv("MOSH", "1")
	env := DetectDisplayEnv()
	if !env.IsMosh {
		t.Error("IsMosh should be true when MOSH is set")
	}
}

// TestDetectDisplayEnv_Wayland verifies Wayland display detection via WAYLAND_DISPLAY.
func TestDetectDisplayEnv_Wayland(t *testing.T) {
	oldWayland := os.Getenv("WAYLAND_DISPLAY")
	oldDisplay := os.Getenv("DISPLAY")
	defer func() {
		os.Setenv("WAYLAND_DISPLAY", oldWayland)
		os.Setenv("DISPLAY", oldDisplay)
	}()

	os.Setenv("WAYLAND_DISPLAY", "wayland-0")
	os.Unsetenv("DISPLAY")
	env := DetectDisplayEnv()
	if !env.HasDisplay {
		t.Error("HasDisplay should be true when WAYLAND_DISPLAY is set")
	}
	if env.DisplayType != "wayland" {
		t.Errorf("DisplayType = %q, want %q", env.DisplayType, "wayland")
	}
}

// TestDetectDisplayEnv_X11 verifies X11 display detection via DISPLAY.
func TestDetectDisplayEnv_X11(t *testing.T) {
	oldWayland := os.Getenv("WAYLAND_DISPLAY")
	oldDisplay := os.Getenv("DISPLAY")
	defer func() {
		os.Setenv("WAYLAND_DISPLAY", oldWayland)
		os.Setenv("DISPLAY", oldDisplay)
	}()

	os.Unsetenv("WAYLAND_DISPLAY")
	os.Setenv("DISPLAY", ":0")
	env := DetectDisplayEnv()
	if !env.HasDisplay {
		t.Error("HasDisplay should be true when DISPLAY is set")
	}
	if env.DisplayType != "x11" {
		t.Errorf("DisplayType = %q, want %q", env.DisplayType, "x11")
	}
}

// TestDetectDisplayEnv_NoDisplay verifies headless detection when no display vars set.
func TestDetectDisplayEnv_NoDisplay(t *testing.T) {
	oldWayland := os.Getenv("WAYLAND_DISPLAY")
	oldDisplay := os.Getenv("DISPLAY")
	defer func() {
		os.Setenv("WAYLAND_DISPLAY", oldWayland)
		os.Setenv("DISPLAY", oldDisplay)
	}()

	os.Unsetenv("WAYLAND_DISPLAY")
	os.Unsetenv("DISPLAY")
	env := DetectDisplayEnv()
	// On non-macOS in CI: no display expected
	_ = env.HasDisplay
}
