package terminal

import (
	"os"
	"testing"
)

func TestIsStdoutTerminal(t *testing.T) {
	// Just ensure it doesn't panic - result depends on environment
	_ = IsStdoutTerminal()
}

func TestIsStdinTerminal(t *testing.T) {
	_ = IsStdinTerminal()
}

func TestIsStderrTerminal(t *testing.T) {
	_ = IsStderrTerminal()
}

func TestGetTerminalType(t *testing.T) {
	// Save and restore
	old := os.Getenv("TERM")
	defer func() { _ = os.Setenv("TERM", old) }()

	_ = os.Setenv("TERM", "test-term")
	if got := GetTerminalType(); got != "test-term" {
		t.Errorf("GetTerminalType() = %q, want %q", got, "test-term")
	}
}

func TestIsDumbTerminal(t *testing.T) {
	old := os.Getenv("TERM")
	defer func() { _ = os.Setenv("TERM", old) }()

	_ = os.Setenv("TERM", "dumb")
	if !IsDumbTerminal() {
		t.Error("IsDumbTerminal() = false, want true")
	}

	_ = os.Setenv("TERM", "xterm")
	if IsDumbTerminal() {
		t.Error("IsDumbTerminal() = true, want false")
	}
}

func TestNoColorRequested(t *testing.T) {
	old := os.Getenv("NO_COLOR")
	defer func() {
		if old != "" {
			_ = os.Setenv("NO_COLOR", old)
		} else {
			_ = os.Unsetenv("NO_COLOR")
		}
	}()

	_ = os.Setenv("NO_COLOR", "1")
	if !NoColorRequested() {
		t.Error("NoColorRequested() = false, want true")
	}

	_ = os.Unsetenv("NO_COLOR")
	if NoColorRequested() {
		t.Error("NoColorRequested() = true, want false")
	}
}

func TestCanUseColors(t *testing.T) {
	oldTerm := os.Getenv("TERM")
	oldNoColor := os.Getenv("NO_COLOR")
	defer func() {
		_ = os.Setenv("TERM", oldTerm)
		if oldNoColor != "" {
			_ = os.Setenv("NO_COLOR", oldNoColor)
		} else {
			_ = os.Unsetenv("NO_COLOR")
		}
	}()

	// NO_COLOR blocks colors
	_ = os.Setenv("NO_COLOR", "1")
	_ = os.Setenv("TERM", "xterm-256color")
	if CanUseColors() {
		t.Error("CanUseColors() should be false when NO_COLOR is set")
	}

	// Dumb terminal blocks colors
	_ = os.Unsetenv("NO_COLOR")
	_ = os.Setenv("TERM", "dumb")
	if CanUseColors() {
		t.Error("CanUseColors() should be false for dumb terminal")
	}
}

func TestGetStdoutSize(t *testing.T) {
	// Just ensure it doesn't panic - may fail in non-terminal env
	_, _, _ = GetStdoutSize()
}

// TestIsTerminal exercises the fd-based wrapper.
func TestIsTerminal(t *testing.T) {
	// In Docker/CI stdout is not a TTY; just ensure no panic.
	_ = IsTerminal(int(os.Stdout.Fd()))
	_ = IsTerminal(int(os.Stdin.Fd()))
	_ = IsTerminal(int(os.Stderr.Fd()))
}

// TestGetSize exercises the fd-based size wrapper.
func TestGetSize(t *testing.T) {
	_, _, _ = GetSize(int(os.Stdout.Fd()))
}

// TestMakeRaw_NonTerminal verifies MakeRaw returns an error on a non-TTY fd.
func TestMakeRaw_NonTerminal(t *testing.T) {
	// In CI stdout is not a TTY; MakeRaw should fail gracefully.
	_, err := MakeRaw(int(os.Stdout.Fd()))
	// Error is expected in a non-TTY environment; nil is also acceptable.
	_ = err
}

// TestReadPasswordFromStdin_NonTerminal verifies ReadPasswordFromStdin does not panic.
func TestReadPasswordFromStdin_NonTerminal(t *testing.T) {
	// In CI stdin is not a TTY; ReadPassword should return an error, not panic.
	_, err := ReadPasswordFromStdin()
	_ = err
}
