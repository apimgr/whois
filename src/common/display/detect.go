// Package display provides display environment detection for CLI and server binaries.
package display

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// DisplayMode - UI display mode (NOT app mode)
type DisplayMode int

const (
	// DisplayModeHeadless - No display, no TTY
	DisplayModeHeadless DisplayMode = iota
	// DisplayModeCLI - Command-line only (piped or command provided)
	DisplayModeCLI
	// DisplayModeTUI - Terminal UI (interactive terminal)
	DisplayModeTUI
	// DisplayModeGUI - Native graphical UI
	DisplayModeGUI
)

// String returns the display mode name
func (m DisplayMode) String() string {
	switch m {
	case DisplayModeHeadless:
		return "headless"
	case DisplayModeCLI:
		return "cli"
	case DisplayModeTUI:
		return "tui"
	case DisplayModeGUI:
		return "gui"
	default:
		return "unknown"
	}
}

// DisplayEnv - detected display environment
type DisplayEnv struct {
	Mode DisplayMode
	// HasDisplay - X11, Wayland, Windows, macOS display
	HasDisplay bool
	// DisplayType - "x11", "wayland", "windows", "macos", "none"
	DisplayType string
	// IsTerminal - stdout is a TTY
	IsTerminal bool
	// IsSSH - Running over SSH
	IsSSH bool
	// IsMosh - Running over mosh
	IsMosh bool
	// IsScreen - Running in screen/tmux
	IsScreen bool
	// TerminalType - TERM value
	TerminalType string
	// Cols - Terminal columns (0 if no terminal)
	Cols int
	// Rows - Terminal rows (0 if no terminal)
	Rows int
}

// DetectDisplayEnv - auto-detect display environment
func DetectDisplayEnv() DisplayEnv {
	env := DisplayEnv{}

	// Terminal detection
	env.IsTerminal = term.IsTerminal(int(os.Stdout.Fd()))
	if env.IsTerminal {
		env.Cols, env.Rows, _ = term.GetSize(int(os.Stdout.Fd()))
	}
	env.TerminalType = os.Getenv("TERM")

	// Remote session detection
	env.IsSSH = os.Getenv("SSH_CLIENT") != "" || os.Getenv("SSH_TTY") != ""
	env.IsMosh = os.Getenv("MOSH") != "" || strings.Contains(os.Getenv("TERM"), "mosh")
	env.IsScreen = os.Getenv("STY") != "" || os.Getenv("TMUX") != ""

	// Platform-specific display detection
	env.detectPlatformDisplay()

	// Auto-detect display mode
	env.Mode = env.autoDetectDisplayMode()

	return env
}

// autoDetectDisplayMode - determine display mode from environment
func (e *DisplayEnv) autoDetectDisplayMode() DisplayMode {
	if !e.IsTerminal && !e.HasDisplay {
		return DisplayModeHeadless
	}
	// TERM=dumb: force CLI mode (no TUI, no ANSI escapes)
	if e.TerminalType == "dumb" {
		return DisplayModeCLI
	}
	if e.HasDisplay && !e.IsSSH && !e.IsMosh {
		return DisplayModeGUI
	}
	if e.IsTerminal {
		return DisplayModeTUI
	}
	return DisplayModeCLI
}

// IsDumbTerminal - check if running in dumb terminal (no ANSI support)
func (e *DisplayEnv) IsDumbTerminal() bool {
	return e.TerminalType == "dumb"
}

// IsAutoDetectDisplayModeGUI returns true if GUI mode detected
func (e DisplayEnv) IsAutoDetectDisplayModeGUI() bool { return e.Mode == DisplayModeGUI }

// IsAutoDetectDisplayModeTUI returns true if TUI mode detected
func (e DisplayEnv) IsAutoDetectDisplayModeTUI() bool { return e.Mode == DisplayModeTUI }

// IsAutoDetectDisplayModeCLI returns true if CLI mode detected
func (e DisplayEnv) IsAutoDetectDisplayModeCLI() bool { return e.Mode == DisplayModeCLI }

// IsAutoDetectDisplayModeHeadless returns true if headless mode detected
func (e DisplayEnv) IsAutoDetectDisplayModeHeadless() bool { return e.Mode == DisplayModeHeadless }

// CanUseANSI checks if ANSI features can be used
func CanUseANSI(env *DisplayEnv) bool {
	if env.IsDumbTerminal() {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return env.IsTerminal
}

// ShowProgress displays progress, falling back for dumb terminals
func ShowProgress(env *DisplayEnv, percent int) {
	if env.IsDumbTerminal() {
		fmt.Printf("%d%% complete\n", percent)
		return
	}
	// ANSI progress bar with cursor control
	fmt.Printf("\r[%-50s] %d%%", strings.Repeat("=", percent/2), percent)
}
