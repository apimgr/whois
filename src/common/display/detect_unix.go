//go:build !windows
// +build !windows

package display

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// detectPlatformDisplay - Unix/macOS display detection
func (e *DisplayEnv) detectPlatformDisplay() {
	// Check for Wayland first (preferred on Linux)
	if waylandDisplay := os.Getenv("WAYLAND_DISPLAY"); waylandDisplay != "" {
		e.HasDisplay = true
		e.DisplayType = "wayland"
		return
	}

	// Check for X11
	if display := os.Getenv("DISPLAY"); display != "" {
		e.HasDisplay = true
		e.DisplayType = "x11"
		return
	}

	// macOS always has a display (unless SSH)
	if runtime.GOOS == "darwin" && !e.IsSSH && !e.IsMosh {
		// Check if we have access to the WindowServer
		cmd := exec.Command("launchctl", "list")
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), "com.apple.WindowServer") {
			e.HasDisplay = true
			e.DisplayType = "macos"
			return
		}
	}

	e.HasDisplay = false
	e.DisplayType = "none"
}
