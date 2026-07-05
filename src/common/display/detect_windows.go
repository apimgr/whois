//go:build windows
// +build windows

package display

import (
	"os"
)

// detectPlatformDisplay - Windows display detection
func (e *DisplayEnv) detectPlatformDisplay() {
	// Windows always has a display unless running as a service
	// Check if we're running as a service by looking for typical service indicators
	if os.Getenv("SESSIONNAME") == "Services" {
		e.HasDisplay = false
		e.DisplayType = "none"
		return
	}

	// Check for remote desktop
	if os.Getenv("SESSIONNAME") == "RDP-Tcp#0" || os.Getenv("SESSIONNAME") != "" {
		e.HasDisplay = true
		e.DisplayType = "windows"
		return
	}

	// Console session
	e.HasDisplay = true
	e.DisplayType = "windows"
}
