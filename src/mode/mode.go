// Package mode tracks the application operating mode (AI.md PART 6).
package mode

import (
	"os"
	"runtime"
	"strings"

	"github.com/apimgr/whois/src/config"
)

var (
	currentMode  = Production
	debugEnabled = false
)

// AppMode represents the application operating mode.
type AppMode int

const (
	// Production is the default mode — minimal logging, strict security.
	Production AppMode = iota
	// Development enables verbose logging, relaxed CORS, debug endpoints.
	Development
)

// String returns the string representation of the mode.
func (m AppMode) String() string {
	switch m {
	case Development:
		return "development"
	default:
		return "production"
	}
}

// SetAppMode sets the application mode.
func SetAppMode(m string) {
	switch strings.ToLower(m) {
	case "dev", "devel", "development":
		currentMode = Development
	case "debug":
		// Alias: development mode + debug on
		// (an explicit --debug flag or DEBUG env var still wins)
		currentMode = Development
		SetDebugEnabled(true)
	default:
		currentMode = Production
	}
	updateAppModeProfilingSettings()
}

// SetDebugEnabled enables or disables debug mode.
func SetDebugEnabled(enabled bool) {
	debugEnabled = enabled
	updateAppModeProfilingSettings()
}

// updateAppModeProfilingSettings enables/disables profiling based on the debug flag.
func updateAppModeProfilingSettings() {
	if debugEnabled {
		// Enable profiling when debug is on
		runtime.SetBlockProfileRate(1)
		runtime.SetMutexProfileFraction(1)
	} else {
		// Disable profiling when debug is off
		runtime.SetBlockProfileRate(0)
		runtime.SetMutexProfileFraction(0)
	}
}

// GetCurrentAppMode returns the current application mode.
func GetCurrentAppMode() AppMode {
	return currentMode
}

// IsAppModeDev returns true if in development mode.
func IsAppModeDev() bool {
	return currentMode == Development
}

// IsAppModeProd returns true if in production mode.
func IsAppModeProd() bool {
	return currentMode == Production
}

// IsDebugEnabled returns true if debug mode is enabled (--debug or DEBUG=true).
func IsDebugEnabled() bool {
	return debugEnabled
}

// GetAppModeString returns the mode string with a debug suffix if enabled.
func GetAppModeString() string {
	s := currentMode.String()
	if debugEnabled {
		s += " [debugging]"
	}
	return s
}

// FromEnv sets mode and debug from environment variables.
// MODE=debug is an alias for development mode + debug on, but an
// explicitly set DEBUG env var (truthy OR falsy) always wins over the
// alias — MODE=debug DEBUG=false runs development mode with debug off.
// The --debug CLI flag (applied after this) wins over both.
func FromEnv() {
	if m := os.Getenv("MODE"); m != "" {
		SetAppMode(m)
	}
	// LookupEnv distinguishes "explicitly set" from "unset": an unset
	// DEBUG leaves the alias result alone; a set DEBUG overrides it
	if v, set := os.LookupEnv("DEBUG"); set {
		SetDebugEnabled(config.IsTruthy(v))
	}
}
