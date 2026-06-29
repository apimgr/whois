package display

import "os"

// DisplayMode represents the display mode
type DisplayMode int

const (
	// ModeCLI is used when a command is provided or output is piped/redirected
	ModeCLI DisplayMode = iota
	// ModeTUI is used when running interactively with no command args
	ModeTUI
	// ModePlain is used for non-TTY environments (scripts, cron, pipes)
	ModePlain
)

// isTTYFunc is the TTY detection function; overridable in tests.
var isTTYFunc = defaultIsTTY

// defaultIsTTY checks if stdout is connected to a terminal
func defaultIsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// Detect returns the appropriate display mode based on terminal state and whether a command was given
func Detect(hasCommand bool) DisplayMode {
	if !isTTYFunc() {
		return ModePlain
	}
	if hasCommand {
		return ModeCLI
	}
	return ModeTUI
}
