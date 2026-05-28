package display

import "os"

// Mode represents the display mode
type Mode int

const (
	// ModeCLI is used when a command is provided or output is piped/redirected
	ModeCLI Mode = iota
	// ModeTUI is used when running interactively with no command args
	ModeTUI
	// ModePlain is used for non-TTY environments (scripts, cron, pipes)
	ModePlain
)

// isTTY checks if stdout is connected to a terminal
func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// Detect returns the appropriate display mode based on terminal state and whether a command was given
func Detect(hasCommand bool) Mode {
	if !isTTY() {
		return ModePlain
	}
	if hasCommand {
		return ModeCLI
	}
	return ModeTUI
}
