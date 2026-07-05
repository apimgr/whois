// Package terminal provides terminal utilities wrapping golang.org/x/term.
package terminal

import (
	"os"

	"golang.org/x/term"
)

// IsTerminal returns true if fd is a terminal
func IsTerminal(fd int) bool {
	return term.IsTerminal(fd)
}

// IsStdoutTerminal returns true if stdout is a terminal
func IsStdoutTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// IsStdinTerminal returns true if stdin is a terminal
func IsStdinTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// IsStderrTerminal returns true if stderr is a terminal
func IsStderrTerminal() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// GetSize returns the visible dimensions of the terminal
func GetSize(fd int) (width, height int, err error) {
	return term.GetSize(fd)
}

// GetStdoutSize returns the visible dimensions of stdout
func GetStdoutSize() (width, height int, err error) {
	return term.GetSize(int(os.Stdout.Fd()))
}

// MakeRaw puts the terminal connected to fd into raw mode
func MakeRaw(fd int) (*term.State, error) {
	return term.MakeRaw(fd)
}

// Restore restores the terminal connected to fd to a previous state
func Restore(fd int, state *term.State) error {
	return term.Restore(fd, state)
}

// ReadPassword reads a password from the terminal without echoing
func ReadPassword(fd int) ([]byte, error) {
	return term.ReadPassword(fd)
}

// ReadPasswordFromStdin reads a password from stdin without echoing
func ReadPasswordFromStdin() ([]byte, error) {
	return term.ReadPassword(int(os.Stdin.Fd()))
}

// GetTerminalType returns the TERM environment variable
func GetTerminalType() string {
	return os.Getenv("TERM")
}

// IsDumbTerminal returns true if TERM is "dumb"
func IsDumbTerminal() bool {
	return os.Getenv("TERM") == "dumb"
}

// NoColorRequested returns true if NO_COLOR is set
func NoColorRequested() bool {
	return os.Getenv("NO_COLOR") != ""
}

// CanUseColors returns true if colors can be used
func CanUseColors() bool {
	if NoColorRequested() {
		return false
	}
	if IsDumbTerminal() {
		return false
	}
	return IsStdoutTerminal()
}
