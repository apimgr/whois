//go:build windows
// +build windows

package update

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/windows"
)

// replaceBinary replaces the running binary (Windows)
// Windows cannot delete/rename a running executable, so we:
// 1. Rename current binary to .old
// 2. Move new binary to current path
// 3. Schedule .old for deletion on reboot (or delete after restart)
// Per AI.md PART 23 specification
func replaceBinary(currentPath, newBinaryPath string) error {
	oldPath := currentPath + ".old"

	// Remove any existing .old file from previous update
	os.Remove(oldPath)

	// Rename running binary to .old (this works on Windows)
	if err := os.Rename(currentPath, oldPath); err != nil {
		return fmt.Errorf("failed to rename current binary: %w", err)
	}

	// Move new binary to current path
	if err := os.Rename(newBinaryPath, currentPath); err != nil {
		// Try to restore original
		os.Rename(oldPath, currentPath)
		return fmt.Errorf("failed to move new binary: %w", err)
	}

	// Schedule old binary for deletion on reboot
	// MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT
	oldPathPtr, err := windows.UTF16PtrFromString(oldPath)
	if err == nil {
		// Ignore error - not critical
		windows.MoveFileEx(oldPathPtr, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}

	return nil
}

// restartSelf starts a new instance and exits (Windows)
// Windows doesn't support exec() replacement, so we spawn new process and exit
// Per AI.md PART 23 specification
func restartSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	// Start new process
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start new process: %w", err)
	}

	// Give the new process time to start
	time.Sleep(100 * time.Millisecond)

	// Exit current process
	os.Exit(0)
	return nil // unreachable
}
