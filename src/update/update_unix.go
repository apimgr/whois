//go:build !windows
// +build !windows

package update

import (
	"fmt"
	"os"
	"syscall"
)

// replaceBinary replaces the running binary (Unix)
// On Unix, we can replace a running binary - the old binary stays in memory
// until the process exits, then the new one takes over on next start
// Per AI.md PART 22 specification
func replaceBinary(currentPath, newBinaryPath string) error {
	// Get current binary permissions
	info, err := os.Stat(currentPath)
	if err != nil {
		return fmt.Errorf("failed to stat current binary: %w", err)
	}

	// Create backup of current binary
	backupPath := currentPath + ".old"
	if err := os.Rename(currentPath, backupPath); err != nil {
		return fmt.Errorf("failed to backup current binary: %w", err)
	}

	// Move new binary to current path
	if err := os.Rename(newBinaryPath, currentPath); err != nil {
		// Restore backup on failure
		os.Rename(backupPath, currentPath)
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	// Restore permissions
	if err := os.Chmod(currentPath, info.Mode()); err != nil {
		return fmt.Errorf("failed to restore permissions: %w", err)
	}

	// Remove backup
	os.Remove(backupPath)

	return nil
}

// restartSelf re-executes the current process (Unix)
// syscall.Exec replaces the current process
// Per AI.md PART 22 specification
func restartSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	// syscall.Exec replaces the current process
	return syscall.Exec(exe, os.Args, os.Environ())
}
