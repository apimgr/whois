//go:build !windows
// +build !windows

package server

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/apimgr/whois/src/common/constants"
)

// CheckPIDFile checks if PID file exists and if the process is still running
// Returns: (isRunning bool, pid int, err error)
func CheckPIDFile(pidPath string) (bool, int, error) {
	data, err := os.ReadFile(pidPath)
	if os.IsNotExist(err) {
		// No PID file, not running
		return false, 0, nil
	}
	if err != nil {
		return false, 0, fmt.Errorf("reading pid file: %w", err)
	}

	// Parse PID (format: PID or PID:PORT)
	pidStr := strings.TrimSpace(string(data))
	parts := strings.Split(pidStr, ":")
	pid, err := strconv.Atoi(parts[0])
	if err != nil {
		// Corrupt PID file - remove it
		os.Remove(pidPath)
		return false, 0, nil
	}

	// Check if process is running
	if !isProcessRunning(pid) {
		// Stale PID file - remove it
		os.Remove(pidPath)
		return false, 0, nil
	}

	// Process exists - verify it's actually our process (not PID reuse)
	if !isOurProcess(pid) {
		// PID was reused by another process - remove stale file
		os.Remove(pidPath)
		return false, 0, nil
	}

	return true, pid, nil
}

// isProcessRunning checks if a process with given PID exists (Unix)
func isProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds - need to send signal 0
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// isOurProcess verifies the process is actually our binary (Unix)
func isOurProcess(pid int) bool {
	// Read /proc/{pid}/exe symlink (Linux)
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		// On macOS/BSD, use ps command
		return isOurProcessDarwin(pid)
	}
	// Check if executable name contains the internal binary name.
	baseName := filepath.Base(exePath)
	return strings.Contains(baseName, constants.InternalName) || strings.Contains(baseName, "whois")
}

// isOurProcessDarwin checks process on macOS/BSD
func isOurProcessDarwin(pid int) bool {
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdName := strings.ToLower(string(output))
	return strings.Contains(cmdName, constants.InternalName) || strings.Contains(cmdName, "whois")
}

// WritePIDFile writes current process PID to file (with optional port)
func WritePIDFile(pidPath string, port int) error {
	// Check for existing running instance first
	running, existingPID, err := CheckPIDFile(pidPath)
	if err != nil {
		return err
	}
	if running {
		return fmt.Errorf("already running (pid %d)", existingPID)
	}

	// Ensure directory exists
	dir := filepath.Dir(pidPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create pid directory: %w", err)
	}

	// Write our PID with port (format: PID:PORT)
	pid := os.Getpid()
	content := fmt.Sprintf("%d:%d\n", pid, port)
	if err := os.WriteFile(pidPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write pid file: %w", err)
	}

	return nil
}

// RemovePIDFile removes PID file on shutdown
func RemovePIDFile(pidPath string) error {
	if err := os.Remove(pidPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove pid file: %w", err)
	}
	return nil
}
