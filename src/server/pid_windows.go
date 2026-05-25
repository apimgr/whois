//go:build windows
// +build windows

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
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

// isProcessRunning checks if a process with given PID exists (Windows)
func isProcessRunning(pid int) bool {
	// Use OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION to check
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)

	// Get exit code - STILL_ACTIVE (259) means process is still running
	var exitCode uint32
	err = windows.GetExitCodeProcess(handle, &exitCode)
	return err == nil && exitCode == windows.STILL_ACTIVE
}

// isOurProcess verifies the process is actually our binary (Windows)
func isOurProcess(pid int) bool {
	// Use Windows API to get process image name
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)

	var buf [windows.MAX_PATH]uint16
	var size uint32 = windows.MAX_PATH
	err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
	if err != nil {
		return false
	}
	exePath := windows.UTF16ToString(buf[:size])
	baseName := strings.ToLower(filepath.Base(exePath))
	return strings.Contains(baseName, "caswhois") || strings.Contains(baseName, "whois")
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
	content := fmt.Sprintf("%d:%d\r\n", pid, port)
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
