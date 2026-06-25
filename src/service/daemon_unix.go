//go:build !windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// osExitFn is the os.Exit implementation; tests may replace it to capture exits.
var osExitFn = os.Exit

// Daemonize forks the process and detaches from the controlling terminal.
// The parent exits; the child continues as a daemon process.
func Daemonize() error {
	// Already a daemon: parent is init (PID 1)
	if os.Getppid() == 1 {
		return nil
	}

	// Child re-entry: skip the fork and continue execution
	if os.Getenv("_DAEMON_CHILD") != "" {
		return nil
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("getting executable path: %w", err)
	}

	args := filterDaemonFlag(os.Args[1:])

	cmd := exec.Command(execPath, args...)
	cmd.Env = append(os.Environ(), "_DAEMON_CHILD=1")
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	// Create new session so the child is detached from the controlling terminal
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting daemon: %w", err)
	}

	fmt.Printf("Daemon started with PID %d\n", cmd.Process.Pid)
	osExitFn(0)
	return nil
}
