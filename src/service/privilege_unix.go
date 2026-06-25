//go:build !windows
// +build !windows

package service

import (
	"os"
	"os/exec"
	"os/user"
)

// isElevatedFn is the privilege-detection implementation; tests may replace it.
var isElevatedFn = defaultIsElevated

// canEscalateFn is the escalation-check implementation; tests may replace it.
var canEscalateFn = defaultCanEscalate

// defaultIsElevated returns true when the effective UID is 0 (Unix).
func defaultIsElevated() bool {
	return os.Geteuid() == 0
}

// IsElevated returns true if running as root (Unix).
func IsElevated() bool {
	return isElevatedFn()
}

// defaultCanEscalate contains the real privilege-escalation check implementation.
func defaultCanEscalate() bool {
	cmd := exec.Command("sudo", "-n", "true")
	if cmd.Run() == nil {
		return true
	}

	u, _ := user.Current()
	groups, _ := u.GroupIds()
	for _, gid := range groups {
		group, _ := user.LookupGroupId(gid)
		if group != nil && (group.Name == "sudo" || group.Name == "wheel" || group.Name == "admin") {
			return true
		}
	}
	return false
}

// CanEscalate checks if the current user can escalate privileges (Unix).
func CanEscalate() bool {
	return canEscalateFn()
}

// ExecElevated re-executes with elevated privileges (Unix).
func ExecElevated(args []string) error {
	sudoArgs := append([]string{args[0]}, args[1:]...)
	cmd := exec.Command("sudo", sudoArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
