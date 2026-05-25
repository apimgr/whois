//go:build !windows
// +build !windows

package service

import (
	"os"
	"os/exec"
	"os/user"
)

// IsElevated returns true if running as root (Unix)
func IsElevated() bool {
	return os.Geteuid() == 0
}

// CanEscalate checks if user can escalate privileges (Unix)
func CanEscalate() bool {
	// Check sudo -n (non-interactive) to see if user has sudo access
	cmd := exec.Command("sudo", "-n", "true")
	if cmd.Run() == nil {
		return true
	}

	// Check if user is in sudo/wheel/admin group
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

// ExecElevated re-executes with elevated privileges (Unix)
func ExecElevated(args []string) error {
	sudoArgs := append([]string{args[0]}, args[1:]...)
	cmd := exec.Command("sudo", sudoArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
