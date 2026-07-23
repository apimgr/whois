//go:build !windows
// +build !windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
)

// isElevatedFn is the privilege-detection implementation; tests may replace it.
var isElevatedFn = defaultIsElevated

// canEscalateFn is the escalation-check implementation; tests may replace it.
var canEscalateFn = defaultCanEscalate

// execElevatedFn is the privilege-escalation implementation; tests may replace it.
var execElevatedFn = defaultExecElevated

// defaultIsElevated returns true when the effective UID is 0 (Unix).
func defaultIsElevated() bool {
	return os.Geteuid() == 0
}

// IsElevated returns true if running as root (Unix).
func IsElevated() bool {
	return isElevatedFn()
}

// escalationOrder returns the ordered list of escalation methods to try for
// the current OS, per AI.md PART 23: Linux tries sudo, su, pkexec, doas (in
// that order); BSD tries doas, sudo, su.
func escalationOrder() []string {
	switch runtime.GOOS {
	case "freebsd", "openbsd", "netbsd":
		return []string{"doas", "sudo", "su"}
	default:
		return []string{"sudo", "su", "pkexec", "doas"}
	}
}

// canUseMethod reports whether the given escalation method is usable on this
// system. sudo additionally accepts group-based access (sudo/wheel/admin)
// even without a cached passwordless credential, since the user will simply
// be prompted for a password.
func canUseMethod(method string) bool {
	switch method {
	case "sudo":
		if _, err := exec.LookPath("sudo"); err != nil {
			return false
		}
		if cmd := exec.Command("sudo", "-n", "true"); cmd.Run() == nil {
			return true
		}
		u, err := user.Current()
		if err != nil {
			return false
		}
		groups, _ := u.GroupIds()
		for _, gid := range groups {
			group, _ := user.LookupGroupId(gid)
			if group != nil && (group.Name == "sudo" || group.Name == "wheel" || group.Name == "admin") {
				return true
			}
		}
		return false
	case "su":
		_, err := exec.LookPath("su")
		return err == nil
	case "pkexec":
		_, err := exec.LookPath("pkexec")
		return err == nil
	case "doas":
		if _, err := exec.LookPath("doas"); err != nil {
			return false
		}
		if _, err := os.Stat("/etc/doas.conf"); err == nil {
			return true
		}
		// doas binary present without a config still gets attempted — doas
		// itself reports the configuration error to the user.
		return true
	default:
		return false
	}
}

// defaultCanEscalate contains the real privilege-escalation check implementation.
func defaultCanEscalate() bool {
	for _, method := range escalationOrder() {
		if canUseMethod(method) {
			return true
		}
	}
	return false
}

// CanEscalate checks if the current user can escalate privileges (Unix).
func CanEscalate() bool {
	return canEscalateFn()
}

// runElevated re-executes args using the given escalation method.
func runElevated(method string, args []string) error {
	var cmd *exec.Cmd
	switch method {
	case "sudo":
		cmd = exec.Command("sudo", args...)
	case "su":
		// su -c takes a single shell command string; quote each argument.
		quoted := make([]string, len(args))
		for i, a := range args {
			quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		cmd = exec.Command("su", "-c", strings.Join(quoted, " "))
	case "pkexec":
		cmd = exec.Command("pkexec", args...)
	case "doas":
		cmd = exec.Command("doas", args...)
	default:
		return fmt.Errorf("unsupported escalation method: %s", method)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// defaultExecElevated is the real privilege-escalation implementation. It
// tries each available escalation method in the OS-specific order until one
// succeeds at launching (not necessarily succeeding at the elevated command).
func defaultExecElevated(args []string) error {
	for _, method := range escalationOrder() {
		if !canUseMethod(method) {
			continue
		}
		return runElevated(method, args)
	}
	return fmt.Errorf("no privilege escalation method available (tried: %s)", strings.Join(escalationOrder(), ", "))
}

// ExecElevated re-executes with elevated privileges (Unix).
func ExecElevated(args []string) error {
	return execElevatedFn(args)
}
