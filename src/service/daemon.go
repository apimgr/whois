package service

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// IsContainer returns true if running inside a container
func IsContainer() bool {
	// File-based detection across Docker, Podman, and LXC/LXD/Incus.
	containerFiles := []string{
		"/.dockerenv",
		"/run/.containerenv",
		"/dev/lxc",
	}
	for _, f := range containerFiles {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}

	// Generic container detection (systemd-nspawn, lxc, etc.)
	if os.Getenv("container") != "" {
		return true
	}
	// Kubernetes pods always have this variable set by the kubelet.
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}

	// Check parent process name for container init systems
	parentName := getParentProcessName()
	switch parentName {
	case "tini", "dumb-init", "s6-svscan", "runsv", "runsvdir", "catatonit":
		return true
	case "caswhois":
		// Parent is our own binary - likely container entrypoint
		return true
	}

	// Check cgroup for container indicators
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") ||
			strings.Contains(content, "kubepods") ||
			strings.Contains(content, "lxc") {
			return true
		}
	}

	return false
}

// DetectServiceManager returns the active service manager
func DetectServiceManager() string {
	// Check for container environment first
	if IsContainer() {
		return "container"
	}

	// Check parent process / init system
	ppid := os.Getppid()

	// systemd: parent is systemd or PPID=1 with systemd running
	if ppid == 1 {
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			return "systemd"
		}
	}
	// Also check INVOCATION_ID (set by systemd)
	if os.Getenv("INVOCATION_ID") != "" {
		return "systemd"
	}

	// launchd: macOS with PPID=1
	if runtime.GOOS == "darwin" && ppid == 1 {
		return "launchd"
	}

	// runit: check for SVDIR
	if os.Getenv("SVDIR") != "" {
		return "runit"
	}

	// s6: check for S6_* vars
	if os.Getenv("S6_LOGGING") != "" {
		return "s6"
	}

	// SysV init: /etc/init.d script, no systemd
	if ppid == 1 {
		if _, err := os.Stat("/etc/init.d"); err == nil {
			if _, err := os.Stat("/run/systemd/system"); os.IsNotExist(err) {
				return "sysv"
			}
		}
	}

	// rc.d (BSD): check for rc.subr
	if _, err := os.Stat("/etc/rc.subr"); err == nil {
		return "rcd"
	}

	return "manual"
}

// getParentProcessName returns the name of the parent process
func getParentProcessName() string {
	ppid := os.Getppid()

	// Linux: read /proc/{ppid}/comm
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", ppid)); err == nil {
		return strings.TrimSpace(string(data))
	}

	// macOS/BSD: use ps command
	cmd := exec.Command("ps", "-p", strconv.Itoa(ppid), "-o", "comm=")
	if output, err := cmd.Output(); err == nil {
		return strings.TrimSpace(string(output))
	}

	return ""
}

// ShouldDaemonize determines if we should daemonize based on context
func ShouldDaemonize(isServiceStart bool, daemonFlag bool, configDaemonize bool) bool {
	if isServiceStart {
		// Service start - detect manager and ignore config
		switch DetectServiceManager() {
		case "systemd", "launchd", "runit", "s6", "container":
			// Always foreground
			return false
		case "sysv", "rcd":
			// Always daemonize
			return true
		default:
			// Unknown, default to foreground
			return false
		}
	}

	// Manual start - respect flag and config
	if daemonFlag {
		return true
	}
	return configDaemonize
}

// filterDaemonFlag removes --daemon flag from args to prevent loop
func filterDaemonFlag(args []string) []string {
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != "--daemon" && arg != "-d" {
			filtered = append(filtered, arg)
		}
	}
	return filtered
}
