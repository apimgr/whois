package service

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/apimgr/whois/src/common/constants"
)

// detectServiceManagerFn is the service-manager detection implementation.
// Tests may replace this variable to simulate different init systems.
var detectServiceManagerFn = detectServiceManagerImpl

// isContainerFn is the container-detection implementation used inside
// detectServiceManagerImpl; tests may replace it to bypass container checks.
var isContainerFn = IsContainer

// containerFilesCheckFn checks for well-known container indicator files.
// Tests may replace this variable to bypass the file-based detection.
var containerFilesCheckFn = defaultContainerFilesCheck

// defaultContainerFilesCheck checks for /.dockerenv, /run/.containerenv, and /dev/lxc.
func defaultContainerFilesCheck() bool {
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
	return false
}

// IsContainer returns true if running inside a container
func IsContainer() bool {
	// File-based detection across Docker, Podman, and LXC/LXD/Incus.
	if containerFilesCheckFn() {
		return true
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
	case constants.InternalName:
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

// detectServiceManagerImpl contains the real service-manager detection logic.
func detectServiceManagerImpl() string {
	// Check for container environment first
	if isContainerFn() {
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

	// OpenRC: /sbin/openrc-run binary present, or RC_SVCNAME env is set
	if _, err := os.Stat("/sbin/openrc-run"); err == nil {
		return "openrc"
	}
	if _, err := os.Stat("/usr/sbin/openrc-run"); err == nil {
		return "openrc"
	}
	if os.Getenv("RC_SVCNAME") != "" {
		return "openrc"
	}

	// SysV init: /etc/init.d script, no systemd, no OpenRC
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

// DetectServiceManager returns the active service manager.
// It delegates to detectServiceManagerFn so that tests can replace the
// implementation without modifying production paths.
func DetectServiceManager() string {
	return detectServiceManagerFn()
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
		switch detectServiceManagerFn() {
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
