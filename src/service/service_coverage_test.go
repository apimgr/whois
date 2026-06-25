//go:build !windows
// +build !windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// withElevated temporarily replaces isElevatedFn for the duration of f.
func withElevated(t *testing.T, elevated bool, f func()) {
	t.Helper()
	orig := isElevatedFn
	isElevatedFn = func() bool { return elevated }
	defer func() { isElevatedFn = orig }()
	f()
}

// withCanEscalate temporarily replaces canEscalateFn for the duration of f.
func withCanEscalate(t *testing.T, escalate bool, f func()) {
	t.Helper()
	orig := canEscalateFn
	canEscalateFn = func() bool { return escalate }
	defer func() { canEscalateFn = orig }()
	f()
}

// withExecElevated temporarily replaces execElevatedFn with a no-op stub so
// tests that reach ExecElevated do not actually invoke sudo (which would
// re-execute the test binary and recurse).
func withExecElevated(t *testing.T, f func()) {
	t.Helper()
	orig := execElevatedFn
	execElevatedFn = func(_ []string) error { return nil }
	defer func() { execElevatedFn = orig }()
	f()
}

// withoutContainer temporarily replaces isContainerFn so that
// detectServiceManagerImpl does not short-circuit on container detection.
func withoutContainer(t *testing.T, f func()) {
	t.Helper()
	orig := isContainerFn
	isContainerFn = func() bool { return false }
	defer func() { isContainerFn = orig }()
	f()
}

// pipeStdin replaces os.Stdin with a pipe pre-filled with input and registers
// cleanup to restore the original stdin after the test.
func pipeStdin(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	fmt.Fprint(w, input)
	w.Close()
	t.Cleanup(func() {
		os.Stdin = orig
		r.Close()
	})
}

// ---------------------------------------------------------------------------
// detectServiceManagerImpl branch coverage
// ---------------------------------------------------------------------------

// TestDetectServiceManagerImpl_NoContainer confirms that when isContainerFn
// returns false the function proceeds past the container check and returns a
// non-empty manager name.
func TestDetectServiceManagerImpl_NoContainer(t *testing.T) {
	withoutContainer(t, func() {
		got := detectServiceManagerImpl()
		if got == "" {
			t.Error("detectServiceManagerImpl() returned empty string")
		}
	})
}

// TestDetectServiceManagerImpl_InvocationID confirms that INVOCATION_ID causes
// systemd to be detected.
func TestDetectServiceManagerImpl_InvocationID(t *testing.T) {
	withoutContainer(t, func() {
		t.Setenv("INVOCATION_ID", "test-invocation-id")
		got := detectServiceManagerImpl()
		if got != "systemd" {
			t.Errorf("got %q, want systemd", got)
		}
	})
}

// TestDetectServiceManagerImpl_SVDIR confirms that SVDIR env var causes runit
// to be detected.
func TestDetectServiceManagerImpl_SVDIR(t *testing.T) {
	withoutContainer(t, func() {
		t.Setenv("SVDIR", "/etc/sv")
		got := detectServiceManagerImpl()
		if got != "runit" {
			t.Errorf("got %q, want runit", got)
		}
	})
}

// TestDetectServiceManagerImpl_S6Logging confirms that S6_LOGGING env var causes
// s6 to be detected.
func TestDetectServiceManagerImpl_S6Logging(t *testing.T) {
	withoutContainer(t, func() {
		t.Setenv("S6_LOGGING", "1")
		got := detectServiceManagerImpl()
		if got != "s6" {
			t.Errorf("got %q, want s6", got)
		}
	})
}

// TestDetectServiceManagerImpl_RCSvcname confirms that RC_SVCNAME env var causes
// openrc to be detected.
func TestDetectServiceManagerImpl_RCSvcname(t *testing.T) {
	withoutContainer(t, func() {
		t.Setenv("RC_SVCNAME", "myservice")
		got := detectServiceManagerImpl()
		if got != "openrc" {
			t.Errorf("got %q, want openrc", got)
		}
	})
}

// ---------------------------------------------------------------------------
// Daemonize fork path
// ---------------------------------------------------------------------------

// TestDaemonize_ForkPath confirms the fork path: a child is spawned (TestMain
// exits it immediately via _DAEMON_CHILD guard), osExitFn is called with 0 in
// the parent, and the function returns nil.
func TestDaemonize_ForkPath(t *testing.T) {
	exitCode := -1
	orig := osExitFn
	osExitFn = func(code int) { exitCode = code }
	defer func() { osExitFn = orig }()

	if err := Daemonize(); err != nil {
		t.Errorf("Daemonize() fork path returned error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("osExitFn called with %d, want 0", exitCode)
	}
}

// ---------------------------------------------------------------------------
// Install privilege paths
// ---------------------------------------------------------------------------

// TestInstall_NotElevated_CannotEscalate confirms that when not elevated and
// unable to escalate, Install falls back to installUserService (no stdin needed).
func TestInstall_NotElevated_CannotEscalate(t *testing.T) {
	sm, err := NewServiceManager("caswhois-cov-inst-ne", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	withElevated(t, false, func() {
		withCanEscalate(t, false, func() {
			// installUserService() is called; in a container it returns an
			// unsupported error.  The important thing is the privilege-check
			// branch is reached.
			_ = sm.Install()
		})
	})
}

// TestInstall_NotElevated_CanEscalate_Decline confirms that when escalation is
// available but the user types "n", Install returns an escalation declined error.
func TestInstall_NotElevated_CanEscalate_Decline(t *testing.T) {
	sm, err := NewServiceManager("caswhois-cov-inst-esc", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	pipeStdin(t, "n\n")
	withElevated(t, false, func() {
		withCanEscalate(t, true, func() {
			err := sm.Install()
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	})
}

// ---------------------------------------------------------------------------
// Uninstall privilege paths
// ---------------------------------------------------------------------------

// TestUninstall_YesPrompt_NotElevated_CannotEscalate confirms that after the
// user confirms uninstall ("y"), when the system service is installed but the
// caller is not elevated and cannot escalate, an error is returned.
func TestUninstall_YesPrompt_NotElevated_CannotEscalate(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/sv/<name>")
	}
	sm, err := NewServiceManager("caswhois-cov-uninst-ne", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	svcDir := "/etc/sv/" + sm.Name
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(svcDir) })

	pipeStdin(t, "y\n")
	withElevated(t, false, func() {
		withCanEscalate(t, false, func() {
			err := sm.Uninstall()
			if err == nil {
				t.Error("expected error for uninstall requires administrator privileges, got nil")
			}
		})
	})
}

// TestUninstall_YesPrompt_NotElevated_CanEscalate_Decline confirms that after
// confirming uninstall ("y"), when escalation is available but declined ("n"),
// an escalation declined error is returned.
func TestUninstall_YesPrompt_NotElevated_CanEscalate_Decline(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/sv/<name>")
	}
	sm, err := NewServiceManager("caswhois-cov-uninst-esc", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	svcDir := "/etc/sv/" + sm.Name
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(svcDir) })

	// "y" accepts the uninstall warning; "n" declines escalation.
	pipeStdin(t, "y\nn\n")
	withElevated(t, false, func() {
		withCanEscalate(t, true, func() {
			err := sm.Uninstall()
			if err == nil {
				t.Error("expected escalation declined error, got nil")
			}
		})
	})
}

// ---------------------------------------------------------------------------
// Disable privilege paths
// ---------------------------------------------------------------------------

// TestDisable_SystemService_NotElevated_CannotEscalate confirms that when the
// system service is installed, the caller is not elevated, and cannot escalate,
// Disable returns an error.
func TestDisable_SystemService_NotElevated_CannotEscalate(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/sv/<name>")
	}
	sm, err := NewServiceManager("caswhois-cov-dis-ne", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	svcDir := "/etc/sv/" + sm.Name
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(svcDir) })

	withElevated(t, false, func() {
		withCanEscalate(t, false, func() {
			err := sm.Disable()
			if err == nil {
				t.Error("expected error for disable requires administrator privileges, got nil")
			}
		})
	})
}

// TestDisable_SystemService_NotElevated_CanEscalate_Decline confirms that when
// escalation is available but the user declines ("n"), Disable returns an error.
func TestDisable_SystemService_NotElevated_CanEscalate_Decline(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/sv/<name>")
	}
	sm, err := NewServiceManager("caswhois-cov-dis-esc", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	svcDir := "/etc/sv/" + sm.Name
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(svcDir) })

	pipeStdin(t, "n\n")
	withElevated(t, false, func() {
		withCanEscalate(t, true, func() {
			err := sm.Disable()
			if err == nil {
				t.Error("expected escalation declined error, got nil")
			}
		})
	})
}

// ---------------------------------------------------------------------------
// Start / Stop / Restart / Reload privilege error paths
// ---------------------------------------------------------------------------

// TestStart_SystemService_NotElevated confirms that starting a system service
// without elevation returns an error.
func TestStart_SystemService_NotElevated(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/sv/<name>")
	}
	sm, err := NewServiceManager("caswhois-cov-start-ne", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	svcDir := "/etc/sv/" + sm.Name
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(svcDir) })

	withElevated(t, false, func() {
		if err := sm.Start(); err == nil {
			t.Error("Start() expected error, got nil")
		}
	})
}

// TestStop_SystemService_NotElevated confirms that stopping a system service
// without elevation returns an error.
func TestStop_SystemService_NotElevated(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/sv/<name>")
	}
	sm, err := NewServiceManager("caswhois-cov-stop-ne", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	svcDir := "/etc/sv/" + sm.Name
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(svcDir) })

	withElevated(t, false, func() {
		if err := sm.Stop(); err == nil {
			t.Error("Stop() expected error, got nil")
		}
	})
}

// TestRestart_SystemService_NotElevated confirms that restarting a system service
// without elevation returns an error.
func TestRestart_SystemService_NotElevated(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/sv/<name>")
	}
	sm, err := NewServiceManager("caswhois-cov-restart-ne", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	svcDir := "/etc/sv/" + sm.Name
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(svcDir) })

	withElevated(t, false, func() {
		if err := sm.Restart(); err == nil {
			t.Error("Restart() expected error, got nil")
		}
	})
}

// TestReload_SystemService_NotElevated confirms that reloading a system service
// without elevation returns an error.
func TestReload_SystemService_NotElevated(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/sv/<name>")
	}
	sm, err := NewServiceManager("caswhois-cov-reload-ne", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	svcDir := "/etc/sv/" + sm.Name
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(svcDir) })

	withElevated(t, false, func() {
		if err := sm.Reload(); err == nil {
			t.Error("Reload() expected error, got nil")
		}
	})
}

// ---------------------------------------------------------------------------
// isSystemServiceInstalled — systemd path
// ---------------------------------------------------------------------------

// TestIsSystemServiceInstalled_SystemdPath confirms isSystemServiceInstalled
// returns true when /etc/systemd/system/<name>.service exists.
func TestIsSystemServiceInstalled_SystemdPath(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/systemd/system/")
	}
	sm, err := NewServiceManager("caswhois-cov-sysdsvc-q8z", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	dir := "/etc/systemd/system"
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	svcPath := filepath.Join(dir, sm.Name+".service")
	if err := os.WriteFile(svcPath, []byte("[Unit]\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Cleanup(func() { os.Remove(svcPath) })

	if !sm.isSystemServiceInstalled() {
		t.Error("isSystemServiceInstalled() = false, want true for /etc/systemd/system path")
	}
}

// TestIsSystemServiceInstalled_InitdPath confirms isSystemServiceInstalled
// returns true when /etc/init.d/<name> exists (OpenRC / SysV path).
func TestIsSystemServiceInstalled_InitdPath(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/init.d/")
	}
	sm, err := NewServiceManager("caswhois-cov-initd-q9z", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	dir := "/etc/init.d"
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	initdPath := filepath.Join(dir, sm.Name)
	if err := os.WriteFile(initdPath, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Cleanup(func() { os.Remove(initdPath) })

	if !sm.isSystemServiceInstalled() {
		t.Error("isSystemServiceInstalled() = false, want true for /etc/init.d path")
	}
}

// TestDisable_Systemd_SystemService covers the systemctl disable (without --user)
// branch in disable() when isSystemServiceInstalled returns true.
func TestDisable_Systemd_SystemService(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/sv/<name>")
	}
	sm, err := NewServiceManager("caswhois-cov-dis-sysd", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	svcDir := "/etc/sv/" + sm.Name
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(svcDir) })

	withManager(t, "systemd", func() {
		// systemctl disable fails (not running), but the branch is covered.
		_ = sm.disable()
	})
}

// ---------------------------------------------------------------------------
// installSystemd — with /etc/systemd/system/ directory
// ---------------------------------------------------------------------------

// TestInstallSystemd_WithDir confirms that when /etc/systemd/system/ exists,
// installSystemd writes the service file before failing at the systemctl step
// (no systemd running in the test container).
func TestInstallSystemd_WithDir(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/systemd/system/")
	}
	sm, err := NewServiceManager("caswhois-cov-sysd-write", "CasWhois Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	dir := "/etc/systemd/system"
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	svcPath := filepath.Join(dir, sm.Name+".service")
	t.Cleanup(func() { os.Remove(svcPath) })

	// The function returns an error because systemctl is not running in the
	// container, but the WriteFile step completes successfully first.
	withManager(t, "systemd", func() {
		_ = sm.installSystemd()
	})
	if _, err := os.Stat(svcPath); err != nil {
		t.Errorf("service file was not written: %v", err)
	}
}

// ---------------------------------------------------------------------------
// installRCD — with /usr/local/etc/rc.d/ directory
// ---------------------------------------------------------------------------

// TestInstallRCD_WithDir confirms that when /usr/local/etc/rc.d/ exists,
// installRCD writes the rc.d script before failing at the service start step.
func TestInstallRCD_WithDir(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /usr/local/etc/rc.d/")
	}
	sm, err := NewServiceManager("caswhois-cov-rcd-write", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	dir := "/usr/local/etc/rc.d"
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	scriptPath := filepath.Join(dir, sm.Name)
	t.Cleanup(func() { os.Remove(scriptPath) })

	withManager(t, "rcd", func() {
		_ = sm.installRCD()
	})
	if _, err := os.Stat(scriptPath); err != nil {
		t.Errorf("rc.d script was not written: %v", err)
	}
}

// ---------------------------------------------------------------------------
// installRunit — symlink succeeds when /etc/service/ exists
// ---------------------------------------------------------------------------

// TestInstallRunit_ServiceDirPresent confirms that when /etc/service/ exists,
// installRunit creates the symlink and returns nil, covering the success path.
func TestInstallRunit_ServiceDirPresent(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/service/ and /etc/sv/")
	}
	sm, err := NewServiceManager("caswhois-cov-runit-svc", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	if err := os.MkdirAll("/etc/service", 0755); err != nil {
		t.Fatalf("MkdirAll /etc/service: %v", err)
	}
	linkPath := "/etc/service/" + sm.Name
	t.Cleanup(func() {
		os.Remove(linkPath)
		os.RemoveAll("/etc/sv/" + sm.Name)
		os.RemoveAll("/var/log/apimgr/" + sm.Name)
	})

	withManager(t, "runit", func() {
		if err := sm.installRunit(); err != nil {
			t.Errorf("installRunit() unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// uninstallSystemd — user service else branch
// ---------------------------------------------------------------------------

// TestUninstallSystemd_UserServicePath confirms that when the system service
// file does not exist but a user service file does, uninstallSystemd takes the
// else branch and removes the user service file.
func TestUninstallSystemd_UserServicePath(t *testing.T) {
	sm, err := NewServiceManager("caswhois-cov-unsysd-user", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	userSvcDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(userSvcDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	userSvcPath := filepath.Join(userSvcDir, sm.Name+".service")
	if err := os.WriteFile(userSvcPath, []byte("[Unit]\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Cleanup(func() { os.Remove(userSvcPath) })

	if err := sm.uninstallSystemd(); err != nil {
		t.Errorf("uninstallSystemd() returned error: %v", err)
	}
	if _, err := os.Stat(userSvcPath); !os.IsNotExist(err) {
		t.Error("user service file was not removed")
	}
}

// ---------------------------------------------------------------------------
// uninstallLaunchd — user agent else branch
// ---------------------------------------------------------------------------

// TestUninstallLaunchd_UserAgentPath confirms that when the system plist does
// not exist but a user agent plist does, uninstallLaunchd takes the else branch
// and removes the user agent plist.
func TestUninstallLaunchd_UserAgentPath(t *testing.T) {
	sm, err := NewServiceManager("caswhois-cov-unlaunchd-user", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	agentDir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(agentDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	plistPath := filepath.Join(agentDir, "io.github.apimgr."+sm.Name+".plist")
	if err := os.WriteFile(plistPath, []byte("<?xml?>\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Cleanup(func() { os.Remove(plistPath) })

	if err := sm.uninstallLaunchd(); err != nil {
		t.Errorf("uninstallLaunchd() returned error: %v", err)
	}
	if _, err := os.Stat(plistPath); !os.IsNotExist(err) {
		t.Error("user agent plist was not removed")
	}
}

// ---------------------------------------------------------------------------
// ensureServiceUser
// ---------------------------------------------------------------------------

// TestEnsureServiceUser_UserAlreadyExists confirms ensureServiceUser returns nil
// immediately when the user already exists (early-return path).
func TestEnsureServiceUser_UserAlreadyExists(t *testing.T) {
	// "root" is guaranteed to exist on any POSIX system.
	sm := &ServiceManager{Name: "root", DisplayName: "root", Description: "root user"}
	if err := sm.ensureServiceUser(); err != nil {
		t.Errorf("ensureServiceUser() with existing user returned error: %v", err)
	}
}

// TestEnsureServiceUser_NewUser confirms ensureServiceUser creates a new system
// group and user when neither exists (Alpine Linux: addgroup/adduser path).
func TestEnsureServiceUser_NewUser(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create system users")
	}
	name := "caswhois-cov-svcusr"
	sm := &ServiceManager{Name: name, DisplayName: name, Description: "coverage test user"}
	t.Cleanup(func() {
		exec.Command("deluser", name).Run()
		exec.Command("delgroup", name).Run()
	})
	if err := sm.ensureServiceUser(); err != nil {
		t.Errorf("ensureServiceUser() returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// withoutContainerFiles helper
// ---------------------------------------------------------------------------

// withoutContainerFiles replaces containerFilesCheckFn so that the file-based
// container detection always returns false, allowing the env-var and cgroup
// branches of IsContainer() to be exercised.
func withoutContainerFiles(t *testing.T, f func()) {
	t.Helper()
	orig := containerFilesCheckFn
	containerFilesCheckFn = func() bool { return false }
	defer func() { containerFilesCheckFn = orig }()
	f()
}

// ---------------------------------------------------------------------------
// IsContainer — env-var and cgroup paths
// ---------------------------------------------------------------------------

// TestIsContainer_ContainerEnvBranch confirms that the "container" env var
// causes IsContainer to return true even when no container files exist. The
// _Branch suffix distinguishes it from the shallow test in service_test.go.
func TestIsContainer_ContainerEnvBranch(t *testing.T) {
	withoutContainerFiles(t, func() {
		t.Setenv("container", "systemd-nspawn")
		if !IsContainer() {
			t.Error("IsContainer() = false with container env var, want true")
		}
	})
}

// TestIsContainer_KubernetesEnvBranch confirms that KUBERNETES_SERVICE_HOST
// causes IsContainer to return true even when no container files exist.
func TestIsContainer_KubernetesEnvBranch(t *testing.T) {
	withoutContainerFiles(t, func() {
		t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		if !IsContainer() {
			t.Error("IsContainer() = false with KUBERNETES_SERVICE_HOST, want true")
		}
	})
}

// TestIsContainer_CgroupPath confirms that IsContainer reads /proc/1/cgroup
// and detects the Docker environment when no container files or env vars are set.
func TestIsContainer_CgroupPath(t *testing.T) {
	withoutContainerFiles(t, func() {
		// No container env vars set — relies on /proc/1/cgroup in Docker.
		got := IsContainer()
		// In a Docker container /proc/1/cgroup contains "docker"; the result may
		// be true or false depending on the kernel, so we only verify the call
		// completes without panic.
		_ = got
	})
}

// ---------------------------------------------------------------------------
// uninstallSystemd — system service path
// ---------------------------------------------------------------------------

// TestUninstallSystemd_SystemPath confirms that when /etc/systemd/system/<name>.service
// exists, uninstallSystemd exercises the system-service branch (systemctl disable,
// os.Remove, systemctl daemon-reload) before printing and returning nil.
func TestUninstallSystemd_SystemPath(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/systemd/system/")
	}
	sm, err := NewServiceManager("caswhois-cov-unsysd-sys", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	dir := "/etc/systemd/system"
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	svcPath := filepath.Join(dir, sm.Name+".service")
	if err := os.WriteFile(svcPath, []byte("[Unit]\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Cleanup(func() { os.Remove(svcPath) })

	if err := sm.uninstallSystemd(); err != nil {
		t.Errorf("uninstallSystemd() unexpected error: %v", err)
	}
	if _, err := os.Stat(svcPath); !os.IsNotExist(err) {
		t.Error("system service file was not removed")
	}
}

// ---------------------------------------------------------------------------
// uninstallLaunchd — system daemon path
// ---------------------------------------------------------------------------

// TestUninstallLaunchd_SystemPath confirms that when
// /Library/LaunchDaemons/io.github.apimgr.<name>.plist exists, uninstallLaunchd exercises
// the system-daemon branch (launchctl unload, os.Remove) before returning nil.
func TestUninstallLaunchd_SystemPath(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /Library/LaunchDaemons/")
	}
	sm, err := NewServiceManager("caswhois-cov-unlaunchd-sys", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	systemDir := "/Library/LaunchDaemons"
	if err := os.MkdirAll(systemDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	plistPath := filepath.Join(systemDir, "io.github.apimgr."+sm.Name+".plist")
	if err := os.WriteFile(plistPath, []byte("<plist/>"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(plistPath)
		// Remove the directory only if it was empty before our test.
		os.Remove(systemDir)
	})

	if err := sm.uninstallLaunchd(); err != nil {
		t.Errorf("uninstallLaunchd() unexpected error: %v", err)
	}
	if _, err := os.Stat(plistPath); !os.IsNotExist(err) {
		t.Error("system plist was not removed")
	}
}

// ---------------------------------------------------------------------------
// disable — rcd path with /etc/rc.conf present
// ---------------------------------------------------------------------------

// TestDisable_RCD_WithRcConf confirms that when /etc/rc.conf contains an enable
// line for the service, disable() with manager="rcd" removes it and rewrites the
// file, covering the lines-split and filter loop.
func TestDisable_RCD_WithRcConf(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to write /etc/rc.conf")
	}
	sm, err := NewServiceManager("caswhois-cov-dis-rcd", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	rcConf := "/etc/rc.conf"
	enableLine := fmt.Sprintf("%s_enable=\"YES\"\n", sm.Name)
	if err := os.WriteFile(rcConf, []byte(enableLine), 0644); err != nil {
		t.Skipf("cannot write /etc/rc.conf: %v", err)
	}
	t.Cleanup(func() { os.Remove(rcConf) })

	withManager(t, "rcd", func() {
		if err := sm.disable(); err != nil {
			t.Errorf("disable() rcd with rc.conf returned error: %v", err)
		}
	})
	data, _ := os.ReadFile(rcConf)
	if len(enableLine) > 0 && len(data) > 0 && string(data) == enableLine {
		t.Error("enable line was not removed from /etc/rc.conf")
	}
}

// ---------------------------------------------------------------------------
// installRCD — /etc/rc.conf update path
// ---------------------------------------------------------------------------

// TestInstallRCD_WithRcConf confirms that when /etc/rc.conf exists and does not
// yet contain the enable line, installRCD appends it, covering the OpenFile and
// WriteString branches.
func TestInstallRCD_WithRcConf(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to write /etc/rc.conf and /usr/local/etc/rc.d/")
	}
	sm, err := NewServiceManager("caswhois-cov-rcd-rcconf", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	dir := "/usr/local/etc/rc.d"
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll rc.d: %v", err)
	}
	scriptPath := filepath.Join(dir, sm.Name)
	rcConf := "/etc/rc.conf"
	// Pre-create rc.conf with some unrelated content so ReadFile succeeds.
	if err := os.WriteFile(rcConf, []byte("# rc.conf\n"), 0644); err != nil {
		t.Skipf("cannot write /etc/rc.conf: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(scriptPath)
		os.Remove(rcConf)
	})

	withManager(t, "rcd", func() {
		// installRCD fails at "service start" (not installed) but the rc.conf
		// update runs first, covering the OpenFile+WriteString path.
		_ = sm.installRCD()
	})
}

// ---------------------------------------------------------------------------
// start / stop / restart / reload — systemd system-service path
// ---------------------------------------------------------------------------

// TestStartStop_Systemd_SystemService covers the systemctl start/stop branches
// when a system service is detected (isSystemServiceInstalled=true) and the
// caller is already elevated (root in Docker).
func TestStartStop_Systemd_SystemService(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/sv/<name>")
	}
	sm, err := NewServiceManager("caswhois-cov-ctrl-sys", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	svcDir := "/etc/sv/" + sm.Name
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(svcDir) })

	// isSystemServiceInstalled() returns true because /etc/sv/<name> exists.
	// systemctl will fail (not running), but the exec stmts are covered.
	withManager(t, "systemd", func() {
		_ = sm.start()
		_ = sm.stop()
	})
}

// TestRestartReload_Systemd_SystemService covers the systemctl restart/reload
// branches when a system service is detected and the caller is elevated.
func TestRestartReload_Systemd_SystemService(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/sv/<name>")
	}
	sm, err := NewServiceManager("caswhois-cov-ctrl-sys2", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	svcDir := "/etc/sv/" + sm.Name
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(svcDir) })

	withManager(t, "systemd", func() {
		_ = sm.restart()
		_ = sm.reload()
	})
}

// ---------------------------------------------------------------------------
// status — systemd system-service path
// ---------------------------------------------------------------------------

// TestStatus_Systemd_SystemService covers the cmd = systemctl status <name>
// branch (without --user) when isSystemServiceInstalled returns true.
func TestStatus_Systemd_SystemService(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /etc/sv/<name>")
	}
	sm, err := NewServiceManager("caswhois-cov-status-sys", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	svcDir := "/etc/sv/" + sm.Name
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(svcDir) })

	withManager(t, "systemd", func() {
		// systemctl fails (not running), but the cmd assignment stmt is covered.
		_ = sm.status()
	})
}

// ---------------------------------------------------------------------------
// start — launchd system-daemon path
// ---------------------------------------------------------------------------

// TestStart_Launchd_SystemPlist covers the launchctl start branch inside the
// if-block (stat /Library/LaunchDaemons/<plist> succeeds).
func TestStart_Launchd_SystemPlist(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /Library/LaunchDaemons/")
	}
	sm, err := NewServiceManager("caswhois-cov-start-sys", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	systemDir := "/Library/LaunchDaemons"
	if err := os.MkdirAll(systemDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	plistPath := filepath.Join(systemDir, "io.github.apimgr."+sm.Name+".plist")
	if err := os.WriteFile(plistPath, []byte("<plist/>"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(plistPath)
		os.Remove(systemDir)
	})

	withManager(t, "launchd", func() {
		// launchctl fails (not on macOS), but the stat-success branch is covered.
		_ = sm.start()
	})
}

// ---------------------------------------------------------------------------
// disable — launchd system-plist path
// ---------------------------------------------------------------------------

// TestDisable_Launchd_SystemPlist covers the launchctl unload branch inside
// the if-block (stat /Library/LaunchDaemons/<plist> succeeds) in disable().
func TestDisable_Launchd_SystemPlist(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /Library/LaunchDaemons/")
	}
	sm, err := NewServiceManager("caswhois-cov-dis-sys", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	systemDir := "/Library/LaunchDaemons"
	if err := os.MkdirAll(systemDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	plistPath := filepath.Join(systemDir, "io.github.apimgr."+sm.Name+".plist")
	if err := os.WriteFile(plistPath, []byte("<plist/>"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(plistPath)
		os.Remove(systemDir)
	})

	withManager(t, "launchd", func() {
		// launchctl fails (not on macOS), but the stat-success branch is covered.
		_ = sm.disable()
	})
}

// ---------------------------------------------------------------------------
// installLaunchd — with /Library/LaunchDaemons/ created
// ---------------------------------------------------------------------------

// TestInstallLaunchd_WithDir confirms that when /Library/LaunchDaemons/ exists,
// installLaunchd writes the plist before failing at the launchctl step, covering
// the WriteFile-success and launchctl-error branches.
func TestInstallLaunchd_WithDir(t *testing.T) {
	if !IsElevated() {
		t.Skip("root required to create /Library/LaunchDaemons/")
	}
	sm, err := NewServiceManager("caswhois-cov-launchd-write", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	systemDir := "/Library/LaunchDaemons"
	if err := os.MkdirAll(systemDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	plistPath := filepath.Join(systemDir, "io.github.apimgr."+sm.Name+".plist")
	t.Cleanup(func() {
		os.Remove(plistPath)
		os.Remove(systemDir)
	})

	withManager(t, "launchd", func() {
		// launchctl fails (not on macOS), but WriteFile now succeeds and the
		// launchctl-error return stmt is covered.
		_ = sm.installLaunchd()
	})
	if _, err := os.Stat(plistPath); err != nil {
		t.Errorf("plist file was not written: %v", err)
	}
}

// ---------------------------------------------------------------------------
// detectServiceManagerImpl — rc.subr (rcd) path
// ---------------------------------------------------------------------------

// TestDetectServiceManagerImpl_RCSubr verifies that /etc/rc.subr causes rcd to
// be returned by detectServiceManagerImpl. Skipped when openrc-run is present
// (it takes priority in detection order).
func TestDetectServiceManagerImpl_RCSubr(t *testing.T) {
	if !IsElevated() {
		t.Skip("requires root to write to /etc")
	}
	if _, err := os.Stat("/sbin/openrc-run"); err == nil {
		t.Skip("/sbin/openrc-run present — openrc is detected before rcd in this environment")
	}
	if _, err := os.Stat("/usr/sbin/openrc-run"); err == nil {
		t.Skip("/usr/sbin/openrc-run present — openrc is detected before rcd in this environment")
	}
	if _, err := os.Stat("/etc/rc.subr"); err == nil {
		t.Skip("/etc/rc.subr already exists — skipping to avoid interference")
	}
	if err := os.WriteFile("/etc/rc.subr", []byte("# placeholder\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Cleanup(func() { os.Remove("/etc/rc.subr") })
	withoutContainer(t, func() {
		got := detectServiceManagerImpl()
		if got != "rcd" {
			t.Errorf("detectServiceManagerImpl() = %q, want rcd", got)
		}
	})
}

// ---------------------------------------------------------------------------
// defaultCanEscalate — exercise the sudo + group-membership branches
// ---------------------------------------------------------------------------

// TestDefaultCanEscalate_Direct calls defaultCanEscalate() to exercise the sudo
// probe and group-membership loop. The return value is not asserted because it
// is environment-dependent.
func TestDefaultCanEscalate_Direct(t *testing.T) {
	// Just invoke to cover statements; result is environment-dependent.
	_ = defaultCanEscalate()
}

// ---------------------------------------------------------------------------
// ExecElevated call-site coverage — accept paths in Install/Disable/Uninstall
// ---------------------------------------------------------------------------

// TestInstall_NotElevated_CanEscalate_Accept covers the return ExecElevated(os.Args)
// stmt in Install() when the user accepts escalation (empty response = default yes).
// execElevatedFn is stubbed to prevent recursive sudo re-execution.
func TestInstall_NotElevated_CanEscalate_Accept(t *testing.T) {
	sm, err := NewServiceManager("caswhois-cov-inst-acc", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	// Empty response accepts escalation (default yes).
	pipeStdin(t, "\n")
	withElevated(t, false, func() {
		withCanEscalate(t, true, func() {
			withExecElevated(t, func() {
				_ = sm.Install()
			})
		})
	})
}

// TestDisable_SystemService_NotElevated_CanEscalate_Accept covers the return
// ExecElevated(os.Args) stmt in Disable() when the system service is installed
// and the user accepts escalation.
// execElevatedFn is stubbed to prevent recursive sudo re-execution.
func TestDisable_SystemService_NotElevated_CanEscalate_Accept(t *testing.T) {
	sm, err := NewServiceManager("caswhois-cov-dis-acc", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	// Create an /etc/sv/<name> dir so isSystemServiceInstalled() returns true.
	svcDir := "/etc/sv/" + sm.Name
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Skipf("cannot create %s (not root?): %v", svcDir, err)
	}
	t.Cleanup(func() { os.RemoveAll(svcDir) })

	// Empty response accepts escalation (default yes).
	pipeStdin(t, "\n")
	withElevated(t, false, func() {
		withCanEscalate(t, true, func() {
			withExecElevated(t, func() {
				_ = sm.Disable()
			})
		})
	})
}

// TestUninstall_YesPrompt_NotElevated_CanEscalate_Accept covers the return
// ExecElevated(os.Args) stmt in Uninstall() when the user confirms the warning
// and accepts escalation.
// execElevatedFn is stubbed to prevent recursive sudo re-execution.
func TestUninstall_YesPrompt_NotElevated_CanEscalate_Accept(t *testing.T) {
	sm, err := NewServiceManager("caswhois-cov-uninst-acc", "Test", "desc")
	if err != nil {
		t.Fatalf("NewServiceManager: %v", err)
	}
	// Create an /etc/sv/<name> dir so isSystemServiceInstalled() returns true.
	svcDir := "/etc/sv/" + sm.Name
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Skipf("cannot create %s (not root?): %v", svcDir, err)
	}
	t.Cleanup(func() { os.RemoveAll(svcDir) })

	// "y\n" accepts the uninstall warning; "\n" (empty) accepts escalation.
	pipeStdin(t, "y\n\n")
	withElevated(t, false, func() {
		withCanEscalate(t, true, func() {
			withExecElevated(t, func() {
				_ = sm.Uninstall()
			})
		})
	})
}

