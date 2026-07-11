//go:build !windows
// +build !windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"github.com/apimgr/whois/src/common/constants"
)

// reservedIDs contains UIDs/GIDs used by well-known services across distros.
// These are never used even if they appear available on the current system.
// AI.md PART 23.
var reservedIDs = map[int]bool{
	65534: true,
	// systemd-*, docker, polkitd, tss and other common system services (980-999)
	999: true, 998: true, 997: true, 996: true, 995: true,
	994: true, 993: true, 992: true, 991: true, 990: true,
	989: true, 988: true, 987: true, 986: true, 985: true,
	984: true, 983: true, 982: true, 981: true, 980: true,
	// Common SSH/mail/IMAP services (101-110) and legacy DB servers (170-179)
	101: true, 102: true, 103: true, 104: true, 105: true,
	106: true, 107: true, 108: true, 109: true, 110: true,
	170: true, 171: true, 172: true, 173: true, 174: true,
	175: true, 176: true, 177: true, 178: true, 179: true,
}

// findAvailableSystemID finds an available UID/GID in the safe range 200-899.
// The returned value is usable for both UID and GID (they are always set to the
// same number per AI.md PART 23). AI.md PART 23.
func findAvailableSystemID() (int, error) {
	for id := 899; id >= 200; id-- {
		if reservedIDs[id] {
			continue
		}
		idStr := strconv.Itoa(id)
		if _, err := user.LookupId(idStr); err == nil {
			continue
		}
		if _, err := user.LookupGroupId(idStr); err == nil {
			continue
		}
		return id, nil
	}
	return 0, fmt.Errorf("no available UID/GID in safe range 200-899")
}

// ensureServiceUser creates the dedicated system group and user the server
// drops to after binding a privileged port (AI.md PART 23). The account has no
// login shell and no home directory. It is idempotent: an existing account is
// left untouched. Tool selection adapts to the distro (useradd/groupadd on
// glibc systems, adduser/addgroup on BusyBox/Alpine). UID and GID are chosen
// from the safe range 200-899, avoiding well-known service IDs (AI.md PART 23).
func (sm *ServiceManager) ensureServiceUser() error {
	if _, err := user.Lookup(sm.Name); err == nil {
		return nil
	}

	id, err := findAvailableSystemID()
	if err != nil {
		return fmt.Errorf("finding available UID/GID: %w", err)
	}
	idStr := strconv.Itoa(id)

	// Create the group first with the chosen GID.
	if _, err := user.LookupGroup(sm.Name); err != nil {
		if groupadd, lookErr := exec.LookPath("groupadd"); lookErr == nil {
			args := []string{"--system", "--gid", idStr, sm.Name}
			if out, runErr := exec.Command(groupadd, args...).CombinedOutput(); runErr != nil {
				return fmt.Errorf("groupadd %s: %w: %s", sm.Name, runErr, strings.TrimSpace(string(out)))
			}
		} else if addgroup, lookErr := exec.LookPath("addgroup"); lookErr == nil {
			args := []string{"-S", "-g", idStr, sm.Name}
			if out, runErr := exec.Command(addgroup, args...).CombinedOutput(); runErr != nil {
				return fmt.Errorf("addgroup %s: %w: %s", sm.Name, runErr, strings.TrimSpace(string(out)))
			}
		} else {
			return fmt.Errorf("no supported group creation tool found (groupadd/addgroup)")
		}
	}

	// Create the system user with the matching UID, same primary group, no shell/home.
	if useradd, lookErr := exec.LookPath("useradd"); lookErr == nil {
		args := []string{
			"--system", "--uid", idStr, "--gid", sm.Name,
			"--no-create-home", "--shell", "/sbin/nologin",
			"--comment", sm.Name + " service account",
			sm.Name,
		}
		if out, runErr := exec.Command(useradd, args...).CombinedOutput(); runErr != nil {
			return fmt.Errorf("useradd %s: %w: %s", sm.Name, runErr, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if adduser, lookErr := exec.LookPath("adduser"); lookErr == nil {
		args := []string{"-S", "-D", "-H", "-u", idStr, "-s", "/sbin/nologin", "-G", sm.Name, sm.Name}
		if out, runErr := exec.Command(adduser, args...).CombinedOutput(); runErr != nil {
			return fmt.Errorf("adduser %s: %w: %s", sm.Name, runErr, strings.TrimSpace(string(out)))
		}
		return nil
	}

	return fmt.Errorf("no supported user creation tool found (useradd/adduser)")
}

// installSystemService installs service as system service (requires root)
func (sm *ServiceManager) installSystemService() error {
	// Detect service manager
	manager := detectServiceManagerFn()

	// Create the dedicated unprivileged service account the binary drops to
	// after binding a privileged port (AI.md PART 23). launchd manages its own
	// accounts, so this only applies to the Linux init systems.
	switch manager {
	case "systemd", "openrc", "runit", "rcd":
		if err := sm.ensureServiceUser(); err != nil {
			return fmt.Errorf("creating service account: %w", err)
		}
	}

	switch manager {
	case "systemd":
		return sm.installSystemd()
	case "openrc":
		return sm.installOpenRC()
	case "runit":
		return sm.installRunit()
	case "rcd":
		return sm.installRCD()
	case "launchd":
		return sm.installLaunchd()
	case "container":
		return fmt.Errorf("cannot install service in container environment")
	default:
		return fmt.Errorf("unsupported service manager: %s", manager)
	}
}

// installUserService installs service as user service (no root)
func (sm *ServiceManager) installUserService() error {
	manager := detectServiceManagerFn()

	switch manager {
	case "systemd":
		return sm.installSystemdUser()
	case "launchd":
		return sm.installLaunchdUser()
	default:
		return fmt.Errorf("user service not supported on this system")
	}
}

// installSystemd installs systemd system service
func (sm *ServiceManager) installSystemd() error {
	servicePath := "/etc/systemd/system/" + sm.Name + ".service"

	content := fmt.Sprintf(`[Unit]
Description=%s
Documentation=https://`+constants.InternalOrg+`.github.io/%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening (binary drops privileges after port binding)
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/etc/`+constants.InternalOrg+`/%s
ReadWritePaths=/var/lib/`+constants.InternalOrg+`/%s
ReadWritePaths=/var/cache/`+constants.InternalOrg+`/%s
ReadWritePaths=/var/log/`+constants.InternalOrg+`/%s

[Install]
WantedBy=multi-user.target
`, sm.DisplayName, sm.Name, sm.BinaryPath, sm.Name, sm.Name, sm.Name, sm.Name)

	if err := os.WriteFile(servicePath, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing service file: %w", err)
	}

	// Reload systemd
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("reloading systemd: %w", err)
	}

	// Enable service
	if err := exec.Command("systemctl", "enable", sm.Name).Run(); err != nil {
		return fmt.Errorf("enabling service: %w", err)
	}

	// Start service
	if err := exec.Command("systemctl", "start", sm.Name).Run(); err != nil {
		return fmt.Errorf("starting service: %w", err)
	}

	fmt.Printf("Service installed and started: %s\n", sm.Name)
	fmt.Printf("Status: systemctl status %s\n", sm.Name)
	fmt.Printf("Logs: journalctl -u %s -f\n", sm.Name)
	return nil
}

// installSystemdUser installs systemd user service
func (sm *ServiceManager) installSystemdUser() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("getting home directory: %w", err)
	}

	serviceDir := home + "/.config/systemd/user"
	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		return fmt.Errorf("creating service directory: %w", err)
	}

	servicePath := serviceDir + "/" + sm.Name + ".service"

	content := fmt.Sprintf(`[Unit]
Description=%s (user service)
Documentation=https://`+constants.InternalOrg+`.github.io/%s

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`, sm.DisplayName, sm.Name, sm.BinaryPath)

	if err := os.WriteFile(servicePath, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing service file: %w", err)
	}

	// Reload systemd user
	exec.Command("systemctl", "--user", "daemon-reload").Run()

	// Enable service
	if err := exec.Command("systemctl", "--user", "enable", sm.Name).Run(); err != nil {
		return fmt.Errorf("enabling service: %w", err)
	}

	// Start service
	if err := exec.Command("systemctl", "--user", "start", sm.Name).Run(); err != nil {
		return fmt.Errorf("starting service: %w", err)
	}

	fmt.Printf("User service installed and started: %s\n", sm.Name)
	fmt.Printf("Status: systemctl --user status %s\n", sm.Name)
	fmt.Printf("Logs: journalctl --user -u %s -f\n", sm.Name)
	return nil
}

// installOpenRC installs an OpenRC init.d service (Alpine, Gentoo, Devuan).
// Installation path: /etc/init.d/{name} per AI.md PART 24.
func (sm *ServiceManager) installOpenRC() error {
	initPath := "/etc/init.d/" + sm.Name

	content := fmt.Sprintf(`#!/sbin/openrc-run
# Service identity: %s
name="%s"
description="%s"
command="%s"
command_args=""
command_user="%s:%s"
pidfile="/var/run/`+constants.InternalOrg+`/%s.pid"
command_background=true
output_log="/var/log/`+constants.InternalOrg+`/%s/server.log"
error_log="/var/log/`+constants.InternalOrg+`/%s/error.log"

depend() {
    need net
    after firewall
    use dns logger
}

start_pre() {
    checkpath -d -m 0755 -o %s:%s /var/run/`+constants.InternalOrg+`
    checkpath -d -m 0755 -o %s:%s /var/log/`+constants.InternalOrg+`/%s
}
`, sm.Name, sm.Name, sm.DisplayName, sm.BinaryPath,
		sm.Name, sm.Name, sm.Name, sm.Name, sm.Name,
		sm.Name, sm.Name, sm.Name, sm.Name, sm.Name)

	if err := os.WriteFile(initPath, []byte(content), 0755); err != nil {
		return fmt.Errorf("writing OpenRC init script: %w", err)
	}

	// Enable at boot
	if err := exec.Command("rc-update", "add", sm.Name, "default").Run(); err != nil {
		return fmt.Errorf("enabling OpenRC service: %w", err)
	}

	// Start service
	if err := exec.Command("rc-service", sm.Name, "start").Run(); err != nil {
		return fmt.Errorf("starting OpenRC service: %w", err)
	}

	fmt.Printf("Service installed and started: %s\n", sm.Name)
	fmt.Printf("Status: rc-service %s status\n", sm.Name)
	fmt.Printf("Logs: tail -f /var/log/"+constants.InternalOrg+"/%s/server.log\n", sm.Name)
	return nil
}

// installLaunchd installs launchd system daemon (macOS)
func (sm *ServiceManager) installLaunchd() error {
	plistPath := "/Library/LaunchDaemons/io.github." + constants.InternalOrg + "." + sm.Name + ".plist"

	content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>io.github.`+constants.InternalOrg+`.%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/var/log/`+constants.InternalOrg+`/%s/stdout.log</string>
	<key>StandardErrorPath</key>
	<string>/var/log/`+constants.InternalOrg+`/%s/stderr.log</string>
</dict>
</plist>
`, sm.Name, sm.BinaryPath, sm.Name, sm.Name)

	// Create log directory
	logDir := "/var/log/" + constants.InternalOrg + "/" + sm.Name
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("creating log directory: %w", err)
	}

	if err := os.WriteFile(plistPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing plist file: %w", err)
	}

	// Load and start service
	if err := exec.Command("launchctl", "load", plistPath).Run(); err != nil {
		return fmt.Errorf("loading service: %w", err)
	}

	fmt.Printf("Service installed and started: %s\n", sm.Name)
	fmt.Printf("Status: launchctl list | grep %s\n", sm.Name)
	fmt.Printf("Logs: tail -f %s\n", logDir+"/stdout.log")
	return nil
}

// installLaunchdUser installs launchd user agent (macOS)
func (sm *ServiceManager) installLaunchdUser() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("getting home directory: %w", err)
	}

	agentDir := home + "/Library/LaunchAgents"
	if err := os.MkdirAll(agentDir, 0755); err != nil {
		return fmt.Errorf("creating agent directory: %w", err)
	}

	plistPath := agentDir + "/io.github." + constants.InternalOrg + "." + sm.Name + ".plist"

	content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>io.github.`+constants.InternalOrg+`.%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
</dict>
</plist>
`, sm.Name, sm.BinaryPath)

	if err := os.WriteFile(plistPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing plist file: %w", err)
	}

	// Load and start service
	if err := exec.Command("launchctl", "load", plistPath).Run(); err != nil {
		return fmt.Errorf("loading service: %w", err)
	}

	fmt.Printf("User service installed and started: %s\n", sm.Name)
	fmt.Printf("Status: launchctl list | grep %s\n", sm.Name)
	return nil
}

// installRunit installs runit service
func (sm *ServiceManager) installRunit() error {
	serviceDir := "/etc/sv/" + sm.Name
	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		return fmt.Errorf("creating service directory: %w", err)
	}

	logDir := serviceDir + "/log"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("creating log directory: %w", err)
	}

	// Main run script
	runScript := fmt.Sprintf("#!/bin/sh\nexec %s 2>&1\n", sm.BinaryPath)
	runPath := serviceDir + "/run"
	if err := os.WriteFile(runPath, []byte(runScript), 0755); err != nil {
		return fmt.Errorf("writing run script: %w", err)
	}

	// Log run script
	logRunScript := fmt.Sprintf("#!/bin/sh\nexec svlogd -tt /var/log/"+constants.InternalOrg+"/%s\n", sm.Name)
	logRunPath := logDir + "/run"
	if err := os.WriteFile(logRunPath, []byte(logRunScript), 0755); err != nil {
		return fmt.Errorf("writing log run script: %w", err)
	}

	// Create log directory
	if err := os.MkdirAll("/var/log/"+constants.InternalOrg+"/"+sm.Name, 0755); err != nil {
		return fmt.Errorf("creating log directory: %w", err)
	}

	// Enable service
	linkPath := "/etc/service/" + sm.Name
	if err := os.Symlink(serviceDir, linkPath); err != nil && !os.IsExist(err) {
		return fmt.Errorf("enabling service: %w", err)
	}

	fmt.Printf("Service installed and started: %s\n", sm.Name)
	fmt.Printf("Status: sv status %s\n", sm.Name)
	fmt.Printf("Logs: tail -f /var/log/apimgr/%s/current\n", sm.Name)
	return nil
}

// installRCD installs rc.d service (BSD)
func (sm *ServiceManager) installRCD() error {
	scriptPath := "/usr/local/etc/rc.d/" + sm.Name

	content := fmt.Sprintf(`#!/bin/sh

# PROVIDE: %s
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="%s"
rcvar="%s_enable"
command="%s"

load_rc_config $name
run_rc_command "$1"
`, sm.Name, sm.Name, sm.Name, sm.BinaryPath)

	if err := os.WriteFile(scriptPath, []byte(content), 0755); err != nil {
		return fmt.Errorf("writing rc.d script: %w", err)
	}

	// Enable service
	rcConf := "/etc/rc.conf"
	enableLine := fmt.Sprintf("%s_enable=\"YES\"\n", sm.Name)

	// Check if already enabled
	data, err := os.ReadFile(rcConf)
	if err == nil && !strings.Contains(string(data), enableLine) {
		f, err := os.OpenFile(rcConf, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("opening rc.conf: %w", err)
		}
		defer f.Close()
		if _, err := f.WriteString(enableLine); err != nil {
			return fmt.Errorf("writing rc.conf: %w", err)
		}
	}

	// Start service
	if err := exec.Command("service", sm.Name, "start").Run(); err != nil {
		return fmt.Errorf("starting service: %w", err)
	}

	fmt.Printf("Service installed and started: %s\n", sm.Name)
	fmt.Printf("Status: service %s status\n", sm.Name)
	return nil
}

// uninstall removes the service
func (sm *ServiceManager) uninstall() error {
	manager := detectServiceManagerFn()

	// Stop service first
	sm.stop()

	switch manager {
	case "systemd":
		return sm.uninstallSystemd()
	case "openrc":
		return sm.uninstallOpenRC()
	case "launchd":
		return sm.uninstallLaunchd()
	case "runit":
		return sm.uninstallRunit()
	case "rcd":
		return sm.uninstallRCD()
	default:
		return fmt.Errorf("unsupported service manager: %s", manager)
	}
}

// uninstallSystemd removes systemd service
func (sm *ServiceManager) uninstallSystemd() error {
	// Try system service first
	servicePath := "/etc/systemd/system/" + sm.Name + ".service"
	if _, err := os.Stat(servicePath); err == nil {
		exec.Command("systemctl", "disable", sm.Name).Run()
		os.Remove(servicePath)
		exec.Command("systemctl", "daemon-reload").Run()
	} else {
		// Try user service
		home, _ := os.UserHomeDir()
		servicePath = home + "/.config/systemd/user/" + sm.Name + ".service"
		if _, err := os.Stat(servicePath); err == nil {
			exec.Command("systemctl", "--user", "disable", sm.Name).Run()
			os.Remove(servicePath)
			exec.Command("systemctl", "--user", "daemon-reload").Run()
		}
	}

	fmt.Printf("Service uninstalled: %s\n", sm.Name)
	fmt.Printf("Delete binary manually: rm %s\n", sm.BinaryPath)
	return nil
}

// uninstallOpenRC removes an OpenRC init.d service.
func (sm *ServiceManager) uninstallOpenRC() error {
	exec.Command("rc-update", "del", sm.Name, "default").Run()
	os.Remove("/etc/init.d/" + sm.Name)
	fmt.Printf("Service uninstalled: %s\n", sm.Name)
	fmt.Printf("Delete binary manually: rm %s\n", sm.BinaryPath)
	return nil
}

// uninstallLaunchd removes launchd service
func (sm *ServiceManager) uninstallLaunchd() error {
	// Try system daemon first
	plistPath := "/Library/LaunchDaemons/io.github." + constants.InternalOrg + "." + sm.Name + ".plist"
	if _, err := os.Stat(plistPath); err == nil {
		exec.Command("launchctl", "unload", plistPath).Run()
		os.Remove(plistPath)
	} else {
		// Try user agent
		home, _ := os.UserHomeDir()
		plistPath = home + "/Library/LaunchAgents/io.github." + constants.InternalOrg + "." + sm.Name + ".plist"
		if _, err := os.Stat(plistPath); err == nil {
			exec.Command("launchctl", "unload", plistPath).Run()
			os.Remove(plistPath)
		}
	}

	fmt.Printf("Service uninstalled: %s\n", sm.Name)
	fmt.Printf("Delete binary manually: rm %s\n", sm.BinaryPath)
	return nil
}

// uninstallRunit removes runit service
func (sm *ServiceManager) uninstallRunit() error {
	linkPath := "/etc/service/" + sm.Name
	serviceDir := "/etc/sv/" + sm.Name

	// Remove link
	os.Remove(linkPath)

	// Remove service directory
	os.RemoveAll(serviceDir)

	fmt.Printf("Service uninstalled: %s\n", sm.Name)
	fmt.Printf("Delete binary manually: rm %s\n", sm.BinaryPath)
	return nil
}

// uninstallRCD removes rc.d service
func (sm *ServiceManager) uninstallRCD() error {
	scriptPath := "/usr/local/etc/rc.d/" + sm.Name
	os.Remove(scriptPath)

	// Remove from rc.conf
	rcConf := "/etc/rc.conf"
	enableLine := fmt.Sprintf("%s_enable=\"YES\"", sm.Name)
	data, err := os.ReadFile(rcConf)
	if err == nil {
		lines := strings.Split(string(data), "\n")
		var newLines []string
		for _, line := range lines {
			if !strings.Contains(line, enableLine) {
				newLines = append(newLines, line)
			}
		}
		os.WriteFile(rcConf, []byte(strings.Join(newLines, "\n")), 0644)
	}

	fmt.Printf("Service uninstalled: %s\n", sm.Name)
	fmt.Printf("Delete binary manually: rm %s\n", sm.BinaryPath)
	return nil
}

// disable stops and disables the service
func (sm *ServiceManager) disable() error {
	manager := detectServiceManagerFn()

	// Stop service first
	sm.stop()

	switch manager {
	case "systemd":
		if sm.isSystemServiceInstalled() {
			return exec.Command("systemctl", "disable", sm.Name).Run()
		}
		return exec.Command("systemctl", "--user", "disable", sm.Name).Run()
	case "openrc":
		return exec.Command("rc-update", "del", sm.Name, "default").Run()
	case "launchd":
		// Launchd unload
		plistPath := "/Library/LaunchDaemons/io.github." + constants.InternalOrg + "." + sm.Name + ".plist"
		if _, err := os.Stat(plistPath); err == nil {
			return exec.Command("launchctl", "unload", plistPath).Run()
		}
		home, _ := os.UserHomeDir()
		plistPath = home + "/Library/LaunchAgents/io.github." + constants.InternalOrg + "." + sm.Name + ".plist"
		return exec.Command("launchctl", "unload", plistPath).Run()
	case "runit":
		// Remove symlink
		return os.Remove("/etc/service/" + sm.Name)
	case "rcd":
		// Remove from rc.conf
		rcConf := "/etc/rc.conf"
		enableLine := fmt.Sprintf("%s_enable=\"YES\"", sm.Name)
		data, err := os.ReadFile(rcConf)
		if err != nil {
			return err
		}
		lines := strings.Split(string(data), "\n")
		var newLines []string
		for _, line := range lines {
			if !strings.Contains(line, enableLine) {
				newLines = append(newLines, line)
			}
		}
		return os.WriteFile(rcConf, []byte(strings.Join(newLines, "\n")), 0644)
	default:
		return fmt.Errorf("unsupported service manager: %s", manager)
	}
}

// isWindowsServiceInstalled is a stub for Unix
func (sm *ServiceManager) isWindowsServiceInstalled() bool {
	return false
}
