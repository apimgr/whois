//go:build !windows
// +build !windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// start starts the service
func (sm *ServiceManager) start() error {
	manager := DetectServiceManager()

	switch manager {
	case "systemd":
		if sm.isSystemServiceInstalled() {
			return exec.Command("systemctl", "start", sm.Name).Run()
		}
		return exec.Command("systemctl", "--user", "start", sm.Name).Run()
	case "launchd":
		// Launchd services auto-start when loaded
		plistPath := "/Library/LaunchDaemons/casapps." + sm.Name + ".plist"
		if _, err := os.Stat(plistPath); err == nil {
			return exec.Command("launchctl", "start", "casapps."+sm.Name).Run()
		}
		home, _ := os.UserHomeDir()
		plistPath = home + "/Library/LaunchAgents/casapps." + sm.Name + ".plist"
		return exec.Command("launchctl", "start", "casapps."+sm.Name).Run()
	case "runit":
		return exec.Command("sv", "start", sm.Name).Run()
	case "rcd":
		return exec.Command("service", sm.Name, "start").Run()
	default:
		return fmt.Errorf("unsupported service manager: %s", manager)
	}
}

// stop stops the service
func (sm *ServiceManager) stop() error {
	manager := DetectServiceManager()

	switch manager {
	case "systemd":
		if sm.isSystemServiceInstalled() {
			return exec.Command("systemctl", "stop", sm.Name).Run()
		}
		return exec.Command("systemctl", "--user", "stop", sm.Name).Run()
	case "launchd":
		return exec.Command("launchctl", "stop", "casapps."+sm.Name).Run()
	case "runit":
		return exec.Command("sv", "stop", sm.Name).Run()
	case "rcd":
		return exec.Command("service", sm.Name, "stop").Run()
	default:
		return fmt.Errorf("unsupported service manager: %s", manager)
	}
}

// restart restarts the service
func (sm *ServiceManager) restart() error {
	manager := DetectServiceManager()

	switch manager {
	case "systemd":
		if sm.isSystemServiceInstalled() {
			return exec.Command("systemctl", "restart", sm.Name).Run()
		}
		return exec.Command("systemctl", "--user", "restart", sm.Name).Run()
	case "launchd":
		// Launchd restart
		exec.Command("launchctl", "stop", "casapps."+sm.Name).Run()
		return exec.Command("launchctl", "start", "casapps."+sm.Name).Run()
	case "runit":
		return exec.Command("sv", "restart", sm.Name).Run()
	case "rcd":
		return exec.Command("service", sm.Name, "restart").Run()
	default:
		return fmt.Errorf("unsupported service manager: %s", manager)
	}
}

// reload reloads the service configuration
func (sm *ServiceManager) reload() error {
	manager := DetectServiceManager()

	switch manager {
	case "systemd":
		if sm.isSystemServiceInstalled() {
			return exec.Command("systemctl", "reload", sm.Name).Run()
		}
		return exec.Command("systemctl", "--user", "reload", sm.Name).Run()
	case "launchd":
		// Launchd doesn't have reload, use restart
		return sm.restart()
	case "runit":
		return exec.Command("sv", "reload", sm.Name).Run()
	case "rcd":
		return exec.Command("service", sm.Name, "reload").Run()
	default:
		return fmt.Errorf("unsupported service manager: %s", manager)
	}
}

// status shows service status
func (sm *ServiceManager) status() error {
	manager := DetectServiceManager()

	var cmd *exec.Cmd
	switch manager {
	case "systemd":
		if sm.isSystemServiceInstalled() {
			cmd = exec.Command("systemctl", "status", sm.Name)
		} else {
			cmd = exec.Command("systemctl", "--user", "status", sm.Name)
		}
	case "launchd":
		cmd = exec.Command("launchctl", "list")
	case "runit":
		cmd = exec.Command("sv", "status", sm.Name)
	case "rcd":
		cmd = exec.Command("service", sm.Name, "status")
	default:
		return fmt.Errorf("unsupported service manager: %s", manager)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if manager == "launchd" {
		// For launchd, filter to just this service
		output, err := cmd.Output()
		if err != nil {
			return err
		}
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "casapps."+sm.Name) {
				fmt.Println(line)
			}
		}
		return nil
	}

	return cmd.Run()
}
