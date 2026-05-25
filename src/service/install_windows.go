//go:build windows
// +build windows

package service

import (
	"fmt"
)

// installSystemService installs Windows service (stub)
func (sm *ServiceManager) installSystemService() error {
	// TODO: Implement Windows service installation using golang.org/x/sys/windows/svc
	return fmt.Errorf("Windows service installation not yet implemented")
}

// installUserService is not supported on Windows
func (sm *ServiceManager) installUserService() error {
	return fmt.Errorf("user services not supported on Windows")
}

// uninstall removes Windows service (stub)
func (sm *ServiceManager) uninstall() error {
	// TODO: Implement Windows service uninstallation
	return fmt.Errorf("Windows service uninstallation not yet implemented")
}

// disable stops and disables Windows service (stub)
func (sm *ServiceManager) disable() error {
	// TODO: Implement Windows service disable
	return fmt.Errorf("Windows service disable not yet implemented")
}

// isWindowsServiceInstalled checks if Windows service is installed (stub)
func (sm *ServiceManager) isWindowsServiceInstalled() bool {
	// TODO: Check Windows service registry
	return false
}
