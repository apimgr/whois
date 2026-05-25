//go:build windows
// +build windows

package service

import (
	"fmt"
)

// start starts Windows service (stub)
func (sm *ServiceManager) start() error {
	// TODO: Implement Windows service start
	return fmt.Errorf("Windows service start not yet implemented")
}

// stop stops Windows service (stub)
func (sm *ServiceManager) stop() error {
	// TODO: Implement Windows service stop
	return fmt.Errorf("Windows service stop not yet implemented")
}

// restart restarts Windows service (stub)
func (sm *ServiceManager) restart() error {
	// TODO: Implement Windows service restart
	return fmt.Errorf("Windows service restart not yet implemented")
}

// reload reloads Windows service (stub)
func (sm *ServiceManager) reload() error {
	// TODO: Implement Windows service reload
	return fmt.Errorf("Windows service reload not yet implemented")
}

// status shows Windows service status (stub)
func (sm *ServiceManager) status() error {
	// TODO: Implement Windows service status
	return fmt.Errorf("Windows service status not yet implemented")
}
