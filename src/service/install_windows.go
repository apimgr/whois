//go:build windows
// +build windows

package service

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// installSystemService installs the binary as an automatic Windows SCM service
// and registers an eventlog source for it.
func (sm *ServiceManager) installSystemService() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to service manager: %w", err)
	}
	defer m.Disconnect()

	// Fail early if service already exists.
	existing, err := m.OpenService(sm.Name)
	if err == nil {
		existing.Close()
		return fmt.Errorf("service %q is already installed", sm.Name)
	}

	cfg := mgr.Config{
		DisplayName: sm.DisplayName,
		Description: sm.Description,
		StartType:   mgr.StartAutomatic,
	}

	s, err := m.CreateService(sm.Name, exePath, cfg)
	if err != nil {
		return fmt.Errorf("creating service %q: %w", sm.Name, err)
	}
	defer s.Close()

	// Register the event-log source (ignored if it already exists).
	if err := eventlog.InstallAsEventCreate(sm.Name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		// Non-fatal: the service still works without a registered event source.
		fmt.Printf("warning: registering eventlog source: %v\n", err)
	}

	fmt.Printf("Service installed: %s\n", sm.Name)
	fmt.Printf("Start: sc start %s\n", sm.Name)
	return nil
}

// installUserService is not supported on Windows.
func (sm *ServiceManager) installUserService() error {
	return fmt.Errorf("user services not supported on Windows")
}

// uninstall stops (if running), deletes the SCM service, and removes the
// eventlog source registration.
func (sm *ServiceManager) uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(sm.Name)
	if err != nil {
		return fmt.Errorf("opening service %q: %w", sm.Name, err)
	}
	defer s.Close()

	// Stop the service if it is currently running.
	status, err := s.Query()
	if err == nil && status.State == svc.Running {
		if _, stopErr := s.Control(svc.Stop); stopErr == nil {
			// Wait up to 10 seconds for the service to reach the stopped state.
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				st, qErr := s.Query()
				if qErr != nil || st.State == svc.Stopped {
					break
				}
				time.Sleep(250 * time.Millisecond)
			}
		}
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("deleting service %q: %w", sm.Name, err)
	}

	// Remove the event-log source; ignore errors (may not be present).
	eventlog.Remove(sm.Name)

	fmt.Printf("Service uninstalled: %s\n", sm.Name)
	fmt.Printf("Delete binary manually: del %s\n", sm.BinaryPath)
	return nil
}

// disable sets the service start type to Disabled and stops it if running.
func (sm *ServiceManager) disable() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(sm.Name)
	if err != nil {
		return fmt.Errorf("opening service %q: %w", sm.Name, err)
	}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("reading service config: %w", err)
	}

	cfg.StartType = mgr.StartDisabled
	if err := s.UpdateConfig(cfg); err != nil {
		return fmt.Errorf("disabling service %q: %w", sm.Name, err)
	}

	// Stop the service if it is currently running.
	status, err := s.Query()
	if err == nil && status.State == svc.Running {
		if _, stopErr := s.Control(svc.Stop); stopErr != nil {
			return fmt.Errorf("stopping service %q: %w", sm.Name, stopErr)
		}
		// Wait up to 10 seconds for the service to reach the stopped state.
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			st, qErr := s.Query()
			if qErr != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
	}

	fmt.Printf("Service disabled: %s\n", sm.Name)
	return nil
}

// isWindowsServiceInstalled returns true if the named SCM service exists.
func (sm *ServiceManager) isWindowsServiceInstalled() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()

	s, err := m.OpenService(sm.Name)
	if err != nil {
		return false
	}
	s.Close()
	return true
}
