//go:build windows
// +build windows

package service

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// waitForState polls the service status until it reaches wantState or the
// deadline expires, returning an error if the deadline is exceeded.
func waitForState(s *mgr.Service, wantState svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return fmt.Errorf("querying service state: %w", err)
		}
		if st.State == wantState {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for service state %d", wantState)
}

// openManagerAndService is a convenience helper that connects to the SCM and
// opens the named service. Both handles must be closed by the caller.
func (sm *ServiceManager) openManagerAndService() (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to service manager: %w", err)
	}

	s, err := m.OpenService(sm.Name)
	if err != nil {
		m.Disconnect()
		return nil, nil, fmt.Errorf("opening service %q: %w", sm.Name, err)
	}

	return m, s, nil
}

// start starts the Windows SCM service and waits for it to reach the running
// state (up to 30 seconds).
func (sm *ServiceManager) start() error {
	m, s, err := sm.openManagerAndService()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	// No-op if already running.
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("querying service state: %w", err)
	}
	if st.State == svc.Running {
		fmt.Printf("Service already running: %s\n", sm.Name)
		return nil
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("starting service %q: %w", sm.Name, err)
	}

	if err := waitForState(s, svc.Running, 30*time.Second); err != nil {
		return fmt.Errorf("service %q did not reach running state: %w", sm.Name, err)
	}

	fmt.Printf("Service started: %s\n", sm.Name)
	return nil
}

// stop sends the Stop control to the Windows SCM service and waits for it to
// reach the stopped state (up to 30 seconds).
func (sm *ServiceManager) stop() error {
	m, s, err := sm.openManagerAndService()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	// No-op if already stopped.
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("querying service state: %w", err)
	}
	if st.State == svc.Stopped {
		fmt.Printf("Service already stopped: %s\n", sm.Name)
		return nil
	}

	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("sending stop control to service %q: %w", sm.Name, err)
	}

	if err := waitForState(s, svc.Stopped, 30*time.Second); err != nil {
		return fmt.Errorf("service %q did not reach stopped state: %w", sm.Name, err)
	}

	fmt.Printf("Service stopped: %s\n", sm.Name)
	return nil
}

// restart stops then starts the service.
func (sm *ServiceManager) restart() error {
	if err := sm.stop(); err != nil {
		return fmt.Errorf("restart (stop phase): %w", err)
	}
	if err := sm.start(); err != nil {
		return fmt.Errorf("restart (start phase): %w", err)
	}
	fmt.Printf("Service restarted: %s\n", sm.Name)
	return nil
}

// reload performs a stop-then-start because Windows has no SIGHUP equivalent.
func (sm *ServiceManager) reload() error {
	if err := sm.stop(); err != nil {
		return fmt.Errorf("reload (stop phase): %w", err)
	}
	if err := sm.start(); err != nil {
		return fmt.Errorf("reload (start phase): %w", err)
	}
	fmt.Printf("Service reloaded: %s\n", sm.Name)
	return nil
}

// status queries the SCM and prints the current service state to stdout.
func (sm *ServiceManager) status() error {
	m, s, err := sm.openManagerAndService()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("querying service %q: %w", sm.Name, err)
	}

	stateNames := map[svc.State]string{
		svc.Stopped:         "Stopped",
		svc.StartPending:    "Start Pending",
		svc.StopPending:     "Stop Pending",
		svc.Running:         "Running",
		svc.ContinuePending: "Continue Pending",
		svc.PausePending:    "Pause Pending",
		svc.Paused:          "Paused",
	}

	stateName, ok := stateNames[st.State]
	if !ok {
		stateName = fmt.Sprintf("Unknown (%d)", st.State)
	}

	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("reading service config: %w", err)
	}

	startTypeNames := map[uint32]string{
		mgr.StartAutomatic: "Automatic",
		mgr.StartManual:    "Manual",
		mgr.StartDisabled:  "Disabled",
	}

	startTypeName, ok := startTypeNames[cfg.StartType]
	if !ok {
		startTypeName = fmt.Sprintf("Unknown (%d)", cfg.StartType)
	}

	fmt.Printf("Service:     %s\n", sm.Name)
	fmt.Printf("DisplayName: %s\n", cfg.DisplayName)
	fmt.Printf("Description: %s\n", cfg.Description)
	fmt.Printf("StartType:   %s\n", startTypeName)
	fmt.Printf("State:       %s\n", stateName)
	fmt.Printf("PID:         %d\n", st.ProcessId)
	return nil
}
