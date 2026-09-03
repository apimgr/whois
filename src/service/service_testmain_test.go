//go:build !windows
// +build !windows

package service

import (
	"os"
	"testing"
)

// TestMain guards against infinite recursion when Daemonize() re-executes the
// test binary with _DAEMON_CHILD=1 set in the environment.  Without this guard
// the re-executed binary would run the full test suite again and fork-bomb.
func TestMain(m *testing.M) {
	if os.Getenv("_DAEMON_CHILD") != "" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}
