//go:build windows
// +build windows

package server

// setupExtraSignals is a no-op on Windows — SIGUSR1 and SIGHUP are not available.
func setupExtraSignals(s *Server) {}
