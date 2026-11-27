//go:build windows
// +build windows

package server

import "context"

// setupExtraSignals is a no-op on Windows — SIGUSR1 and SIGHUP are not available.
func setupExtraSignals(context.Context, *Server) <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}
