//go:build windows

package service

import "fmt"

// Daemonize is not supported on Windows; the Windows Service Manager handles
// process lifecycle. Use --service install instead.
func Daemonize() error {
	return fmt.Errorf("daemonization not supported on Windows; use --service install")
}
