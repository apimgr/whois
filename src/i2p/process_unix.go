//go:build !windows

package i2p

import (
	"os"
	"syscall"
)

func signalProcess(p *os.Process) { _ = p.Signal(syscall.SIGTERM) }

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}
