//go:build windows

package i2p

import "os"

func signalProcess(p *os.Process) { _ = p.Kill() }
func processAlive(pid int) bool   { p, err := os.FindProcess(pid); return err == nil && p != nil }
