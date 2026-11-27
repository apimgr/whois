//go:build !windows
// +build !windows

package server

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/apimgr/whois/src/config"
)

// setupExtraSignals registers SIGUSR1 (log rotation) and SIGHUP (config reload)
// on Unix platforms. These signals are not available on Windows.
func setupExtraSignals(ctx context.Context, s *Server) <-chan struct{} {
	rotateSig := make(chan os.Signal, 1)
	signal.Notify(rotateSig, syscall.SIGUSR1)
	reloadSig := make(chan os.Signal, 1)
	signal.Notify(reloadSig, syscall.SIGHUP)
	done := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		defer signal.Stop(rotateSig)
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-rotateSig:
				if !ok {
					return
				}
				if s.logger != nil {
					if err := s.logger.Rotate(); err != nil {
						log.Printf("ERROR: log rotation failed: %v", err)
					} else {
						log.Printf("Log files reopened (SIGUSR1)")
					}
				}
			}
		}
	}()

	go func() {
		defer workers.Done()
		defer signal.Stop(reloadSig)
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-reloadSig:
				if !ok {
					return
				}
				log.Printf("Received SIGHUP, reloading configuration...")
				newCfg, err := config.LoadServerConfig(s.config.ConfigDir)
				if err != nil {
					log.Printf("ERROR: config reload failed: %v", err)
					continue
				}
				if s.configManager != nil {
					s.configManager.ApplyExternalConfig(newCfg)
				} else {
					s.config = newCfg
				}
				log.Printf("Configuration reloaded successfully")
			}
		}
	}()
	go func() {
		workers.Wait()
		close(done)
	}()
	return done
}
