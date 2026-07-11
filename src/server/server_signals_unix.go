//go:build !windows
// +build !windows

package server

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/apimgr/whois/src/config"
)

// setupExtraSignals registers SIGUSR1 (log rotation) and SIGHUP (config reload)
// on Unix platforms. These signals are not available on Windows.
func setupExtraSignals(s *Server) {
	rotateSig := make(chan os.Signal, 1)
	signal.Notify(rotateSig, syscall.SIGUSR1)
	go func() {
		for range rotateSig {
			if s.logger != nil {
				if err := s.logger.Rotate(); err != nil {
					log.Printf("ERROR: log rotation failed: %v", err)
				} else {
					log.Printf("Log files reopened (SIGUSR1)")
				}
			}
		}
	}()

	reloadSig := make(chan os.Signal, 1)
	signal.Notify(reloadSig, syscall.SIGHUP)
	go func() {
		for range reloadSig {
			log.Printf("Received SIGHUP, reloading configuration...")
			newCfg, err := config.LoadServerConfig(s.config.ConfigDir)
			if err != nil {
				log.Printf("ERROR: config reload failed: %v", err)
				continue
			}
			s.config = newCfg
			log.Printf("Configuration reloaded successfully")
		}
	}()
}
