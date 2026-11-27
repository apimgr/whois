package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apimgr/whois/src/config"
	castor "github.com/apimgr/whois/src/tor"
)

type torActionRequest struct {
	Action  string
	Confirm bool
	Prefix  string
	Workers int
	Address string
	Path    string
	Reply   chan torActionResult
}

type torActionResult struct {
	Data    any
	Err     error
	Code    string
	Details map[string]any
}

type torControlBody struct {
	Confirm bool   `json:"confirm"`
	Prefix  string `json:"prefix"`
	Workers int    `json:"workers"`
	Address string `json:"address"`
	Path    string `json:"path"`
}

func (s *Server) handleTorControl(w http.ResponseWriter, r *http.Request) {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(peer) == nil || !net.ParseIP(peer).IsLoopback() {
		http.NotFound(w, r)
		return
	}
	actions := map[string]string{
		"/server/tor/status": "status", "/server/tor/validate": "validate", "/server/tor/restart": "restart",
		"/server/tor/regenerate": "regenerate", "/server/tor/vanity/start": "vanity-start", "/server/tor/vanity/stop": "vanity-stop",
		"/server/tor/vanity/apply": "vanity-apply", "/server/tor/import-keys": "import-keys",
	}
	action, ok := actions[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	method := http.MethodGet
	if action != "status" {
		method = http.MethodPost
	}
	if r.Method != method {
		http.NotFound(w, r)
		return
	}
	body := torControlBody{}
	if action != "status" && action != "validate" && action != "restart" && action != "vanity-stop" {
		if !strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
			torControlError(w, ErrBadRequest, "JSON request body required", nil)
			return
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			torControlError(w, ErrBadRequest, "Invalid JSON request body", nil)
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			torControlError(w, ErrBadRequest, "Request must contain one JSON object", nil)
			return
		}
	}
	if action == "regenerate" || action == "vanity-apply" || action == "import-keys" {
		if !body.Confirm {
			torControlError(w, ErrValidationFailed, "confirm must be true", nil)
			return
		}
	}
	if action == "vanity-start" && strings.TrimSpace(body.Prefix) == "" {
		torControlError(w, ErrValidationFailed, "prefix is required", nil)
		return
	}
	if action == "import-keys" && (!filepath.IsAbs(body.Path) || body.Path == "") {
		torControlError(w, ErrValidationFailed, "path must be an absolute directory path", nil)
		return
	}
	if action == "status" {
		SendSuccess(w, s.torStatusData())
		return
	}
	if action == "validate" {
		errors := castor.ValidateConfig(torConfigFromServer(s.config.Tor))
		SendSuccess(w, map[string]any{"valid": len(errors) == 0, "errors": errorsOrEmpty(errors)})
		return
	}
	if s.torActions == nil {
		torControlError(w, ErrServerError, "Tor control is unavailable", nil)
		return
	}
	reply := make(chan torActionResult, 1)
	request := torActionRequest{Action: action, Confirm: body.Confirm, Prefix: body.Prefix, Workers: body.Workers, Address: body.Address, Path: body.Path, Reply: reply}
	select {
	case s.torActions <- request:
	case <-r.Context().Done():
		return
	case <-time.After(2 * time.Second):
		torControlError(w, ErrServerError, "Tor control is unavailable", nil)
		return
	}
	select {
	case result := <-reply:
		if result.Err != nil {
			code := result.Code
			if code == "" {
				code = ErrServerError
			}
			torControlError(w, code, result.Err.Error(), result.Details)
			return
		}
		status := http.StatusOK
		if action == "vanity-start" {
			status = http.StatusAccepted
		}
		writeJSON(w, status, APIResponse{OK: true, Data: result.Data})
	case <-r.Context().Done():
	}
}

func errorsOrEmpty(errs []castor.FieldError) []castor.FieldError {
	if errs == nil {
		return []castor.FieldError{}
	}
	return errs
}

func torControlError(w http.ResponseWriter, code, message string, details map[string]any) {
	status := mapErrorCodeToStatus(code)
	writeJSON(w, status, APIResponse{OK: false, Error: code, Message: message, Details: details})
}

func (s *Server) torStatusData() map[string]any {
	s.torMu.RLock()
	service, state := s.torService, s.torStatus
	s.torMu.RUnlock()
	vanity := castor.VanityStatus{State: "idle", Candidates: []string{}}
	if s.torMaintenance != nil {
		vanity = s.torMaintenance.VanityStatus()
	}
	data := map[string]any{"running": false, "version": "", "bootstrap_percent": 0, "circuit_established": false, "vanity": vanity}
	if state == "disabled" {
		data["running"] = false
	}
	if service != nil {
		data["running"] = true
		data["onion_address"] = service.OnionAddress()
		if process, ok := service.(interface {
			PID() int
			Version() string
			BootstrapPercent() int
			CircuitEstablished() bool
		}); ok {
			if pid := process.PID(); pid > 0 {
				data["pid"] = pid
			} else {
				data["running"] = false
			}
			data["version"] = process.Version()
			data["bootstrap_percent"] = process.BootstrapPercent()
			data["circuit_established"] = process.CircuitEstablished()
		}
	}
	return data
}

func torConfigFromServer(cfg config.TorConfig) castor.TorConfig {
	return castor.TorConfig{Binary: cfg.Binary, UseNetwork: cfg.UseNetwork, AllowUserPreference: cfg.AllowUserPreference, MaxCircuits: cfg.MaxCircuits,
		StartupTimeout: cfg.StartupTimeout, CircuitTimeout: cfg.CircuitTimeout, BootstrapTimeout: cfg.BootstrapTimeout, SafeLogging: cfg.SafeLogging,
		MaxStreamsPerCircuit: cfg.MaxStreamsPerCircuit, CloseCircuitOnStreamLimit: cfg.CloseCircuitOnStreamLimit, BandwidthRate: cfg.BandwidthRate,
		BandwidthBurst: cfg.BandwidthBurst, MaxMonthlyBandwidth: cfg.MaxMonthlyBandwidth, NumIntroPoints: cfg.NumIntroPoints, VirtualPort: cfg.VirtualPort}
}

func (s *Server) runTorManager(ctx context.Context, cfg castor.TorConfig, handler http.Handler, readTimeout, writeTimeout, idleTimeout time.Duration, actions <-chan torActionRequest, updates <-chan config.TorConfig) {
	if s.torMaintenance == nil {
		s.torMaintenance = &castor.Maintenance{DataDir: s.config.DataDir}
	}
	start := func() (*castor.TorService, error) {
		s.torMu.Lock()
		s.torStatus = "starting"
		s.torMu.Unlock()
		svc, err := castor.Start(ctx, s.config.Port, &cfg, s.config.ConfigDir, s.config.DataDir)
		if err != nil {
			s.torMu.Lock()
			s.torStatus = "unavailable"
			s.torService = nil
			s.torMu.Unlock()
			return nil, err
		}
		if svc == nil {
			s.torMu.Lock()
			s.torStatus = "disabled"
			s.torService = nil
			s.torMu.Unlock()
			return nil, nil
		}
		s.torMu.Lock()
		s.torService = svc
		s.torStatus = "healthy"
		s.torMu.Unlock()
		return svc, nil
	}
	var service *castor.TorService
	backoff := time.Second
	for ctx.Err() == nil {
		if service == nil {
			if castor.FindBinary(cfg.Binary) == "" {
				select {
				case <-ctx.Done():
					return
				case next := <-updates:
					cfg = torConfigFromServer(next)
					cfg.Binary = castor.FindBinary(next.Binary)
				case action := <-actions:
					_, _, restart, result := s.runTorAction(ctx, action, nil, cfg, handler, readTimeout, writeTimeout, idleTimeout)
					if restart {
						result.Err = errors.New("tor is not running")
						result.Code = ErrServerError
					}
					action.Reply <- result
				}
				continue
			}
			var err error
			service, err = start()
			if err != nil {
				log.Printf("[Tor] bootstrap failed: %v", err)
				select {
				case <-ctx.Done():
					return
				case next := <-updates:
					cfg = torConfigFromServer(next)
					cfg.Binary = castor.FindBinary(next.Binary)
					backoff = time.Second
				case <-time.After(backoff):
					backoff = min(backoff*2, 30*time.Second)
				}
				continue
			}
			if service == nil {
				return
			}
			backoff = time.Second
		}
		serveErr := make(chan error, 1)
		go func(svc *castor.TorService) {
			serveErr <- svc.Serve(torRequestHandler(handler), readTimeout, writeTimeout, idleTimeout)
		}(service)
		health := time.NewTicker(10 * time.Second)
		for service != nil {
			select {
			case <-ctx.Done():
				health.Stop()
				_ = service.Close()
				return
			case err := <-serveErr:
				health.Stop()
				if ctx.Err() == nil {
					log.Printf("[Tor] backend stopped: %v", err)
				}
				_ = service.Close()
				service = nil
			case <-health.C:
				if err := service.Health(ctx); err != nil {
					log.Printf("[Tor] process health failed; restarting: %v", err)
					health.Stop()
					_ = service.Close()
					service = nil
				}
			case next := <-updates:
				health.Stop()
				_ = service.Close()
				service = nil
				cfg = torConfigFromServer(next)
				cfg.Binary = castor.FindBinary(next.Binary)
			case action := <-actions:
				next, nextCfg, restart, result := s.runTorAction(ctx, action, service, cfg, handler, readTimeout, writeTimeout, idleTimeout)
				cfg = nextCfg
				if restart {
					if service != nil && service != next {
						_ = service.Close()
					}
					service = next
					if service == nil {
						health.Stop()
						break
					}
					s.torMu.Lock()
					s.torService = service
					s.torStatus = "healthy"
					s.torMu.Unlock()
					health.Stop()
					serveErr = make(chan error, 1)
					go func(svc *castor.TorService) {
						serveErr <- svc.Serve(torRequestHandler(handler), readTimeout, writeTimeout, idleTimeout)
					}(service)
					health = time.NewTicker(10 * time.Second)
				}
				action.Reply <- result
			}
		}
		health.Stop()
		s.torMu.Lock()
		s.torService = nil
		s.torStatus = "unavailable"
		s.torMu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
			backoff = min(backoff*2, 30*time.Second)
		}
	}
}

func (s *Server) runTorAction(ctx context.Context, request torActionRequest, service *castor.TorService, cfg castor.TorConfig, handler http.Handler, readTimeout, writeTimeout, idleTimeout time.Duration) (*castor.TorService, castor.TorConfig, bool, torActionResult) {
	result := torActionResult{}
	maintenance := s.torMaintenance
	if maintenance == nil {
		maintenance = &castor.Maintenance{DataDir: s.config.DataDir}
		s.torMaintenance = maintenance
	}
	switch request.Action {
	case "vanity-start":
		if err := maintenance.StartVanity(request.Prefix, request.Workers); err != nil {
			result.Err = err
			result.Code = ErrConflict
			if strings.Contains(err.Error(), "prefix") || strings.Contains(err.Error(), "workers") {
				result.Code = ErrValidationFailed
			}
			if strings.Contains(err.Error(), "already running") {
				result.Details = map[string]any{"prefix": maintenance.VanityStatus().Prefix}
			}
		} else {
			v := maintenance.VanityStatus()
			result.Data = map[string]any{"state": v.State, "prefix": v.Prefix, "workers": v.Workers}
		}
	case "vanity-stop":
		stopped, candidates := maintenance.StopVanity()
		result.Data = map[string]any{"stopped": stopped, "candidates": candidates}
	case "restart", "regenerate", "vanity-apply", "import-keys":
		if service == nil {
			result.Err = errors.New("tor is not running")
			result.Code = ErrServerError
			break
		}
		previous := service.OnionAddress()
		newIdentity := false
		source := ""
		switch request.Action {
		case "regenerate":
			if !request.Confirm {
				result.Err = errors.New("confirm must be true")
				result.Code = ErrValidationFailed
				break
			}
			newIdentity = true
		case "vanity-apply":
			if !request.Confirm {
				result.Err = errors.New("confirm must be true")
				result.Code = ErrValidationFailed
				break
			}
			var err error
			source, err = maintenance.SelectCandidate(request.Address)
			if err != nil {
				result.Err = err
				result.Code = ErrNotFound
				if strings.Contains(err.Error(), "ambiguous") {
					result.Code = ErrConflict
					result.Details = map[string]any{"candidates": maintenance.Candidates()}
				}
				break
			}
			newIdentity = true
		case "import-keys":
			if !request.Confirm {
				result.Err = errors.New("confirm must be true")
				result.Code = ErrValidationFailed
				break
			}
			if !filepath.IsAbs(request.Path) {
				result.Err = errors.New("path must be absolute")
				result.Code = ErrValidationFailed
				break
			}
			source = request.Path
			newIdentity = true
		}
		if source != "" {
			if _, err := castor.ValidateKeyDirectory(source); err != nil {
				result.Err = err
				result.Code = ErrValidationFailed
				break
			}
		}
		if result.Err != nil {
			return service, cfg, false, result
		}
		if err := service.Close(); err != nil {
			result.Err = err
			result.Code = ErrServerError
			return service, cfg, false, result
		}
		var rollback, commit func() error
		siteDir := filepath.Join(s.config.DataDir, "tor", "site")
		if source != "" {
			rollback, commit, result.Err = castor.SwapKeyDirectoryTransactional(source, siteDir)
			if result.Err != nil {
				result.Code = ErrValidationFailed
				if restored, restoreErr := castor.Start(ctx, s.config.Port, &cfg, s.config.ConfigDir, s.config.DataDir); restoreErr == nil {
					service = restored
				}
				return service, cfg, true, result
			}
		} else if request.Action == "regenerate" {
			backup := siteDir + ".regenerate-backup"
			if err := os.RemoveAll(backup); err != nil {
				result.Err = err
				result.Code = ErrServerError
				if restored, restoreErr := castor.Start(ctx, s.config.Port, &cfg, s.config.ConfigDir, s.config.DataDir); restoreErr == nil {
					service = restored
				}
				return service, cfg, true, result
			}
			if err := os.Rename(siteDir, backup); err != nil {
				result.Err = err
				result.Code = ErrServerError
				if restored, restoreErr := castor.Start(ctx, s.config.Port, &cfg, s.config.ConfigDir, s.config.DataDir); restoreErr == nil {
					service = restored
				}
				return service, cfg, true, result
			}
			rollback = func() error { _ = os.RemoveAll(siteDir); return os.Rename(backup, siteDir) }
			commit = func() error { return os.RemoveAll(backup) }
		}
		next, err := castor.Start(ctx, s.config.Port, &cfg, s.config.ConfigDir, s.config.DataDir)
		if err != nil || next == nil {
			if rollback != nil {
				_ = rollback()
			}
			result.Err = fmt.Errorf("tor restart failed; previous onion address was %s: %w", previous, err)
			if err == nil {
				result.Err = fmt.Errorf("tor restart failed; previous onion address was %s: tor did not return a running service", previous)
			}
			result.Code = ErrServerError
			if restored, restoreErr := castor.Start(ctx, s.config.Port, &cfg, s.config.ConfigDir, s.config.DataDir); restoreErr == nil && restored != nil {
				service = restored
			}
			return service, cfg, true, result
		}
		if newIdentity && ((source != "" && next.OnionAddress() != candidateHostname(source)) || (request.Action == "regenerate" && next.OnionAddress() == previous)) {
			_ = next.Close()
			if rollback != nil {
				_ = rollback()
			}
			result.Err = errors.New("tor published a hostname that does not match the imported key directory")
			result.Code = ErrServerError
			if restored, restoreErr := castor.Start(ctx, s.config.Port, &cfg, s.config.ConfigDir, s.config.DataDir); restoreErr == nil && restored != nil {
				service = restored
			}
			break
		}
		if commit != nil {
			if err := commit(); err != nil {
				_ = next.Close()
				if rollback != nil {
					_ = rollback()
				}
				result.Err = err
				result.Code = ErrServerError
				if restored, restoreErr := castor.Start(ctx, s.config.Port, &cfg, s.config.ConfigDir, s.config.DataDir); restoreErr == nil {
					service = restored
				}
				break
			}
		}
		service = next
		if request.Action == "vanity-apply" {
			_ = os.RemoveAll(source)
		}
		switch request.Action {
		case "restart":
			result.Data = map[string]any{"restarted": true, "onion_address": next.OnionAddress()}
		case "regenerate":
			result.Data = map[string]any{"onion_address": next.OnionAddress(), "previous_address": previous}
		default:
			result.Data = map[string]any{"onion_address": next.OnionAddress()}
		}
		_ = newIdentity
	default:
		result.Err = fmt.Errorf("unknown Tor action %q", request.Action)
	}
	if result.Err != nil && service == nil {
		return nil, cfg, false, result
	}
	if service != nil && request.Action != "restart" && request.Action != "regenerate" && request.Action != "vanity-apply" && request.Action != "import-keys" {
		return service, cfg, false, result
	}
	return service, cfg, request.Action == "restart" || request.Action == "regenerate" || request.Action == "vanity-apply" || request.Action == "import-keys", result
}

func candidateHostname(path string) string {
	if path == "" {
		return ""
	}
	address, err := castor.ValidateKeyDirectory(path)
	if err != nil {
		return ""
	}
	return address
}

var _ = os.ErrNotExist
