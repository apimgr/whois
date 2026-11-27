package tor

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cretz/bine/control"
	"github.com/pires/go-proxyproto"
	"golang.org/x/net/proxy"
)

// TorConfig holds Tor-related configuration from server config.
type TorConfig struct {
	Binary                    string `yaml:"binary" json:"binary"`
	UseNetwork                bool   `yaml:"use_network" json:"use_network"`
	AllowUserPreference       bool   `yaml:"allow_user_preference" json:"allow_user_preference"`
	MaxCircuits               int    `yaml:"max_circuits" json:"max_circuits"`
	StartupTimeout            int    `yaml:"startup_timeout" json:"startup_timeout"`
	CircuitTimeout            int    `yaml:"circuit_timeout" json:"circuit_timeout"`
	BootstrapTimeout          int    `yaml:"bootstrap_timeout" json:"bootstrap_timeout"`
	SafeLogging               bool   `yaml:"safe_logging" json:"safe_logging"`
	MaxStreamsPerCircuit      int    `yaml:"max_streams_per_circuit" json:"max_streams_per_circuit"`
	CloseCircuitOnStreamLimit bool   `yaml:"close_circuit_on_stream_limit" json:"close_circuit_on_stream_limit"`
	BandwidthRate             string `yaml:"bandwidth_rate" json:"bandwidth_rate"`
	BandwidthBurst            string `yaml:"bandwidth_burst" json:"bandwidth_burst"`
	MaxMonthlyBandwidth       string `yaml:"max_monthly_bandwidth" json:"max_monthly_bandwidth"`
	NumIntroPoints            int    `yaml:"num_intro_points" json:"num_intro_points"`
	VirtualPort               int    `yaml:"virtual_port" json:"virtual_port"`
}

// DefaultTorConfig returns the canonical Tor settings.
func DefaultTorConfig() TorConfig {
	return TorConfig{AllowUserPreference: true, MaxCircuits: 32, StartupTimeout: 60, CircuitTimeout: 60,
		BootstrapTimeout: 180, SafeLogging: true, MaxStreamsPerCircuit: 100, CloseCircuitOnStreamLimit: true,
		BandwidthRate: "1 MB", BandwidthBurst: "2 MB", MaxMonthlyBandwidth: "100 GB", NumIntroPoints: 3, VirtualPort: 80}
}

// TorService owns one Tor process and its dedicated PROXY-protocol listener.
type TorService struct {
	cmd          *exec.Cmd
	processDone  <-chan struct{}
	ctrl         *control.Conn
	eventCancel  context.CancelFunc
	onionAddress string
	listener     net.Listener
	dialer       proxy.ContextDialer
	closeOnce    sync.Once
	closeErr     error
}

func (s *TorService) OnionAddress() string  { return s.onionAddress }
func (s *TorService) OutboundEnabled() bool { return s.dialer != nil }

// PID returns the child process ID while Tor is running.
func (s *TorService) PID() int {
	if s.cmd == nil || s.cmd.Process == nil || s.cmd.ProcessState != nil {
		return 0
	}
	return s.cmd.Process.Pid
}

// Version returns Tor's runtime version string when available.
func (s *TorService) Version() string {
	if s.ctrl == nil {
		return ""
	}
	values, err := s.ctrl.GetInfo("version")
	if err != nil || len(values) == 0 {
		return ""
	}
	return values[0].Val
}

// BootstrapPercent reads Tor's current client bootstrap percentage.
func (s *TorService) BootstrapPercent() int {
	if s.ctrl == nil {
		return 0
	}
	values, err := s.ctrl.GetInfo("status/bootstrap-phase")
	if err != nil || len(values) == 0 {
		return 0
	}
	for _, field := range strings.Fields(values[0].Val) {
		if strings.HasPrefix(field, "PROGRESS=") {
			value, _ := strconv.Atoi(strings.TrimPrefix(field, "PROGRESS="))
			if value < 0 {
				return 0
			}
			if value > 100 {
				return 100
			}
			return value
		}
	}
	return 0
}

// CircuitEstablished reports whether Tor currently has a built circuit.
func (s *TorService) CircuitEstablished() bool {
	if s.ctrl == nil {
		return false
	}
	values, err := s.ctrl.GetInfo("circuit-status")
	if err != nil {
		return false
	}
	for _, value := range values {
		if strings.Contains(value.Val, " BUILT ") || strings.HasSuffix(value.Val, " BUILT") {
			return true
		}
	}
	return false
}

// GetHTTPClient returns an HTTP client, routed through Tor only when requested.
func (s *TorService) GetHTTPClient(useTor bool) *http.Client {
	client := &http.Client{Timeout: 30 * time.Second}
	if useTor && s.dialer != nil {
		client.Timeout = 60 * time.Second
		client.Transport = &http.Transport{DialContext: s.dialer.DialContext}
	}
	return client
}

// Health reports process and authenticated-control connection liveness.
func (s *TorService) Health(ctx context.Context) error {
	if s.cmd == nil || s.cmd.Process == nil || s.cmd.ProcessState != nil {
		return fmt.Errorf("tor process is not running")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// Serve passes PROXY-protocol requests to the existing application handler.
func (s *TorService) Serve(handler http.Handler, readTimeout, writeTimeout, idleTimeout time.Duration) error {
	server := &http.Server{Handler: handler, ReadTimeout: readTimeout, WriteTimeout: writeTimeout, IdleTimeout: idleTimeout}
	return server.Serve(s.listener)
}

// Close shuts down Tor gracefully, then escalates to TERM/KILL within bounds.
func (s *TorService) Close() error {
	s.closeOnce.Do(func() {
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.closeErr = stopTor(s.cmd, s.ctrl, s.processDone)
		if s.eventCancel != nil {
			s.eventCancel()
		}
	})
	return s.closeErr
}

// FindBinary locates Tor from configuration, PATH, or standard locations.
func FindBinary(configured string) string {
	if configured != "" {
		if info, err := os.Stat(configured); err == nil && !info.IsDir() {
			return configured
		}
	}
	if path, err := exec.LookPath("tor"); err == nil {
		return path
	}
	paths := []string{"/usr/bin/tor", "/usr/sbin/tor", "/usr/local/bin/tor"}
	if runtime.GOOS == "darwin" {
		paths = []string{"/usr/local/bin/tor", "/opt/homebrew/bin/tor"}
	}
	if runtime.GOOS == "windows" {
		paths = []string{`C:\Program Files\Tor\tor.exe`, `C:\Program Files (x86)\Tor\tor.exe`}
	}
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

// Start creates a dedicated hidden service. serverPort is retained for API
// compatibility; hidden traffic always targets the service-owned backend port.
func Start(ctx context.Context, serverPort int, cfg *TorConfig, configDir, dataDir string) (*TorService, error) {
	_ = serverPort
	if cfg == nil {
		defaults := DefaultTorConfig()
		cfg = &defaults
	}
	binary := FindBinary(cfg.Binary)
	if binary == "" {
		log.Printf("[Tor] binary not found, hidden service disabled")
		return nil, nil
	}
	if failures := ValidateConfig(*cfg); len(failures) > 0 {
		return nil, fmt.Errorf("tor configuration is invalid: %s: %s", failures[0].Field, failures[0].Message)
	}
	if err := ensureTorDirs(configDir, dataDir); err != nil {
		return nil, fmt.Errorf("tor: create directories: %w", err)
	}
	torData := filepath.Join(dataDir, "tor")
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("tor: bind backend listener: %w", err)
	}
	backendAddr := backend.Addr().(*net.TCPAddr)
	backendPort := backendAddr.Port
	proxyListener := &proxyproto.Listener{
		Listener:          backend,
		ConnPolicy:        func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) { return proxyproto.REQUIRE, nil },
		ReadHeaderTimeout: 5 * time.Second,
	}
	torrcPath := filepath.Join(configDir, "tor", "torrc")
	content := getTorConfig(cfg, filepath.Join(dataDir, "tor", "site"), backendPort, torData)
	if _, err := ensureTorrc(torrcPath, []byte(content)); err != nil {
		_ = proxyListener.Close()
		return nil, fmt.Errorf("tor: write torrc: %w", err)
	}
	controlFile := filepath.Join(torData, "control_port")
	_ = os.Remove(controlFile)
	cmd := exec.Command(binary, "-f", torrcPath)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	if err := cmd.Start(); err != nil {
		_ = proxyListener.Close()
		return nil, fmt.Errorf("tor: start process: %w", err)
	}
	cmdDone := make(chan struct{})
	go func() { _ = cmd.Wait(); close(cmdDone) }()
	startup := time.Duration(cfg.StartupTimeout) * time.Second
	if startup <= 0 {
		startup = 60 * time.Second
	}
	controlAddr, err := waitControlPort(ctx, cmd, cmdDone, controlFile, startup)
	if err != nil {
		_ = stopTor(cmd, nil, cmdDone)
		_ = proxyListener.Close()
		return nil, fmt.Errorf("tor control port (%s): %w; stderr: %s", torrcPath, err, strings.TrimSpace(stderr.String()))
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", controlAddr)
	cancel()
	if err != nil {
		_ = stopTor(cmd, nil, cmdDone)
		_ = proxyListener.Close()
		return nil, fmt.Errorf("tor: connect control port: %w", err)
	}
	ctrl := control.NewConn(textproto.NewConn(conn))
	if err := ctrl.Authenticate(""); err != nil {
		_ = stopTor(cmd, ctrl, cmdDone)
		_ = proxyListener.Close()
		return nil, fmt.Errorf("tor: authenticate control port: %w", err)
	}
	events := make(chan control.Event, 32)
	if err := ctrl.AddEventListener(events, control.EventCodeStatusClient, control.EventCodeHSDesc); err != nil {
		_ = stopTor(cmd, ctrl, cmdDone)
		_ = proxyListener.Close()
		return nil, fmt.Errorf("tor: subscribe to events: %w", err)
	}
	eventCtx, eventCancel := context.WithCancel(ctx)
	go func() { _ = ctrl.HandleEvents(eventCtx) }()
	cleanup := func() {
		eventCancel()
		_ = stopTor(cmd, ctrl, cmdDone)
		_ = proxyListener.Close()
	}
	if err := ctrl.SetConf(control.NewKeyVal("DisableNetwork", "0")); err != nil {
		cleanup()
		return nil, fmt.Errorf("tor: enable network: %w", err)
	}
	bootTimeout := time.Duration(cfg.BootstrapTimeout) * time.Second
	if bootTimeout <= 0 {
		bootTimeout = 180 * time.Second
	}
	bootCtx, bootCancel := context.WithTimeout(ctx, bootTimeout)
	err = waitBootstrap(bootCtx, ctrl, events)
	bootCancel()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("tor bootstrap: %w", err)
	}
	hostname, err := waitHostname(ctx, filepath.Join(dataDir, "tor", "site", "hostname"), bootTimeout)
	if err != nil {
		cleanup()
		return nil, err
	}
	if err := waitDescriptorUpload(ctx, events); err != nil {
		log.Printf("[Tor] hidden-service descriptor is not uploaded yet: %v", err)
	}
	svc := &TorService{cmd: cmd, processDone: cmdDone, ctrl: ctrl, eventCancel: eventCancel, onionAddress: hostname, listener: proxyListener}
	if cfg.UseNetwork {
		if entries, infoErr := ctrl.GetInfo("net/listeners/socks"); infoErr == nil && len(entries) > 0 {
			addr := strings.Trim(entries[0].Val, "\"[]")
			if d, dialErr := proxy.SOCKS5("tcp", addr, nil, proxy.Direct); dialErr == nil {
				if cd, ok := d.(proxy.ContextDialer); ok {
					svc.dialer = cd
				}
			}
		}
	}
	log.Printf("[Tor] hidden service started: %s", hostname)
	return svc, nil
}

var controlPortPattern = regexp.MustCompile(`^PORT=(127\.0\.0\.1:[0-9]{1,5})\n$`)

func waitControlPort(ctx context.Context, cmd *exec.Cmd, done <-chan struct{}, file string, timeout time.Duration) (string, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if data, err := os.ReadFile(file); err == nil {
			if match := controlPortPattern.FindSubmatch(data); match != nil {
				_, portText, splitErr := net.SplitHostPort(string(match[1]))
				if splitErr == nil {
					port, _ := strconv.Atoi(portText)
					if port > 0 && port <= 65535 {
						return string(match[1]), nil
					}
				}
			}
		}
		select {
		case <-done:
			return "", fmt.Errorf("tor exited before control port opened: %v", cmd.ProcessState)
		case <-ctx.Done():
			return "", ctx.Err()
		case <-timer.C:
			return "", fmt.Errorf("control_port file not ready after %s", timeout)
		case <-ticker.C:
		}
	}
}

func waitBootstrap(ctx context.Context, ctrl *control.Conn, events <-chan control.Event) error {
	if info, err := ctrl.GetInfo("status/bootstrap-phase"); err == nil && len(info) > 0 && strings.Contains(info[0].Val, "PROGRESS=100") {
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event := <-events:
			status, ok := event.(*control.StatusEvent)
			if !ok {
				continue
			}
			if status.Type == control.EventCodeStatusClient && status.Arguments["PROGRESS"] == "100" {
				return nil
			}
			if status.Severity == "WARN" || status.Severity == "ERR" {
				log.Printf("[Tor] bootstrap notice: %s", status.Raw)
			}
		}
	}
}

func waitDescriptorUpload(ctx context.Context, events <-chan control.Event) error {
	uploadCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for {
		select {
		case <-uploadCtx.Done():
			return uploadCtx.Err()
		case event := <-events:
			if descriptor, ok := event.(*control.HSDescEvent); ok {
				if descriptor.Action == "UPLOADED" {
					return nil
				}
				if descriptor.Action == "FAILED" {
					log.Printf("[Tor] hidden-service descriptor upload failed: %s", descriptor.Reason)
				}
			}
		}
	}
}

func waitHostname(ctx context.Context, path string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 180 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if data, err := os.ReadFile(path); err == nil {
			address := strings.TrimSpace(string(data))
			if validOnion(address) {
				return address, nil
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-timer.C:
			return "", fmt.Errorf("tor hostname was not generated at %s", path)
		case <-ticker.C:
		}
	}
}

func validOnion(address string) bool {
	if !strings.HasSuffix(address, ".onion") {
		return false
	}
	name := strings.TrimSuffix(address, ".onion")
	if len(name) != 56 {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '2' || r > '7') {
			return false
		}
	}
	return true
}

func stopTor(cmd *exec.Cmd, ctrl *control.Conn, done <-chan struct{}) error {
	if ctrl != nil {
		_ = ctrl.Signal("SHUTDOWN")
		_ = ctrl.Close()
	}
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-time.After(10 * time.Second):
	}
	if runtime.GOOS == "windows" {
		_ = cmd.Process.Kill()
	} else {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
	}
	_ = cmd.Process.Kill()
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("tor process did not exit after kill")
	}
}

func ensureTorDirs(configDir, dataDir string) error {
	for _, path := range []string{filepath.Join(configDir, "tor"), filepath.Join(dataDir, "tor"), filepath.Join(dataDir, "tor", "site")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			return fmt.Errorf("mkdir %s: %w", path, err)
		}
		if err := os.Chmod(path, 0700); err != nil {
			return fmt.Errorf("secure %s: %w", path, err)
		}
	}
	return nil
}

func ensureTorrc(path string, content []byte) (bool, error) {
	if err := os.WriteFile(path, content, 0600); err != nil {
		return false, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return false, err
	}
	return true, nil
}

func getTorConfig(cfg *TorConfig, hsDir string, backendPort int, dataDir string) string {
	socks := "SocksPort 0"
	if cfg.UseNetwork || cfg.AllowUserPreference {
		socks = "SocksPort 127.0.0.1:auto\nSocksPolicy accept 127.0.0.1"
	}
	safe := 1
	if !cfg.SafeLogging {
		safe = 0
	}
	closeCircuit := 0
	if cfg.CloseCircuitOnStreamLimit {
		closeCircuit = 1
	}
	accounting := ""
	if cfg.MaxMonthlyBandwidth != "" && cfg.MaxMonthlyBandwidth != "unlimited" {
		accounting = "AccountingStart month 1 00:00\nAccountingMax " + cfg.MaxMonthlyBandwidth
	}
	return fmt.Sprintf("DataDirectory %s\nControlPort 127.0.0.1:auto\nControlPortWriteToFile %s\nCookieAuthentication 1\nDisableNetwork 1\n__OwningControllerProcess %d\n%s\nSafeLogging %d\nMaxCircuitDirtiness 600\nMaxClientCircuitsPending %d\nCircuitBuildTimeout %d\nLearnCircuitBuildTimeout 0\nBandwidthRate %s\nBandwidthBurst %s\n%s\nExitRelay 0\nExitPolicy reject *:*\nORPort 0\nDirPort 0\nPublishServerDescriptor 0\nVanguardsLiteEnabled 1\nHiddenServiceDir %s\nHiddenServiceVersion 3\nHiddenServiceNumIntroductionPoints %d\nHiddenServiceMaxStreams %d\nHiddenServiceMaxStreamsCloseCircuit %d\nHiddenServicePort %d 127.0.0.1:%d\nHiddenServiceExportCircuitID haproxy\n",
		dataDir, filepath.Join(dataDir, "control_port"), os.Getpid(), socks, safe, cfg.MaxCircuits, cfg.CircuitTimeout,
		cfg.BandwidthRate, cfg.BandwidthBurst, accounting, hsDir, cfg.NumIntroPoints, cfg.MaxStreamsPerCircuit, closeCircuit, cfg.VirtualPort, backendPort)
}
