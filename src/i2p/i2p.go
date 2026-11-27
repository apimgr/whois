// Package i2p implements the optional SAMv3 eepsite and dedicated i2pd provider.
package i2p

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var i2pBase64 = base64Encoding()
var ErrDuplicateDestination = errors.New("I2P destination is already in use")

func base64Encoding() *base64.Encoding {
	return base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~")
}

type Config struct {
	Enabled                                                                                                        bool
	Binary, SAMAddress, ConfigDir, DataDir, LogDir                                                                 string
	VirtualPort, InboundLength, OutboundLength, InboundQuantity, OutboundQuantity, SignatureType, BootstrapTimeout int
	StateHook                                                                                                      func(string)
}

type Provider string

const (
	ProviderI2PD Provider = "i2pd"
	ProviderSAM  Provider = "sam"
)

type Service struct {
	mu                           sync.Mutex
	provider                     Provider
	control, forward             net.Conn
	controlReader, forwardReader *bufio.Reader
	command                      *exec.Cmd
	exited                       chan struct{}
	pidPath                      string
	address, status, samAddress  string
	backendPort                  int
	lost                         chan struct{}
	probeFailures                int
	cfg                          Config
}

func FindBinary(configured string) string {
	if configured != "" {
		if st, err := os.Stat(configured); err == nil && !st.IsDir() {
			return configured
		}
	}
	for _, path := range []string{"/usr/bin/i2pd", "/usr/sbin/i2pd", "/usr/local/bin/i2pd", "/opt/homebrew/bin/i2pd"} {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path
		}
	}
	path, _ := exec.LookPath("i2pd")
	return path
}

func Resolve(cfg Config) (Provider, string, string) {
	if binary := FindBinary(cfg.Binary); binary != "" {
		return ProviderI2PD, binary, ""
	}
	address := cfg.SAMAddress
	if address == "" {
		address = "127.0.0.1:7656"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if ProbeSAM(ctx, address) {
		return ProviderSAM, "", address
	}
	return "", "", ""
}

func ListenBackend() (net.Listener, error) {
	start, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		return nil, err
	}
	for offset := 0; offset < 1000; offset++ {
		port := 64000 + int(start.Int64()) + offset
		if port > 64999 {
			port = 64000 + (port - 65000)
		}
		listener, listenErr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if listenErr == nil {
			return listener, nil
		}
	}
	return nil, errors.New("no unused I2P backend port in 64000-64999")
}

func ProbeSAM(ctx context.Context, address string) bool {
	conn, reader, err := samDial(ctx, address)
	if err != nil {
		return false
	}
	_ = reader
	_ = conn.Close()
	return true
}

func Start(ctx context.Context, cfg Config, backendPort int) (*Service, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	provider, binary, samAddress := Resolve(cfg)
	if provider == "" {
		return nil, errors.New("no I2P provider available")
	}
	if cfg.BootstrapTimeout < 30 || cfg.BootstrapTimeout > 600 {
		cfg.BootstrapTimeout = 300
	}
	if cfg.DataDir == "" || cfg.ConfigDir == "" {
		return nil, errors.New("I2P data and config directories are required")
	}
	if err := ensureDirs(cfg); err != nil {
		return nil, err
	}
	s := &Service{provider: provider, status: "starting", cfg: cfg, backendPort: backendPort}
	s.setStatus("starting")
	if provider == ProviderI2PD {
		var err error
		samAddress, err = startI2PD(ctx, cfg, binary, s)
		if err != nil {
			_ = s.Close()
			return nil, err
		}
	}
	s.samAddress = samAddress
	if err := s.startSession(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Service) startSession(ctx context.Context) error {
	deadlineCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.BootstrapTimeout)*time.Second)
	defer cancel()
	control, cr, err := samDial(deadlineCtx, s.samAddress)
	if err != nil {
		return errors.New("I2P control HELLO failed")
	}
	keyPath := filepath.Join(s.cfg.DataDir, "i2p", "site", "site-keys.dat")
	priv, err := loadOrCreateDestination(control, cr, keyPath, s.cfg.SignatureType)
	if err != nil {
		_ = control.Close()
		return err
	}
	destination, err := destinationBytes(priv)
	if err != nil {
		_ = control.Close()
		return errors.New("I2P destination key is invalid")
	}
	s.address = b32Address(destination)
	s.setStatus("building")
	id := fmt.Sprintf("site-%d", os.Getpid())
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			id = fmt.Sprintf("%s-%d", id, time.Now().UnixNano())
		}
		rep, commandErr := samCommand(control, cr, time.Duration(s.cfg.BootstrapTimeout)*time.Second,
			"SESSION CREATE STYLE=STREAM ID=%s DESTINATION=%s i2cp.leaseSetEncType=4 inbound.length=%d outbound.length=%d inbound.quantity=%d outbound.quantity=%d",
			id, priv, s.cfg.InboundLength, s.cfg.OutboundLength, s.cfg.InboundQuantity, s.cfg.OutboundQuantity)
		if commandErr != nil {
			_ = control.Close()
			return errors.New("I2P SESSION CREATE timed out or failed")
		}
		if rep.fields["RESULT"] == "OK" {
			break
		}
		if rep.fields["RESULT"] == "DUPLICATED_ID" && attempt == 0 {
			continue
		}
		_ = control.Close()
		if rep.fields["RESULT"] == "DUPLICATED_DEST" {
			return ErrDuplicateDestination
		}
		if rep.fields["RESULT"] == "INVALID_KEY" {
			return errors.New("I2P destination key is invalid")
		}
		return errors.New("I2P SESSION CREATE rejected")
	}
	forward, fr, err := samDial(deadlineCtx, s.samAddress)
	if err != nil {
		_ = control.Close()
		return errors.New("I2P forward HELLO failed")
	}
	rep, err := samCommand(forward, fr, 10*time.Second, "STREAM FORWARD ID=%s PORT=%d HOST=127.0.0.1 SILENT=true", id, s.backendPort)
	if err != nil || rep.fields["RESULT"] != "OK" {
		_ = forward.Close()
		_ = control.Close()
		return errors.New("I2P STREAM FORWARD failed")
	}
	s.control, s.controlReader, s.forward, s.forwardReader = control, cr, forward, fr
	s.lost = make(chan struct{}, 1)
	go s.watchControl(control)
	go s.watchControl(forward)
	s.setStatus("running")
	return nil
}

func RetryDelay(err error) time.Duration {
	if errors.Is(err, ErrDuplicateDestination) {
		return 60 * time.Second
	}
	return 0
}

func (s *Service) watchControl(conn net.Conn) {
	var one [1]byte
	_, _ = conn.Read(one[:])
	select {
	case s.lost <- struct{}{}:
	default:
	}
}

type samReply struct {
	topic, action string
	fields        map[string]string
}

func parseReply(line string) *samReply {
	parts := strings.Fields(strings.TrimSpace(line))
	r := &samReply{fields: make(map[string]string)}
	if len(parts) > 0 {
		r.topic = parts[0]
	}
	if len(parts) > 1 {
		r.action = parts[1]
	}
	for _, part := range parts[2:] {
		k, v, ok := strings.Cut(part, "=")
		if ok {
			r.fields[k] = strings.Trim(v, `"`)
		}
	}
	return r
}

func samDial(ctx context.Context, address string) (net.Conn, *bufio.Reader, error) {
	if address == "" {
		address = "127.0.0.1:7656"
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	reader := bufio.NewReader(conn)
	helloTimeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < helloTimeout {
		helloTimeout = time.Until(deadline)
	}
	reply, err := samCommand(conn, reader, helloTimeout, "HELLO VERSION MIN=3.1 MAX=3.3")
	if err != nil || reply.topic != "HELLO" || reply.fields["RESULT"] != "OK" {
		_ = conn.Close()
		return nil, nil, errors.New("SAM HELLO rejected")
	}
	return conn, reader, nil
}

func samCommand(conn net.Conn, reader *bufio.Reader, timeout time.Duration, format string, args ...any) (*samReply, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	if _, err := fmt.Fprintf(conn, format+"\n", args...); err != nil {
		return nil, errors.New("SAM write failed")
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, errors.New("SAM read failed")
	}
	return parseReply(line), nil
}

func destinationBytes(priv string) ([]byte, error) {
	raw, err := i2pBase64.DecodeString(priv)
	if err != nil || len(raw) < 387 {
		return nil, errors.New("invalid I2P destination")
	}
	n := 387 + int(binary.BigEndian.Uint16(raw[385:387]))
	if len(raw) < n {
		return nil, errors.New("truncated I2P destination")
	}
	return raw[:n], nil
}

func loadOrCreateDestination(conn net.Conn, reader *bufio.Reader, path string, sigType int) (string, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		key := strings.TrimSpace(string(b))
		if _, err = destinationBytes(key); err != nil {
			return "", fmt.Errorf("corrupt I2P destination key file %s", path)
		}
		_ = os.Chmod(path, 0600)
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	rep, err := samCommand(conn, reader, 10*time.Second, "DEST GENERATE SIGNATURE_TYPE=%d", sigType)
	if err != nil {
		return "", errors.New("I2P DEST GENERATE failed")
	}
	priv := rep.fields["PRIV"]
	if _, err = destinationBytes(priv); err != nil {
		return "", errors.New("I2P DEST GENERATE returned an invalid key")
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	if _, err = io.WriteString(f, priv+"\n"); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err = os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if dir, openErr := os.Open(filepath.Dir(path)); openErr == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return priv, nil
}

func b32Address(dest []byte) string {
	sum := sha256.Sum256(dest)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])) + ".b32.i2p"
}

func ensureDirs(cfg Config) error {
	for _, dir := range []string{filepath.Join(cfg.ConfigDir, "i2p"), filepath.Join(cfg.DataDir, "i2p"), filepath.Join(cfg.DataDir, "i2p", "site")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return err
		}
	}
	return nil
}

func i2pdConfig(port int, logPath string) string {
	return fmt.Sprintf("daemon = false\nipv4 = true\nipv6 = false\nnotransit = true\nfloodfill = false\nlog = file\nlogfile = %s\nloglevel = warn\n\n[http]\nenabled = false\n[httpproxy]\nenabled = false\n[socksproxy]\nenabled = false\n[sam]\nenabled = true\naddress = 127.0.0.1\nport = %d\n[bob]\nenabled = false\n[i2cp]\nenabled = false\n[i2pcontrol]\nenabled = false\n[upnp]\nenabled = false\n", logPath, port)
}

func writePrivate(path string, content []byte) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if err := os.WriteFile(tmp, content, 0600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = f.Sync()
	_ = f.Close()
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func startI2PD(ctx context.Context, cfg Config, binary string, s *Service) (string, error) {
	confDir := filepath.Join(cfg.ConfigDir, "i2p")
	dataDir := filepath.Join(cfg.DataDir, "i2p")
	logPath := filepath.Join(cfg.LogDir, "i2pd.log")
	for _, dir := range []string{cfg.LogDir} {
		if dir != "" {
			if err := os.MkdirAll(dir, 0750); err != nil {
				return "", err
			}
		}
	}
	conf := filepath.Join(confDir, "i2pd.conf")
	tunconf := filepath.Join(confDir, "tunnels.conf")
	tunDir := filepath.Join(confDir, "tunnels.d")
	pid := filepath.Join(dataDir, "i2pd.pid")
	port, err := unusedLoopbackPort()
	if err != nil {
		return "", err
	}
	if err = writePrivate(conf, []byte(i2pdConfig(port, logPath))); err != nil {
		return "", err
	}
	if err = writePrivate(tunconf, nil); err != nil {
		return "", err
	}
	if err = os.MkdirAll(tunDir, 0700); err != nil {
		return "", err
	}
	if err = os.Chmod(tunDir, 0700); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(tunDir)
	if err != nil {
		return "", err
	}
	if len(entries) > 0 {
		return "", errors.New("i2pd tunnels.d must be empty")
	}
	if err = reapStale(pid, binary); err != nil {
		return "", err
	}
	cmd := exec.Command(binary, "--conf", conf, "--tunconf", tunconf, "--tunnelsdir", tunDir, "--datadir", dataDir, "--pidfile", pid)
	setParentDeathSignal(cmd)
	if err = cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start dedicated i2pd; see %s", logPath)
	}
	s.command = cmd
	s.exited = make(chan struct{})
	s.pidPath = pid
	go func() { _ = cmd.Wait(); close(s.exited) }()
	_ = os.WriteFile(pid, []byte(fmt.Sprintf("%d\n", cmd.Process.Pid)), 0600)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	waitCtx, waitCancel := context.WithTimeout(ctx, 60*time.Second)
	defer waitCancel()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		probeCtx, cancel := context.WithTimeout(waitCtx, 2*time.Second)
		conn, _, dialErr := samDial(probeCtx, address)
		cancel()
		if dialErr == nil {
			_ = conn.Close()
			return address, nil
		}
		select {
		case <-s.exited:
			return "", fmt.Errorf("i2pd exited before SAM became ready; see %s", logPath)
		case <-waitCtx.Done():
			s.stopProcess()
			return "", fmt.Errorf("i2pd SAM startup timed out; see %s", logPath)
		case <-tick.C:
		}
	}
}

func unusedLoopbackPort() (int, error) {
	l, err := ListenBackend()
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}
func reapStale(path, binary string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var pid int
	if _, err = fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid); err != nil || pid <= 1 {
		return nil
	}
	if !processAlive(pid) {
		_ = os.Remove(path)
		return nil
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || filepath.Clean(exe) != filepath.Clean(binary) {
		return nil
	}
	args, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || !strings.Contains(string(args), "i2pd.conf") {
		return nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	signalProcess(proc)
	for n := 0; n < 100 && processAlive(pid); n++ {
		time.Sleep(100 * time.Millisecond)
	}
	if processAlive(pid) {
		_ = proc.Kill()
		for n := 0; n < 100 && processAlive(pid); n++ {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if processAlive(pid) {
		return fmt.Errorf("stale owned i2pd process %d did not exit", pid)
	}
	_ = os.Remove(path)
	return nil
}
func (s *Service) stopProcess() {
	if s.command == nil || s.command.Process == nil {
		return
	}
	signalProcess(s.command.Process)
	select {
	case <-s.exited:
	case <-time.After(10 * time.Second):
		_ = s.command.Process.Kill()
		<-s.exited
	}
	s.command = nil
	if s.pidPath != "" {
		_ = os.Remove(s.pidPath)
		s.pidPath = ""
	}
}

func (s *Service) Address() string    { s.mu.Lock(); defer s.mu.Unlock(); return s.address }
func (s *Service) Status() string     { s.mu.Lock(); defer s.mu.Unlock(); return s.status }
func (s *Service) Provider() Provider { return s.provider }
func (s *Service) setStatus(value string) {
	s.mu.Lock()
	s.status = value
	s.mu.Unlock()
	if s.cfg.StateHook != nil {
		s.cfg.StateHook(value)
	}
}

func (s *Service) Health(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.control == nil || s.forward == nil {
		return errors.New("I2P session is closed")
	}
	if s.provider == ProviderI2PD {
		select {
		case <-s.exited:
			return errors.New("i2pd process exited")
		default:
			return nil
		}
	}
	select {
	case <-s.lost:
		return errors.New("I2P SAM control connection closed")
	default:
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, reader, err := samDial(probeCtx, s.samAddress)
	if err == nil {
		_, err = samCommand(conn, reader, 5*time.Second, "QUIT")
		_ = conn.Close()
	}
	if err == nil {
		s.probeFailures = 0
		return nil
	}
	s.probeFailures++
	if s.probeFailures < 3 {
		return nil
	}
	return errors.New("I2P SAM probe failed three times")
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.forward != nil {
		_ = s.forward.Close()
		s.forward = nil
	}
	if s.control != nil {
		_ = s.control.Close()
		s.control = nil
	}
	s.status = "disabled"
	s.mu.Unlock()
	if s.cfg.StateHook != nil {
		s.cfg.StateHook("disabled")
	}
	s.stopProcess()
	return nil
}
