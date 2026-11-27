package tor

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cretz/bine/control"
	"github.com/pires/go-proxyproto"
)

func TestGetTorConfigDeclaresPersistedHiddenService(t *testing.T) {
	cfg := DefaultTorConfig()
	config := getTorConfig(&cfg, "/var/lib/whois/tor/site", 64321, "/var/lib/whois/tor")
	for _, required := range []string{
		"DataDirectory /var/lib/whois/tor", "ControlPort 127.0.0.1:auto", "ControlPortWriteToFile /var/lib/whois/tor/control_port",
		"CookieAuthentication 1", "DisableNetwork 1", "__OwningControllerProcess", "HiddenServiceDir /var/lib/whois/tor/site",
		"HiddenServiceVersion 3", "HiddenServicePort 80 127.0.0.1:64321", "HiddenServiceExportCircuitID haproxy", "VanguardsLiteEnabled 1",
	} {
		if !strings.Contains(config, required) {
			t.Errorf("torrc missing %q", required)
		}
	}
	if strings.Contains(config, "ADD_ONION") || strings.Contains(config, "9050") || strings.Contains(config, "9051") {
		t.Fatal("torrc contains forbidden ADD_ONION/default port configuration")
	}
}

func TestGetTorConfigDisablesOutboundSocksAndAppliesLimits(t *testing.T) {
	cfg := DefaultTorConfig()
	cfg.AllowUserPreference = false
	cfg.MaxCircuits = 41
	cfg.CircuitTimeout = 75
	cfg.MaxMonthlyBandwidth = "unlimited"
	config := getTorConfig(&cfg, "/tmp/site", 63001, "/tmp/tor")
	for _, line := range []string{"SocksPort 0", "MaxClientCircuitsPending 41", "CircuitBuildTimeout 75", "LearnCircuitBuildTimeout 0", "HiddenServiceNumIntroductionPoints 3", "HiddenServiceMaxStreams 100", "HiddenServiceMaxStreamsCloseCircuit 1"} {
		if !strings.Contains(config, line) {
			t.Errorf("torrc missing %q", line)
		}
	}
	if strings.Contains(config, "AccountingMax") {
		t.Error("unlimited accounting unexpectedly emitted")
	}
}

func TestEnsureTorDirsUsesPrivateModes(t *testing.T) {
	root := t.TempDir()
	configDir, dataDir := filepath.Join(root, "config"), filepath.Join(root, "data")
	if err := ensureTorDirs(configDir, dataDir); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(configDir, "tor"), filepath.Join(dataDir, "tor"), filepath.Join(dataDir, "tor", "site")} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0700 {
			t.Errorf("%s mode = %04o, want 0700", dir, got)
		}
	}
}

func TestWaitControlPortWaitsForCompleteLoopbackAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control_port")
	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = os.WriteFile(path, []byte("PORT=127.0.0.1:"), 0600)
		time.Sleep(300 * time.Millisecond)
		_ = os.WriteFile(path, []byte("PORT=127.0.0.1:12345\n"), 0600)
	}()
	addr, err := waitControlPort(ctx, nil, done, path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:12345" {
		t.Fatalf("address = %q", addr)
	}
}

func TestWaitControlPortRejectsNonLoopback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control_port")
	if err := os.WriteFile(path, []byte("PORT=0.0.0.0:12345\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := waitControlPort(ctx, nil, make(chan struct{}), path, time.Second)
	if err == nil {
		t.Fatal("expected non-loopback port to be rejected")
	}
}

func TestValidOnion(t *testing.T) {
	good := strings.Repeat("a", 56) + ".onion"
	if !validOnion(good) {
		t.Fatal("valid v3 onion rejected")
	}
	for _, bad := range []string{"short.onion", strings.Repeat("0", 56) + ".onion", strings.Repeat("a", 56) + ".onion\nextra"} {
		if validOnion(bad) {
			t.Errorf("invalid onion accepted: %q", bad)
		}
	}
}

func TestTorServiceAccessorsAndHealth(t *testing.T) {
	empty := &TorService{onionAddress: "abc.onion"}
	if empty.OnionAddress() != "abc.onion" || empty.OutboundEnabled() || empty.PID() != 0 || empty.Version() != "" || empty.BootstrapPercent() != 0 || empty.CircuitEstablished() {
		t.Fatalf("empty service accessors = address %q, outbound %v, pid %d, version %q, bootstrap %d, circuit %v", empty.OnionAddress(), empty.OutboundEnabled(), empty.PID(), empty.Version(), empty.BootstrapPercent(), empty.CircuitEstablished())
	}
	if err := empty.Health(context.Background()); err == nil {
		t.Fatal("Health should reject a service with no process")
	}
	if got := empty.GetHTTPClient(true).Timeout; got != 30*time.Second {
		t.Errorf("client timeout with no dialer = %s, want 30s", got)
	}
	live := &TorService{cmd: &exec.Cmd{Process: &os.Process{Pid: 123}}}
	if live.PID() != 123 {
		t.Errorf("PID = %d, want 123", live.PID())
	}
	if err := live.Health(context.Background()); err != nil {
		t.Errorf("Health for live process: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := live.Health(ctx); err != context.Canceled {
		t.Errorf("Health with canceled context = %v, want context.Canceled", err)
	}
	if err := empty.Close(); err != nil {
		t.Errorf("Close without process: %v", err)
	}
}

func TestWaitHostnameAndDescriptorUpload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hostname")
	if err := os.WriteFile(path, []byte("not-an-onion\n"), 0600); err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("a", 56) + ".onion"
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(path, []byte(want+"\n"), 0600)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := waitHostname(ctx, path, time.Second)
	if err != nil || got != want {
		t.Fatalf("waitHostname() = %q, %v; want %q", got, err, want)
	}
	if _, err := waitHostname(context.Background(), filepath.Join(t.TempDir(), "missing"), 10*time.Millisecond); err == nil {
		t.Fatal("waitHostname should time out when the hostname is absent")
	}
	events := make(chan control.Event, 1)
	events <- &control.HSDescEvent{Action: "UPLOADED"}
	if err := waitDescriptorUpload(context.Background(), events); err != nil {
		t.Fatalf("waitDescriptorUpload() = %v", err)
	}
	canceled, cancelUpload := context.WithCancel(context.Background())
	cancelUpload()
	if err := waitDescriptorUpload(canceled, make(chan control.Event)); err != context.Canceled {
		t.Errorf("waitDescriptorUpload(canceled) = %v, want context.Canceled", err)
	}
}

func TestFindBinaryAndCircuitID(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "tor")
	if err := os.WriteFile(binary, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := FindBinary(binary); got != binary {
		t.Fatalf("FindBinary(configured) = %q, want %q", got, binary)
	}
	if got := FindBinary(filepath.Join(root, "missing")); got == filepath.Join(root, "missing") {
		t.Fatalf("FindBinary accepted missing configured path %q", got)
	}
	if id, ok := CircuitIDFromIPv6(net.ParseIP("fd00::2a").To16()); !ok || id != 42 {
		t.Errorf("CircuitIDFromIPv6() = (%d,%v), want (42,true)", id, ok)
	}
	if id, ok := CircuitIDFromIPv6([]byte{1, 2}); ok || id != 0 {
		t.Errorf("CircuitIDFromIPv6(short) = (%d,%v), want (0,false)", id, ok)
	}
}

func TestTorServiceServeProxyProtocolRequest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyListener := &proxyproto.Listener{Listener: listener, ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
		return proxyproto.REQUIRE, nil
	}}
	service := &TorService{listener: proxyListener}
	served := make(chan struct{}, 1)
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- service.Serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.RemoteAddr != "198.51.100.7:12345" {
				t.Errorf("PROXY remote address = %q", r.RemoteAddr)
			}
			_, _ = fmt.Fprint(w, "ok")
			served <- struct{}{}
		}), 0, 0, 0)
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		_ = proxyListener.Close()
		t.Fatal(err)
	}
	_, err = fmt.Fprint(conn, "PROXY TCP4 198.51.100.7 127.0.0.1 12345 80\r\nGET / HTTP/1.1\r\nHost: example.onion\r\nConnection: close\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("response status = %d, want 200", response.StatusCode)
	}
	<-served
	_ = conn.Close()
	_ = proxyListener.Close()
	if err := <-serveDone; err == nil {
		t.Fatal("Serve returned nil after the listener was closed")
	}
}
