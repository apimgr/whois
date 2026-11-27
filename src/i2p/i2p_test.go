package i2p

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testPrivateDestination() (string, string) {
	dest := make([]byte, 391)
	binary.BigEndian.PutUint16(dest[385:387], 4)
	for n := 387; n < len(dest); n++ {
		dest[n] = byte(n)
	}
	priv := append(append([]byte{}, dest...), make([]byte, 64)...)
	return i2pBase64.EncodeToString(priv), i2pBase64.EncodeToString(dest)
}

func TestDestinationAddressKnownVector(t *testing.T) {
	priv, _ := testPrivateDestination()
	destination, err := destinationBytes(priv)
	if err != nil {
		t.Fatal(err)
	}
	got := b32Address(destination)
	const want = "3xc3hiv3gnophbjsyhx3vgsmiztjmriyr3mk55yhujh22j4cmrlq.b32.i2p"
	if got != want {
		t.Fatalf("address = %q, want %q", got, want)
	}
}

func TestI2PBase64RoundTrip(t *testing.T) {
	data := []byte{0xfb, 0xef, 0xff}
	encoded := i2pBase64.EncodeToString(data)
	if !strings.ContainsAny(encoded, "-~") {
		t.Fatalf("test vector did not use I2P alphabet: %q", encoded)
	}
	decoded, err := i2pBase64.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(data) {
		t.Fatalf("round trip mismatch: %x", decoded)
	}
}

func TestSAMForwardRetrySlowBootstrapAndPersistentIdentity(t *testing.T) {
	priv, pub := testPrivateDestination()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	dataDir := t.TempDir()
	keys := filepath.Join(dataDir, "i2p", "site", "site-keys.dat")
	commands := make(chan string, 16)
	go func() {
		var handlers sync.WaitGroup
		var sessionCount atomic.Int32
		for socket := 0; socket < 4; socket++ {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				break
			}
			handlers.Add(1)
			go func(socket int, conn net.Conn) {
				defer handlers.Done()
				defer func() { _ = conn.Close() }()
				reader := bufio.NewReader(conn)
				for {
					line, readErr := reader.ReadString('\n')
					if readErr != nil {
						return
					}
					line = strings.TrimSpace(line)
					commands <- fmt.Sprintf("%d:%s", socket, line)
					switch {
					case strings.HasPrefix(line, "HELLO "):
						_, _ = fmt.Fprintln(conn, "HELLO REPLY RESULT=OK VERSION=3.3")
					case strings.HasPrefix(line, "DEST GENERATE "):
						_, _ = fmt.Fprintf(conn, "DEST REPLY PUB=%s PRIV=%s\n", pub, priv)
					case strings.HasPrefix(line, "SESSION CREATE "):
						if _, statErr := os.Stat(keys); statErr != nil {
							_, _ = fmt.Fprintln(conn, "SESSION STATUS RESULT=INVALID_KEY")
						} else if sessionCount.Add(1) == 1 {
							_, _ = fmt.Fprintln(conn, "SESSION STATUS RESULT=DUPLICATED_ID")
						} else {
							time.Sleep(150 * time.Millisecond)
							_, _ = fmt.Fprintln(conn, "SESSION STATUS RESULT=OK ID=site")
						}
					case strings.HasPrefix(line, "STREAM FORWARD "):
						_, _ = fmt.Fprintln(conn, "STREAM STATUS RESULT=OK")
					}
				}
			}(socket, conn)
		}
		handlers.Wait()
	}()
	cfg := Config{Enabled: true, SAMAddress: listener.Addr().String(), DataDir: dataDir, ConfigDir: t.TempDir(), SignatureType: 7, BootstrapTimeout: 30}
	if err := ensureDirs(cfg); err != nil {
		t.Fatal(err)
	}
	svc := &Service{provider: ProviderSAM, status: "starting", cfg: cfg, samAddress: cfg.SAMAddress, backendPort: 8088}
	err = svc.startSession(context.Background())
	if err != nil {
		var seen []string
		for {
			select {
			case command := <-commands:
				seen = append(seen, command)
			default:
				t.Fatalf("startSession: %v; SAM commands: %v", err, seen)
			}
		}
	}
	if svc.Status() != "running" {
		t.Fatalf("status=%q", svc.Status())
	}
	if svc.Address() == "" {
		t.Fatal("missing b32 address")
	}
	firstAddress := svc.Address()
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	if err := svc.startSession(context.Background()); err != nil {
		t.Fatalf("second start with persisted key: %v", err)
	}
	defer func() { _ = svc.Close() }()
	if svc.Address() != firstAddress {
		t.Fatalf("destination changed after restart: %s != %s", svc.Address(), firstAddress)
	}
	if strings.TrimSpace(string(mustRead(t, keys))) != priv {
		t.Fatal("persisted destination key mismatch")
	}
	keyInfo, err := os.Stat(keys)
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Fatalf("key mode=%04o", keyInfo.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Dir(keys))
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("site directory mode=%04o", dirInfo.Mode().Perm())
	}
	var received []string
	for len(received) < 10 {
		received = append(received, <-commands)
	}
	var sessionSocket, forwardSocket = -1, -1
	var sessionIDs []string
	for _, cmd := range received {
		if strings.Contains(cmd, "SESSION CREATE") {
			if _, err := os.Stat(keys); err != nil {
				t.Fatal("key was not persisted before session create")
			}
			sessionSocket = int(cmd[0] - '0')
			for _, field := range strings.Fields(cmd) {
				if strings.HasPrefix(field, "ID=") {
					sessionIDs = append(sessionIDs, strings.TrimPrefix(field, "ID="))
				}
			}
		}
		if strings.Contains(cmd, "STREAM FORWARD") {
			forwardSocket = int(cmd[0] - '0')
			if !strings.Contains(cmd, "SILENT=true") {
				t.Fatal("forward lacks SILENT=true")
			}
		}
	}
	if len(sessionIDs) != 3 || sessionIDs[0] == sessionIDs[1] {
		t.Fatalf("duplicated session ID retry or restart failed: %v", sessionIDs)
	}
	generateCount := 0
	for _, command := range received {
		if strings.Contains(command, "DEST GENERATE") {
			generateCount++
		}
	}
	if generateCount != 1 {
		t.Fatalf("DEST GENERATE count=%d want 1 across two starts", generateCount)
	}
	if sessionSocket < 0 || forwardSocket < 0 || sessionSocket == forwardSocket {
		t.Fatalf("session socket=%d forward socket=%d", sessionSocket, forwardSocket)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCorruptDestinationIsNotRegenerated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "site-keys.dat")
	if err := os.WriteFile(path, []byte("not-a-private-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateDestination(nil, nil, path, 7); err == nil {
		t.Fatal("expected corrupt key error")
	}
	if string(mustRead(t, path)) != "not-a-private-key\n" {
		t.Fatal("corrupt key was modified")
	}
}

func TestI2PDConfigDisablesUnneededServices(t *testing.T) {
	conf := i2pdConfig(43217, "/var/log/whois/i2pd.log")
	for _, line := range []string{"notransit = true", "floodfill = false", "[sam]\nenabled = true", "address = 127.0.0.1", "port = 43217", "[http]\nenabled = false", "[httpproxy]\nenabled = false", "[socksproxy]\nenabled = false", "[bob]\nenabled = false", "[i2cp]\nenabled = false", "[i2pcontrol]\nenabled = false", "[upnp]\nenabled = false"} {
		if !strings.Contains(conf, line) {
			t.Errorf("i2pd config missing %q", line)
		}
	}
	for _, port := range []string{"7070", "4444", "4447", "7654"} {
		if strings.Contains(conf, "port = "+port) {
			t.Errorf("i2pd config exposes forbidden port %s", port)
		}
	}
}
