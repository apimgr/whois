package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenEmpty(t *testing.T) {
	// Empty dir = no-op; should not error.
	l, err := Open("")
	if err != nil {
		t.Fatalf("Open(\"\") returned error: %v", err)
	}
	defer l.Close()

	// All writes must be no-ops (no panic, no error).
	l.WriteAccess("127.0.0.1", "GET", "/", "HTTP/1.1", 200, 42, "", "test/1.0")
	l.Info("test info")
	l.Warn("test warn")
	l.Error("test error")
	l.WriteAudit(AuditEntry{Category: "test", Action: "open", Success: true})
	l.WriteSecurity("test event")
}

func TestOpenCreatesFiles(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	for _, name := range []string{"access.log", "server.log", "error.log", "audit.log", "security.log"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}
}

func TestWriteAccess(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	l.WriteAccess("1.2.3.4", "GET", "/api/v1/whois/example.com", "HTTP/1.1", 200, 512, "https://example.com/", "curl/7.64.1")

	data, err := os.ReadFile(filepath.Join(dir, "access.log"))
	if err != nil {
		t.Fatalf("read access.log: %v", err)
	}

	line := strings.TrimSpace(string(data))

	// Apache Combined Log: host ident auth [time] "method path proto" status bytes "referer" "agent"
	if !strings.HasPrefix(line, "1.2.3.4 - - [") {
		t.Errorf("unexpected access log prefix: %q", line)
	}
	if !strings.Contains(line, `"GET /api/v1/whois/example.com HTTP/1.1"`) {
		t.Errorf("missing request field in access log: %q", line)
	}
	if !strings.Contains(line, " 200 512 ") {
		t.Errorf("missing status/bytes in access log: %q", line)
	}
	if !strings.Contains(line, `"https://example.com/"`) {
		t.Errorf("missing referer in access log: %q", line)
	}
	if !strings.Contains(line, `"curl/7.64.1"`) {
		t.Errorf("missing user-agent in access log: %q", line)
	}
}

func TestWriteServerLog(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	l.Info("server started", "port", 64000)
	l.Warn("low disk space", "free_mb", 100)

	data, err := os.ReadFile(filepath.Join(dir, "server.log"))
	if err != nil {
		t.Fatalf("read server.log: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "server started") {
		t.Errorf("missing INFO message in server.log: %q", content)
	}
	if !strings.Contains(content, "low disk space") {
		t.Errorf("missing WARN message in server.log: %q", content)
	}
	// No ANSI codes.
	if strings.Contains(content, "\x1b[") {
		t.Errorf("server.log contains ANSI escape codes")
	}
}

func TestWriteErrorLog(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	l.Error("database connection failed", "driver", "sqlite")

	data, err := os.ReadFile(filepath.Join(dir, "error.log"))
	if err != nil {
		t.Fatalf("read error.log: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "database connection failed") {
		t.Errorf("missing error message in error.log: %q", content)
	}
	// Error also written to server.log.
	serverData, _ := os.ReadFile(filepath.Join(dir, "server.log"))
	if !strings.Contains(string(serverData), "database connection failed") {
		t.Errorf("error not mirrored to server.log")
	}
}

func TestWriteAuditLog(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	l.WriteAudit(AuditEntry{
		Category:   "auth",
		Action:     "token_validated",
		ActorIP:    "10.0.0.1",
		TargetType: "server",
		TargetID:   "self",
		Success:    true,
	})

	data, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("read audit.log: %v", err)
	}

	// Must be valid JSON on every line.
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Errorf("audit.log line is not valid JSON: %q — %v", line, err)
		}
		if entry.Category != "auth" {
			t.Errorf("unexpected category %q", entry.Category)
		}
		if entry.Action != "token_validated" {
			t.Errorf("unexpected action %q", entry.Action)
		}
	}
}

func TestWriteSecurityLog(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	l.WriteSecurity("Failed authentication attempt from 192.168.1.100")

	data, err := os.ReadFile(filepath.Join(dir, "security.log"))
	if err != nil {
		t.Fatalf("read security.log: %v", err)
	}

	line := strings.TrimSpace(string(data))
	if !strings.Contains(line, "[security]") {
		t.Errorf("missing [security] tag in security.log: %q", line)
	}
	if !strings.Contains(line, "192.168.1.100") {
		t.Errorf("missing IP in security.log: %q", line)
	}
}

func TestRotate(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	l.Info("before rotate")

	// Rename access.log to simulate external rotation.
	oldPath := filepath.Join(dir, "access.log")
	newPath := filepath.Join(dir, "access.log.1")
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatalf("rename: %v", err)
	}

	// Rotate should reopen a fresh access.log.
	if err := l.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	l.WriteAccess("127.0.0.1", "GET", "/", "HTTP/1.1", 200, 0, "", "")
	l.Info("after rotate")

	// New file must exist.
	if _, err := os.Stat(oldPath); err != nil {
		t.Errorf("expected new access.log after rotate: %v", err)
	}
}

func TestTimeFormat(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	before := time.Now()
	l.WriteAccess("1.2.3.4", "GET", "/", "HTTP/1.1", 200, 0, "", "")
	after := time.Now()

	data, _ := os.ReadFile(filepath.Join(dir, "access.log"))
	line := string(data)

	// Extract time string between brackets.
	start := strings.Index(line, "[")
	end := strings.Index(line, "]")
	if start < 0 || end < 0 || end <= start {
		t.Fatalf("no timestamp bracket found in: %q", line)
	}
	tStr := line[start+1 : end]

	// Must parse as Apache Combined time format.
	parsed, err := time.Parse("02/Jan/2006:15:04:05 -0700", tStr)
	if err != nil {
		t.Errorf("timestamp %q does not match Apache Combined format: %v", tStr, err)
	}
	if parsed.Before(before.Add(-time.Second)) || parsed.After(after.Add(time.Second)) {
		t.Errorf("timestamp %v out of expected range [%v, %v]", parsed, before, after)
	}
}
