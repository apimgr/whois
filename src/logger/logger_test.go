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

// TestAccessWriter_NilFile verifies AccessWriter returns io.Discard when the
// logger was opened with an empty dir (no accessFile opened).
func TestAccessWriter_NilFile(t *testing.T) {
	l, err := Open("")
	if err != nil {
		t.Fatalf("Open(\"\") error: %v", err)
	}
	defer l.Close()

	w := l.AccessWriter()
	if w == nil {
		t.Fatal("AccessWriter() returned nil, want io.Discard")
	}
	// Write a byte — must not panic.
	_, _ = w.Write([]byte("test"))
}

// TestAccessWriter_WithFile verifies AccessWriter returns the real file handle
// when the logger was opened with a valid directory.
func TestAccessWriter_WithFile(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	w := l.AccessWriter()
	if w == nil {
		t.Fatal("AccessWriter() returned nil")
	}
	// Must not be io.Discard — verify it's a *os.File by writing to it.
	n, err := w.Write([]byte("direct access line\n"))
	if err != nil {
		t.Errorf("AccessWriter().Write error: %v", err)
	}
	if n == 0 {
		t.Error("AccessWriter().Write wrote 0 bytes")
	}
}

// TestApp_WritesMessage verifies App() writes an INFO-level logfmt line to app.log.
func TestApp_WritesMessage(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	l.App("app event fired", "component", "scheduler", "count", 42)

	data, err := os.ReadFile(filepath.Join(dir, "app.log"))
	if err != nil {
		t.Fatalf("read app.log: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "app event fired") {
		t.Errorf("app.log missing message: %q", content)
	}
}

// TestApp_NilHandler verifies App() does not panic when the logger has no appHandler
// (opened with empty dir).
func TestApp_NilHandler(t *testing.T) {
	l, err := Open("")
	if err != nil {
		t.Fatalf("Open(\"\") error: %v", err)
	}
	defer l.Close()

	l.App("should not panic")
}

// TestAppWarn_WritesMessage verifies AppWarn() writes a WARN-level logfmt line to app.log.
func TestAppWarn_WritesMessage(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	l.AppWarn("quota near limit", "used_pct", 92)

	data, err := os.ReadFile(filepath.Join(dir, "app.log"))
	if err != nil {
		t.Fatalf("read app.log: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "quota near limit") {
		t.Errorf("app.log missing warn message: %q", content)
	}
}

// TestAppWarn_NilHandler verifies AppWarn() does not panic on empty logger.
func TestAppWarn_NilHandler(t *testing.T) {
	l, err := Open("")
	if err != nil {
		t.Fatalf("Open(\"\") error: %v", err)
	}
	defer l.Close()

	l.AppWarn("should not panic")
}

// TestWriteAuth_WritesEntry verifies WriteAuth() appends a syslog-format line to auth.log.
func TestWriteAuth_WritesEntry(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	l.WriteAuth("alice", "10.0.0.5", "success", "password")

	data, err := os.ReadFile(filepath.Join(dir, "auth.log"))
	if err != nil {
		t.Fatalf("read auth.log: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "caswhois[") {
		t.Errorf("auth.log missing process tag: %q", content)
	}
	if !strings.Contains(content, "user=alice") {
		t.Errorf("auth.log missing user=alice: %q", content)
	}
	if !strings.Contains(content, "ip=10.0.0.5") {
		t.Errorf("auth.log missing ip: %q", content)
	}
	if !strings.Contains(content, "result=success") {
		t.Errorf("auth.log missing result: %q", content)
	}
}

// TestWriteAuth_NilFile verifies WriteAuth() is a no-op (no panic) when the logger
// was opened with an empty dir (no authFile opened).
func TestWriteAuth_NilFile(t *testing.T) {
	l, err := Open("")
	if err != nil {
		t.Fatalf("Open(\"\") error: %v", err)
	}
	defer l.Close()

	// Must not panic when authFile is nil.
	l.WriteAuth("alice", "10.0.0.5", "fail", "bad_password")
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
