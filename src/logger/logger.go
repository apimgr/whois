// Package logger opens and manages all required log files for caswhois.
// Log files per AI.md PART 11:
//
//	access.log   — Apache Combined Log Format (HTTP requests)
//	server.log   — Text format (application events)
//	error.log    — Text format (error messages)
//	app.log      — logfmt format (general info/warn events)
//	auth.log     — Syslog RFC 3164 format (authentication events)
//	audit.log    — JSON format (security events; machine-parseable)
//	security.log — Fail2ban format (security/auth events)
//	debug.log    — Text format (verbose debug events; written only when debug mode enabled)
//
// All log files are raw text only: no ANSI codes, no emojis, one event per line.
package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Logger owns file handles for all required log files.
type Logger struct {
	mu sync.Mutex

	dir string
	// debugEnabled controls whether Debug() writes to debug.log.
	// Set to true when the server runs in debug/development mode.
	debugEnabled bool

	// File handles (nil when dir is empty or file could not be opened)
	accessFile   *os.File
	serverFile   *os.File
	errorFile    *os.File
	appFile      *os.File
	authFile     *os.File
	auditFile    *os.File
	securityFile *os.File
	debugFile    *os.File

	// slog handler writing to serverFile; swapped on Rotate.
	serverHandler slog.Handler
	// slog handler writing to errorFile; swapped on Rotate.
	errorHandler slog.Handler
	// slog handler writing to appFile in logfmt format; swapped on Rotate.
	appHandler slog.Handler
	// slog handler writing to debugFile; swapped on Rotate.
	debugHandler slog.Handler
}

// Open creates the log directory and opens all log files in append mode.
// If dir is empty, Open is a no-op and all writes become no-ops.
func Open(dir string) (*Logger, error) {
	return OpenWithDebug(dir, false)
}

// OpenWithDebug creates the log directory and opens all log files.
// When debugEnabled is true, debug.log is also opened and Debug() calls write to it.
func OpenWithDebug(dir string, debugEnabled bool) (*Logger, error) {
	if dir == "" {
		return &Logger{}, nil
	}

	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("logger: create log dir %s: %w", dir, err)
	}

	l := &Logger{dir: dir, debugEnabled: debugEnabled}
	if err := l.openFiles(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// openFiles opens (or reopens) each log file.  Called by Open and Rotate.
// Must be called with l.mu held OR before the logger is shared.
func (l *Logger) openFiles() error {
	files := []struct {
		name string
		dest **os.File
	}{
		{"access.log", &l.accessFile},
		{"server.log", &l.serverFile},
		{"error.log", &l.errorFile},
		{"app.log", &l.appFile},
		{"auth.log", &l.authFile},
		{"audit.log", &l.auditFile},
		{"security.log", &l.securityFile},
	}

	for _, f := range files {
		path := filepath.Join(l.dir, f.name)
		fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return fmt.Errorf("logger: open %s: %w", path, err)
		}
		*f.dest = fh
	}

	// debug.log is opened only in debug mode (AI.md PART 11).
	if l.debugEnabled {
		path := filepath.Join(l.dir, "debug.log")
		fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return fmt.Errorf("logger: open %s: %w", path, err)
		}
		l.debugFile = fh
		// debug.log uses bracket text format like server.log per AI.md PART 11.
		l.debugHandler = newBracketTextHandler(l.debugFile)
	}

	// server.log and error.log use bracket text format per AI.md PART 11:
	//   2024-10-10T13:55:36-04:00 [INFO] message key=value
	l.serverHandler = newBracketTextHandler(l.serverFile)
	l.errorHandler = newBracketTextHandler(l.errorFile)
	// app.log uses logfmt per AI.md PART 11:
	//   time=2026-05-13T10:58:00-04:00 level=INFO msg="user created" id=abc123 ip=1.2.3.4
	l.appHandler = newTextHandler(l.appFile)

	return nil
}

// Close flushes and closes all open log file handles.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, fh := range []*os.File{l.accessFile, l.serverFile, l.errorFile, l.appFile, l.authFile, l.auditFile, l.securityFile, l.debugFile} {
		if fh != nil {
			_ = fh.Close()
		}
	}
}

// Rotate reopens all log files (called on SIGUSR1 so external rotation tools
// can truncate or rename the old files while the server keeps running).
func (l *Logger) Rotate() error {
	if l.dir == "" {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Close existing handles silently.
	for _, fh := range []*os.File{l.accessFile, l.serverFile, l.errorFile, l.appFile, l.authFile, l.auditFile, l.securityFile, l.debugFile} {
		if fh != nil {
			_ = fh.Close()
		}
	}
	l.accessFile = nil
	l.serverFile = nil
	l.errorFile = nil
	l.appFile = nil
	l.authFile = nil
	l.auditFile = nil
	l.securityFile = nil
	l.debugFile = nil
	l.debugHandler = nil

	return l.openFiles()
}

// AccessWriter returns the underlying writer for access.log.
// The HTTP middleware writes pre-formatted Apache Combined Log lines directly.
// Returns io.Discard when no file is open.
func (l *Logger) AccessWriter() io.Writer {
	if l.accessFile == nil {
		return io.Discard
	}
	return l.accessFile
}

// WriteAccess writes a single Apache Combined Log Format line to access.log.
//
// Format: host ident authuser [time] "request" status bytes "referer" "agent"
func (l *Logger) WriteAccess(remoteAddr, method, path, proto string, status, bytes int, referer, userAgent string) {
	if l.accessFile == nil {
		return
	}

	ident := "-"
	authUser := "-"
	timeStr := time.Now().Format("02/Jan/2006:15:04:05 -0700")
	if referer == "" {
		referer = "-"
	}
	if userAgent == "" {
		userAgent = "-"
	}

	line := fmt.Sprintf("%s %s %s [%s] \"%s %s %s\" %d %d \"%s\" \"%s\"\n",
		remoteAddr, ident, authUser, timeStr,
		method, path, proto,
		status, bytes,
		referer, userAgent,
	)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.accessFile != nil {
		_, _ = l.accessFile.WriteString(line)
	}
}

// Info writes an INFO-level event to server.log.
func (l *Logger) Info(msg string, args ...any) {
	l.writeText(l.serverHandler, slog.LevelInfo, msg, args...)
}

// Warn writes a WARN-level event to server.log.
func (l *Logger) Warn(msg string, args ...any) {
	l.writeText(l.serverHandler, slog.LevelWarn, msg, args...)
}

// Error writes an ERROR-level event to both error.log and server.log.
func (l *Logger) Error(msg string, args ...any) {
	l.writeText(l.errorHandler, slog.LevelError, msg, args...)
	l.writeText(l.serverHandler, slog.LevelError, msg, args...)
}

// writeText emits a slog record through the given handler under l.mu.
func (l *Logger) writeText(h slog.Handler, level slog.Level, msg string, args ...any) {
	if h == nil {
		return
	}
	r := slog.NewRecord(time.Now(), level, msg, 0)
	for i := 0; i+1 < len(args); i += 2 {
		key, ok := args[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", args[i])
		}
		r.AddAttrs(slog.Any(key, args[i+1]))
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	_ = h.Handle(context.Background(), r)
}

// AuditEntry is the JSON structure written to audit.log.
type AuditEntry struct {
	Time       string `json:"time"`
	Level      string `json:"level"`
	Category   string `json:"category"`
	Action     string `json:"action"`
	ActorIP    string `json:"actor_ip,omitempty"`
	TargetType string `json:"target_type,omitempty"`
	TargetID   string `json:"target_id,omitempty"`
	Details    string `json:"details,omitempty"`
	Success    bool   `json:"success"`
}

// WriteAudit appends a JSON audit entry to audit.log.
func (l *Logger) WriteAudit(entry AuditEntry) {
	if l.auditFile == nil {
		return
	}
	if entry.Time == "" {
		entry.Time = time.Now().Format(time.RFC3339)
	}
	if entry.Level == "" {
		entry.Level = "INFO"
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.auditFile != nil {
		_, _ = l.auditFile.Write(data)
		_, _ = l.auditFile.WriteString("\n")
	}
}

// WriteSecurity appends a Fail2ban-compatible line to security.log.
//
// Format: 2024-10-10T13:55:36-04:00 [security] message
func (l *Logger) WriteSecurity(msg string) {
	if l.securityFile == nil {
		return
	}

	line := fmt.Sprintf("%s [security] %s\n", time.Now().Format(time.RFC3339), msg)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.securityFile != nil {
		_, _ = l.securityFile.WriteString(line)
	}
}

// App writes a general INFO-level event to app.log in logfmt format (AI.md PART 11).
// Format: time=<RFC3339> level=INFO msg="..." key=value ...
func (l *Logger) App(msg string, args ...any) {
	l.writeText(l.appHandler, slog.LevelInfo, msg, args...)
}

// AppWarn writes a WARN-level event to app.log in logfmt format (AI.md PART 11).
func (l *Logger) AppWarn(msg string, args ...any) {
	l.writeText(l.appHandler, slog.LevelWarn, msg, args...)
}

// Debug writes a DEBUG-level event to debug.log (AI.md PART 11).
// debug.log is only opened and written when the logger was created with debugEnabled = true.
func (l *Logger) Debug(msg string, args ...any) {
	l.writeText(l.debugHandler, slog.LevelDebug, msg, args...)
}

// SetDebugEnabled controls whether Debug() writes to debug.log.
// Calling with true on a logger opened without debugEnabled is a no-op
// (the file handle is nil; writes are silently discarded).
func (l *Logger) SetDebugEnabled(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debugEnabled = enabled
}

// WriteAuth appends a syslog RFC 3164 authentication event to auth.log (AI.md PART 11).
//
// Format: MMM DD HH:MM:SS hostname caswhois[pid]: auth: user=xxx ip=x.x.x.x result=success|fail reason=<code>
func (l *Logger) WriteAuth(user, ip, result, reason string) {
	if l.authFile == nil {
		return
	}

	hostname, _ := os.Hostname()
	now := time.Now()
	// Syslog RFC 3164 timestamp: "Jan  2 15:04:05" (no year, leading space for single-digit day).
	syslogTime := now.Format("Jan _2 15:04:05")
	pid := os.Getpid()

	line := fmt.Sprintf("%s %s caswhois[%d]: auth: user=%s ip=%s result=%s reason=%s\n",
		syslogTime, hostname, pid, user, ip, result, reason)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.authFile != nil {
		_, _ = l.authFile.WriteString(line)
	}
}

// newTextHandler builds a slog.Handler that writes logfmt output per AI.md PART 11.
// Used for app.log:
//
//	time=2026-05-13T10:58:00-04:00 level=INFO msg="user created" id=abc123 ip=1.2.3.4
func newTextHandler(w io.Writer) slog.Handler {
	opts := &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Format time as RFC3339 with timezone offset.
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(a.Value.Time().Format(time.RFC3339))
			}
			return a
		},
	}
	return slog.NewTextHandler(w, opts)
}

// bracketTextHandler is a slog.Handler for server.log, error.log, and debug.log.
// Produces the bracket text format required by AI.md PART 11:
//
//	2024-10-10T13:55:36-04:00 [INFO] message key=value key2=value2
type bracketTextHandler struct {
	w io.Writer
}

func newBracketTextHandler(w io.Writer) slog.Handler {
	return &bracketTextHandler{w: w}
}

func (h *bracketTextHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *bracketTextHandler) WithAttrs(_ []slog.Attr) slog.Handler         { return h }
func (h *bracketTextHandler) WithGroup(_ string) slog.Handler              { return h }

// Handle formats and writes a single log record.
func (h *bracketTextHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Time.Format(time.RFC3339))
	b.WriteString(" [")
	b.WriteString(r.Level.String())
	b.WriteString("] ")
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteByte(' ')
		b.WriteString(a.Key)
		b.WriteByte('=')
		v := a.Value.String()
		// Quote values containing whitespace or '=' to keep lines parseable.
		if strings.ContainsAny(v, " \t\n=") {
			b.WriteString(strconv.Quote(v))
		} else {
			b.WriteString(v)
		}
		return true
	})
	b.WriteByte('\n')
	_, err := io.WriteString(h.w, b.String())
	return err
}
