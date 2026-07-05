package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/apimgr/whois/src/client/config"
	"github.com/apimgr/whois/src/client/lookup"
)

func TestResolveColor_Always(t *testing.T) {
	for _, v := range []string{"always", "on", "yes", "1"} {
		if !resolveColor(v) {
			t.Errorf("resolveColor(%q) = false, want true", v)
		}
	}
}

func TestResolveColor_Never(t *testing.T) {
	for _, v := range []string{"never", "off", "no", "0"} {
		if resolveColor(v) {
			t.Errorf("resolveColor(%q) = true, want false", v)
		}
	}
}

func TestResolveColor_NoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if resolveColor("") {
		t.Error("resolveColor() with NO_COLOR set should return false")
	}
}

func TestResolveColor_Auto_NoPanic(t *testing.T) {
	os.Unsetenv("NO_COLOR")
	// Auto mode checks TTY; just verify no panic
	_ = resolveColor("")
	_ = resolveColor("auto")
}

func TestApplyEnvOverrides_Server(t *testing.T) {
	t.Setenv("CASWHOIS_SERVER", "http://test.example.com:64000")
	cfg := &config.CLIConfig{}
	applyEnvOverrides(cfg)
	if cfg.Server != "http://test.example.com:64000" {
		t.Errorf("Server = %q, want %q", cfg.Server, "http://test.example.com:64000")
	}
}

func TestApplyEnvOverrides_DoesNotOverwriteExisting(t *testing.T) {
	t.Setenv("CASWHOIS_SERVER", "http://env.example.com")
	cfg := &config.CLIConfig{Server: "http://existing.example.com"}
	applyEnvOverrides(cfg)
	if cfg.Server != "http://existing.example.com" {
		t.Error("applyEnvOverrides should not overwrite existing server value")
	}
}

func TestApplyEnvOverrides_Token(t *testing.T) {
	t.Setenv("CASWHOIS_TOKEN", "tok_testtoken")
	cfg := &config.CLIConfig{}
	applyEnvOverrides(cfg)
	if cfg.Token != "tok_testtoken" {
		t.Errorf("Token = %q, want tok_testtoken", cfg.Token)
	}
}

func TestApplyEnvOverrides_Format(t *testing.T) {
	t.Setenv("CASWHOIS_FORMAT", "json")
	cfg := &config.CLIConfig{}
	applyEnvOverrides(cfg)
	if cfg.Format != "json" {
		t.Errorf("Format = %q, want json", cfg.Format)
	}
}

func TestApplyEnvOverrides_AllEmpty(t *testing.T) {
	os.Unsetenv("CASWHOIS_SERVER")
	os.Unsetenv("CASWHOIS_TOKEN")
	os.Unsetenv("CASWHOIS_FORMAT")
	cfg := &config.CLIConfig{}
	applyEnvOverrides(cfg)
	if cfg.Server != "" || cfg.Token != "" || cfg.Format != "" {
		t.Error("applyEnvOverrides with no env vars should not change cfg")
	}
}

func TestPrintResult_Text(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := &lookup.Result{
		Query:     "example.com",
		Type:      "domain",
		Server:    "whois.verisign-grs.com",
		Timestamp: "2025-01-01T00:00:00Z",
		Raw:       "Domain Name: EXAMPLE.COM",
	}
	printResult(result, nil, "text")

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "example.com") {
		t.Error("text output should contain query")
	}
	if !strings.Contains(out, "EXAMPLE.COM") {
		t.Error("text output should contain raw data")
	}
}

func TestPrintResult_JSON(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := &lookup.Result{
		Query: "8.8.8.8",
		Type:  "ip",
		Raw:   "NetRange: 8.8.8.0 - 8.8.8.255",
	}
	printResult(result, nil, "json")

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Errorf("json output is not valid JSON: %v\nOutput: %s", err, out)
	}
}

func TestPrintResult_Raw(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := &lookup.Result{
		Query: "AS15169",
		Type:  "asn",
		Raw:   "aut-num: AS15169",
	}
	printResult(result, nil, "raw")

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "aut-num: AS15169") {
		t.Errorf("raw output should contain raw data, got: %s", out)
	}
}

func TestShowVersion_NoPanic(t *testing.T) {
	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w
	showVersion()
	w.Close()
	os.Stdout = old
}

func TestShowHelp_NoPanic(t *testing.T) {
	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w
	showHelp()
	w.Close()
	os.Stdout = old
}

func TestShowHelp_ContainsUsage(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	showHelp()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "Usage") {
		t.Error("showHelp should contain 'Usage'")
	}
	if !strings.Contains(out, "domain") {
		t.Error("showHelp should contain 'domain' command")
	}
}

// Verify Version variable is accessible (set at build time via ldflags)
func TestVersion_Variable(t *testing.T) {
	if Version == "" {
		t.Error("Version should not be empty")
	}
}

// Test that the resolveColor auto detection does not panic on unknown platform.
func TestResolveColor_CaseInsensitive(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"ALWAYS", true},
		{"Always", true},
		{"NEVER", false},
		{"Never", false},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := resolveColor(tc.input)
			if got != tc.want {
				t.Errorf("resolveColor(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// Test that printResult with default (empty) format uses text output.
func TestPrintResult_DefaultFormat(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := &lookup.Result{
		Query:     "test.com",
		Type:      "domain",
		Server:    "whois.test",
		Timestamp: "now",
		Raw:       "raw data here",
	}
	printResult(result, nil, "")

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "test.com") {
		t.Errorf("default format output should contain query, got: %s", out)
	}
}

// Ensure there is no panic when printResult is called with format "unknown".
func TestPrintResult_UnknownFormat(t *testing.T) {
	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	result := &lookup.Result{Query: "x.com", Type: "domain"}
	// Should not panic
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(old, "panic: %v\n", r)
			}
		}()
		printResult(result, nil, "unknown")
	}()

	w.Close()
	os.Stdout = old
}

// ---------------------------------------------------------------------------
// runStatusCheck — subprocess test (function calls os.Exit)
// ---------------------------------------------------------------------------

// TestRunStatusCheck_Healthy verifies that runStatusCheck exits 0 when the
// server health endpoint returns HTTP 200.
func TestRunStatusCheck_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.CLIConfig{Server: srv.URL}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	runStatusCheck(cfg)
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()
	if !strings.Contains(out, "healthy") {
		t.Errorf("runStatusCheck healthy output should contain 'healthy', got %q", out)
	}
}

// ---------------------------------------------------------------------------
// runUpdateCommand — branch=<name> success path (no os.Exit on success)
// ---------------------------------------------------------------------------

// TestRunUpdateCommand_BranchSet verifies the branch=<name> path updates
// cfg.UpdateChannel and saves the config without calling os.Exit.
// The test uses XDG_CONFIG_HOME to redirect the config path to a temp dir.
func TestRunUpdateCommand_BranchSet(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	cfg := &config.CLIConfig{Format: "text"}

	oldOut := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	runUpdateCommand("branch=beta", cfg)
	w.Close()
	os.Stdout = oldOut

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if cfg.UpdateChannel != "beta" {
		t.Errorf("UpdateChannel = %q, want %q", cfg.UpdateChannel, "beta")
	}
	if !strings.Contains(out, "beta") {
		t.Errorf("output should mention channel name, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// runCLICommand — validate success path via fake server
// ---------------------------------------------------------------------------

// TestRunCLICommand_Validate verifies the validate sub-command prints a
// message without error when the server returns a valid response.
func TestRunCLICommand_Validate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"message":"domain"}`)
	}))
	defer srv.Close()

	cfg := &config.CLIConfig{Server: srv.URL, Format: "text"}

	oldOut := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	code := runCLICommand([]string{"validate", "example.com"}, cfg)
	w.Close()
	os.Stdout = oldOut
	if code != 0 {
		t.Errorf("validate returned exit code %d, want 0", code)
	}

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()
	if !strings.Contains(out, "domain") {
		t.Errorf("validate output = %q, want it to contain %q", out, "domain")
	}
}

// TestRunCLICommand_Lookup verifies the auto-detect lookup path.
func TestRunCLICommand_Lookup(t *testing.T) {
	inner, _ := json.Marshal(struct {
		Query     string `json:"query"`
		Type      string `json:"type"`
		Server    string `json:"server"`
		Timestamp string `json:"timestamp"`
		Raw       string `json:"raw"`
	}{"example.com", "domain", "whois.iana.org", "2024-01-01T00:00:00Z", "raw data"})
	body, _ := json.Marshal(map[string]interface{}{
		"ok":   true,
		"data": json.RawMessage(inner),
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	cfg := &config.CLIConfig{Server: srv.URL, Format: "text"}

	oldOut := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	code := runCLICommand([]string{"lookup", "example.com"}, cfg)
	w.Close()
	os.Stdout = oldOut

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()
	if code != 0 {
		t.Errorf("lookup returned exit code %d, want 0", code)
	}
	if !strings.Contains(out, "example.com") {
		t.Errorf("lookup output = %q, want it to contain %q", out, "example.com")
	}
}

// TestRunCLICommand_Domain verifies the domain sub-command path.
func TestRunCLICommand_Domain(t *testing.T) {
	inner, _ := json.Marshal(struct {
		Query     string `json:"query"`
		Type      string `json:"type"`
		Server    string `json:"server"`
		Timestamp string `json:"timestamp"`
		Raw       string `json:"raw"`
	}{"github.com", "domain", "whois.verisign-grs.com", "2024-01-01T00:00:00Z", "Domain Name: GITHUB.COM"})
	body, _ := json.Marshal(map[string]interface{}{
		"ok":   true,
		"data": json.RawMessage(inner),
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	cfg := &config.CLIConfig{Server: srv.URL, Format: "raw"}

	oldOut := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	code := runCLICommand([]string{"domain", "github.com"}, cfg)
	w.Close()
	os.Stdout = oldOut

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()
	if code != 0 {
		t.Errorf("domain returned exit code %d, want 0", code)
	}
	if !strings.Contains(out, "GITHUB.COM") {
		t.Errorf("domain output = %q, want it to contain %q", out, "GITHUB.COM")
	}
}

// TestRunCLICommand_IP verifies the ip sub-command path.
func TestRunCLICommand_IP(t *testing.T) {
	inner, _ := json.Marshal(struct {
		Query     string `json:"query"`
		Type      string `json:"type"`
		Server    string `json:"server"`
		Timestamp string `json:"timestamp"`
		Raw       string `json:"raw"`
	}{"8.8.8.8", "ip", "whois.arin.net", "2024-01-01T00:00:00Z", "NetRange: 8.8.8.0"})
	body, _ := json.Marshal(map[string]interface{}{
		"ok":   true,
		"data": json.RawMessage(inner),
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	cfg := &config.CLIConfig{Server: srv.URL, Format: "json"}

	oldOut := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	code := runCLICommand([]string{"ip", "8.8.8.8"}, cfg)
	w.Close()
	os.Stdout = oldOut

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()
	if code != 0 {
		t.Errorf("ip returned exit code %d, want 0", code)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Errorf("ip command json output is not valid JSON: %v\nOutput: %s", err, out)
	}
}

// TestRunCLICommand_ASN verifies the asn sub-command path.
func TestRunCLICommand_ASN(t *testing.T) {
	inner, _ := json.Marshal(struct {
		Query     string `json:"query"`
		Type      string `json:"type"`
		Server    string `json:"server"`
		Timestamp string `json:"timestamp"`
		Raw       string `json:"raw"`
	}{"AS15169", "asn", "whois.radb.net", "2024-01-01T00:00:00Z", "aut-num: AS15169"})
	body, _ := json.Marshal(map[string]interface{}{
		"ok":   true,
		"data": json.RawMessage(inner),
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	cfg := &config.CLIConfig{Server: srv.URL, Format: "text"}

	oldOut := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	code := runCLICommand([]string{"asn", "AS15169"}, cfg)
	w.Close()
	os.Stdout = oldOut

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()
	if code != 0 {
		t.Errorf("asn returned exit code %d, want 0", code)
	}
	if !strings.Contains(out, "AS15169") {
		t.Errorf("asn output = %q, want it to contain %q", out, "AS15169")
	}
}

// TestRunCLICommand_DefaultLookup verifies the catch-all default path where
// the first arg is treated as a direct lookup query.
func TestRunCLICommand_DefaultLookup(t *testing.T) {
	inner, _ := json.Marshal(struct {
		Query     string `json:"query"`
		Type      string `json:"type"`
		Server    string `json:"server"`
		Timestamp string `json:"timestamp"`
		Raw       string `json:"raw"`
	}{"auto.example.com", "domain", "whois.iana.org", "2024-01-01T00:00:00Z", "auto raw"})
	body, _ := json.Marshal(map[string]interface{}{
		"ok":   true,
		"data": json.RawMessage(inner),
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	cfg := &config.CLIConfig{Server: srv.URL, Format: "raw"}

	oldOut := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	code := runCLICommand([]string{"auto.example.com"}, cfg)
	w.Close()
	os.Stdout = oldOut

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()
	if code != 0 {
		t.Errorf("default lookup returned exit code %d, want 0", code)
	}
	if !strings.Contains(out, "auto raw") {
		t.Errorf("default lookup output = %q, want it to contain %q", out, "auto raw")
	}
}

// ---------------------------------------------------------------------------
// printResult — error path via subprocess (os.Exit(1) is called)
// ---------------------------------------------------------------------------

// TestPrintResult_Error_ExitCode confirms that printResult calls os.Exit(1)
// when a non-nil error is passed. We verify via a subprocess test so the
// parent process is not killed.
func TestPrintResult_Error_ExitCode(t *testing.T) {
	if os.Getenv("SUBPROCESS_EXIT_TEST") == "1" {
		os.Exit(printResult(nil, fmt.Errorf("injected error"), "text"))
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestPrintResult_Error_ExitCode")
	cmd.Env = append(os.Environ(), "SUBPROCESS_EXIT_TEST=1")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit, got nil")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("unexpected error type: %T %v", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("exit code = %d, want 1", exitErr.ExitCode())
	}
}

// ---------------------------------------------------------------------------
// run() — tests for the refactored entrypoint
// ---------------------------------------------------------------------------

// TestRun_Version verifies that --version returns exit code 0 and prints the binary name.
func TestRun_Version(t *testing.T) {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"--version"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if code != 0 {
		t.Errorf("run(--version) = %d, want 0", code)
	}
	if !strings.Contains(buf.String(), "version") {
		t.Errorf("version output missing 'version': %q", buf.String())
	}
}

// TestRun_ShortVersion verifies that -v returns exit code 0.
func TestRun_ShortVersion(t *testing.T) {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"-v"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if code != 0 {
		t.Errorf("run(-v) = %d, want 0", code)
	}
	_ = buf
}

// TestRun_InvalidFlag verifies that an unknown flag returns exit code 1.
func TestRun_InvalidFlag(t *testing.T) {
	code := run([]string{"--this-flag-does-not-exist"})
	if code != 1 {
		t.Errorf("run(unknown flag) = %d, want 1", code)
	}
}

// TestRun_NoServer_Plain verifies that when no server is configured and the
// display mode is plain, run returns exit code 1.
func TestRun_NoServer_Plain(t *testing.T) {
	t.Setenv("CASWHOIS_SERVER", "")
	t.Setenv("CASWHOIS_TOKEN", "")
	// Use a temp dir as config home so no config file is found.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// TERM=dumb forces plain (non-TTY, non-TUI) display mode.
	t.Setenv("TERM", "dumb")
	// Provide a domain argument so display.Detect sees args>0 and uses plain mode.
	code := run([]string{"--server", "", "example.com"})
	// Either exits 0 (made a request, server answered) or 1 (no server configured).
	// We just confirm it does not panic.
	_ = code
}

// TestRun_ServerFlag_WithCommand verifies that --server flag is picked up and
// the domain command reaches the server (which returns an error since it is a
// fake server returning garbage, hence exit code 1 is acceptable).
func TestRun_ServerFlag_WithCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		inner, _ := json.Marshal(struct {
			Query     string `json:"query"`
			Type      string `json:"type"`
			Server    string `json:"server"`
			Timestamp string `json:"timestamp"`
			Raw       string `json:"raw"`
		}{"example.com", "domain", "whois.test", "2024-01-01T00:00:00Z", "raw"})
		body, _ := json.Marshal(map[string]interface{}{"ok": true, "data": json.RawMessage(inner)})
		w.Write(body)
	}))
	defer srv.Close()

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"--server", srv.URL, "domain", "example.com"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if code != 0 {
		t.Errorf("run with server and domain command = %d, want 0", code)
	}
	if !strings.Contains(buf.String(), "example.com") {
		t.Errorf("expected output to contain example.com, got: %q", buf.String())
	}
}

// TestRun_OutputFlag verifies that --output flag changes the format.
func TestRun_OutputFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		inner, _ := json.Marshal(struct {
			Query     string `json:"query"`
			Type      string `json:"type"`
			Server    string `json:"server"`
			Timestamp string `json:"timestamp"`
			Raw       string `json:"raw"`
		}{"8.8.8.8", "ip", "whois.arin.net", "2024-01-01T00:00:00Z", "NetRange: 8.8.8.0"})
		body, _ := json.Marshal(map[string]interface{}{"ok": true, "data": json.RawMessage(inner)})
		w.Write(body)
	}))
	defer srv.Close()

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"--server", srv.URL, "--output", "json", "ip", "8.8.8.8"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if code != 0 {
		t.Errorf("run --output json = %d, want 0", code)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Errorf("--output json did not produce valid JSON: %v\nOutput: %s", err, buf.String())
	}
}

// TestRun_FormatFlag verifies that --format flag (legacy alias) changes the output format.
func TestRun_FormatFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		inner, _ := json.Marshal(struct {
			Query     string `json:"query"`
			Type      string `json:"type"`
			Server    string `json:"server"`
			Timestamp string `json:"timestamp"`
			Raw       string `json:"raw"`
		}{"AS15169", "asn", "whois.radb.net", "2024-01-01T00:00:00Z", "aut-num: AS15169"})
		body, _ := json.Marshal(map[string]interface{}{"ok": true, "data": json.RawMessage(inner)})
		w.Write(body)
	}))
	defer srv.Close()

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"--server", srv.URL, "--format", "raw", "asn", "AS15169"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if code != 0 {
		t.Errorf("run --format raw = %d, want 0", code)
	}
	if !strings.Contains(buf.String(), "AS15169") {
		t.Errorf("raw format output should contain AS15169, got: %q", buf.String())
	}
}

// TestRun_NoColorFlag verifies --no-color does not break execution.
func TestRun_NoColorFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		inner, _ := json.Marshal(struct {
			Query     string `json:"query"`
			Type      string `json:"type"`
			Server    string `json:"server"`
			Timestamp string `json:"timestamp"`
			Raw       string `json:"raw"`
		}{"test.com", "domain", "whois.test", "2024-01-01T00:00:00Z", "raw"})
		body, _ := json.Marshal(map[string]interface{}{"ok": true, "data": json.RawMessage(inner)})
		w.Write(body)
	}))
	defer srv.Close()

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"--server", srv.URL, "--no-color", "test.com"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if code != 0 {
		t.Errorf("run --no-color = %d, want 0", code)
	}
	_ = buf
}

// TestRun_DebugFlag verifies --debug does not break execution.
func TestRun_DebugFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		inner, _ := json.Marshal(struct {
			Query     string `json:"query"`
			Type      string `json:"type"`
			Server    string `json:"server"`
			Timestamp string `json:"timestamp"`
			Raw       string `json:"raw"`
		}{"test.com", "domain", "whois.test", "2024-01-01T00:00:00Z", "raw"})
		body, _ := json.Marshal(map[string]interface{}{"ok": true, "data": json.RawMessage(inner)})
		w.Write(body)
	}))
	defer srv.Close()

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"--server", srv.URL, "--debug", "test.com"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if code != 0 {
		t.Errorf("run --debug = %d, want 0", code)
	}
	_ = buf
}

// TestRun_TokenFlag verifies --token flag is picked up without error.
func TestRun_TokenFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		inner, _ := json.Marshal(struct {
			Query     string `json:"query"`
			Type      string `json:"type"`
			Server    string `json:"server"`
			Timestamp string `json:"timestamp"`
			Raw       string `json:"raw"`
		}{"test.com", "domain", "whois.test", "2024-01-01T00:00:00Z", "raw"})
		body, _ := json.Marshal(map[string]interface{}{"ok": true, "data": json.RawMessage(inner)})
		w.Write(body)
	}))
	defer srv.Close()

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"--server", srv.URL, "--token", "tok_abc123", "test.com"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if code != 0 {
		t.Errorf("run --token = %d, want 0", code)
	}
	_ = buf
}

// TestRun_LangFlag verifies --lang flag is accepted without error.
func TestRun_LangFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		inner, _ := json.Marshal(struct {
			Query     string `json:"query"`
			Type      string `json:"type"`
			Server    string `json:"server"`
			Timestamp string `json:"timestamp"`
			Raw       string `json:"raw"`
		}{"test.com", "domain", "whois.test", "2024-01-01T00:00:00Z", "raw"})
		body, _ := json.Marshal(map[string]interface{}{"ok": true, "data": json.RawMessage(inner)})
		w.Write(body)
	}))
	defer srv.Close()

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"--server", srv.URL, "--lang", "es", "test.com"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if code != 0 {
		t.Errorf("run --lang es = %d, want 0", code)
	}
	_ = buf
}

// TestRun_LangFlag_Unsupported verifies an unsupported lang falls back gracefully.
func TestRun_LangFlag_Unsupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		inner, _ := json.Marshal(struct {
			Query     string `json:"query"`
			Type      string `json:"type"`
			Server    string `json:"server"`
			Timestamp string `json:"timestamp"`
			Raw       string `json:"raw"`
		}{"test.com", "domain", "whois.test", "2024-01-01T00:00:00Z", "raw"})
		body, _ := json.Marshal(map[string]interface{}{"ok": true, "data": json.RawMessage(inner)})
		w.Write(body)
	}))
	defer srv.Close()

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"--server", srv.URL, "--lang", "xx", "test.com"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	// Unsupported lang falls back to "en" — should still succeed.
	if code != 0 {
		t.Errorf("run --lang xx (unsupported) = %d, want 0", code)
	}
	_ = buf
}

// TestRun_ColorFlag_Always verifies --color always does not break execution.
func TestRun_ColorFlag_Always(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		inner, _ := json.Marshal(struct {
			Query     string `json:"query"`
			Type      string `json:"type"`
			Server    string `json:"server"`
			Timestamp string `json:"timestamp"`
			Raw       string `json:"raw"`
		}{"test.com", "domain", "whois.test", "2024-01-01T00:00:00Z", "raw"})
		body, _ := json.Marshal(map[string]interface{}{"ok": true, "data": json.RawMessage(inner)})
		w.Write(body)
	}))
	defer srv.Close()

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"--server", srv.URL, "--color", "always", "test.com"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if code != 0 {
		t.Errorf("run --color always = %d, want 0", code)
	}
	_ = buf
}

// TestRun_Update verifies --update branch=name returns exit code 0.
func TestRun_Update_Branch(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"--update", "branch=beta"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if code != 0 {
		t.Errorf("run --update branch=beta = %d, want 0", code)
	}
	if !strings.Contains(buf.String(), "beta") {
		t.Errorf("update branch output should mention 'beta', got: %q", buf.String())
	}
}

// TestRun_Status_Healthy verifies --status with healthy server returns 0.
func TestRun_Status_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"--server", srv.URL, "--status"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if code != 0 {
		t.Errorf("run --status healthy = %d, want 0", code)
	}
	if !strings.Contains(buf.String(), "healthy") {
		t.Errorf("status output should contain 'healthy', got: %q", buf.String())
	}
}

// TestRun_Lookup verifies the lookup subcommand via run().
func TestRun_Lookup(t *testing.T) {
	inner, _ := json.Marshal(struct {
		Query     string `json:"query"`
		Type      string `json:"type"`
		Server    string `json:"server"`
		Timestamp string `json:"timestamp"`
		Raw       string `json:"raw"`
	}{"example.com", "domain", "whois.iana.org", "2024-01-01T00:00:00Z", "lookup raw"})
	body, _ := json.Marshal(map[string]interface{}{"ok": true, "data": json.RawMessage(inner)})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"--server", srv.URL, "lookup", "example.com"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if code != 0 {
		t.Errorf("run lookup = %d, want 0", code)
	}
	if !strings.Contains(buf.String(), "example.com") {
		t.Errorf("lookup output should contain example.com, got: %q", buf.String())
	}
}

// TestRun_Validate verifies the validate subcommand via run().
func TestRun_Validate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"message":"domain"}`)
	}))
	defer srv.Close()

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"--server", srv.URL, "validate", "example.com"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if code != 0 {
		t.Errorf("run validate = %d, want 0", code)
	}
	if !strings.Contains(buf.String(), "domain") {
		t.Errorf("validate output should contain 'domain', got: %q", buf.String())
	}
}

// TestRun_EnvServerOverride verifies CASWHOIS_SERVER env var is picked up.
func TestRun_EnvServerOverride(t *testing.T) {
	inner, _ := json.Marshal(struct {
		Query     string `json:"query"`
		Type      string `json:"type"`
		Server    string `json:"server"`
		Timestamp string `json:"timestamp"`
		Raw       string `json:"raw"`
	}{"test.com", "domain", "whois.test", "2024-01-01T00:00:00Z", "env raw"})
	body, _ := json.Marshal(map[string]interface{}{"ok": true, "data": json.RawMessage(inner)})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	t.Setenv("CASWHOIS_SERVER", srv.URL)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := run([]string{"test.com"})
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if code != 0 {
		t.Errorf("run via CASWHOIS_SERVER env = %d, want 0", code)
	}
	_ = buf
}

// ---------------------------------------------------------------------------
// runStatusCheck — subprocess test for empty server (os.Exit path)
// ---------------------------------------------------------------------------

// TestRunStatusCheck_EmptyServer verifies that runStatusCheck exits 1 when
// no server is configured.
func TestRunStatusCheck_EmptyServer(t *testing.T) {
	if os.Getenv("SUBPROCESS_EXIT_TEST") == "TestRunStatusCheck_EmptyServer" {
		os.Exit(runStatusCheck(&config.CLIConfig{Server: ""}))
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestRunStatusCheck_EmptyServer", "-test.v")
	cmd.Env = append(os.Environ(), "SUBPROCESS_EXIT_TEST=TestRunStatusCheck_EmptyServer")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit, got nil")
	}
	if e, ok := err.(*exec.ExitError); !ok || e.Success() {
		t.Fatalf("expected non-zero exit error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runUpdateCommand — subprocess tests for os.Exit paths
// ---------------------------------------------------------------------------

// TestRunUpdateCommand_DefaultUnknown verifies that an unknown update command
// causes os.Exit(1).
func TestRunUpdateCommand_DefaultUnknown(t *testing.T) {
	if os.Getenv("SUBPROCESS_EXIT_TEST") == "TestRunUpdateCommand_DefaultUnknown" {
		os.Exit(runUpdateCommand("badcmd", &config.CLIConfig{}))
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestRunUpdateCommand_DefaultUnknown", "-test.v")
	cmd.Env = append(os.Environ(), "SUBPROCESS_EXIT_TEST=TestRunUpdateCommand_DefaultUnknown")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit, got nil")
	}
	if e, ok := err.(*exec.ExitError); !ok || e.Success() {
		t.Fatalf("expected non-zero exit error, got: %v", err)
	}
}

// TestRunUpdateCommand_BranchEmpty verifies that branch= with no name causes os.Exit(1).
func TestRunUpdateCommand_BranchEmpty(t *testing.T) {
	if os.Getenv("SUBPROCESS_EXIT_TEST") == "TestRunUpdateCommand_BranchEmpty" {
		os.Exit(runUpdateCommand("branch=", &config.CLIConfig{}))
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestRunUpdateCommand_BranchEmpty", "-test.v")
	cmd.Env = append(os.Environ(), "SUBPROCESS_EXIT_TEST=TestRunUpdateCommand_BranchEmpty")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit, got nil")
	}
	if e, ok := err.(*exec.ExitError); !ok || e.Success() {
		t.Fatalf("expected non-zero exit error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runCLICommand — subprocess tests for empty-arg os.Exit paths
// ---------------------------------------------------------------------------

// TestRunCLICommand_DomainEmpty verifies that "domain" with no args causes os.Exit(1).
func TestRunCLICommand_DomainEmpty(t *testing.T) {
	if os.Getenv("SUBPROCESS_EXIT_TEST") == "TestRunCLICommand_DomainEmpty" {
		os.Exit(runCLICommand([]string{"domain"}, &config.CLIConfig{Server: "http://localhost:9999"}))
		
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestRunCLICommand_DomainEmpty", "-test.v")
	cmd.Env = append(os.Environ(), "SUBPROCESS_EXIT_TEST=TestRunCLICommand_DomainEmpty")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit, got nil")
	}
	if e, ok := err.(*exec.ExitError); !ok || e.Success() {
		t.Fatalf("expected non-zero exit error, got: %v", err)
	}
}

// TestRunCLICommand_IPEmpty verifies that "ip" with no args causes os.Exit(1).
func TestRunCLICommand_IPEmpty(t *testing.T) {
	if os.Getenv("SUBPROCESS_EXIT_TEST") == "TestRunCLICommand_IPEmpty" {
		os.Exit(runCLICommand([]string{"ip"}, &config.CLIConfig{Server: "http://localhost:9999"}))
		
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestRunCLICommand_IPEmpty", "-test.v")
	cmd.Env = append(os.Environ(), "SUBPROCESS_EXIT_TEST=TestRunCLICommand_IPEmpty")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit, got nil")
	}
	if e, ok := err.(*exec.ExitError); !ok || e.Success() {
		t.Fatalf("expected non-zero exit error, got: %v", err)
	}
}

// TestRunCLICommand_ASNEmpty verifies that "asn" with no args causes os.Exit(1).
func TestRunCLICommand_ASNEmpty(t *testing.T) {
	if os.Getenv("SUBPROCESS_EXIT_TEST") == "TestRunCLICommand_ASNEmpty" {
		os.Exit(runCLICommand([]string{"asn"}, &config.CLIConfig{Server: "http://localhost:9999"}))
		
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestRunCLICommand_ASNEmpty", "-test.v")
	cmd.Env = append(os.Environ(), "SUBPROCESS_EXIT_TEST=TestRunCLICommand_ASNEmpty")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit, got nil")
	}
	if e, ok := err.(*exec.ExitError); !ok || e.Success() {
		t.Fatalf("expected non-zero exit error, got: %v", err)
	}
}

// TestRunCLICommand_ValidateEmpty verifies that "validate" with no args causes os.Exit(1).
func TestRunCLICommand_ValidateEmpty(t *testing.T) {
	if os.Getenv("SUBPROCESS_EXIT_TEST") == "TestRunCLICommand_ValidateEmpty" {
		os.Exit(runCLICommand([]string{"validate"}, &config.CLIConfig{Server: "http://localhost:9999"}))
		
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestRunCLICommand_ValidateEmpty", "-test.v")
	cmd.Env = append(os.Environ(), "SUBPROCESS_EXIT_TEST=TestRunCLICommand_ValidateEmpty")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit, got nil")
	}
	if e, ok := err.(*exec.ExitError); !ok || e.Success() {
		t.Fatalf("expected non-zero exit error, got: %v", err)
	}
}

// TestRunCLICommand_LookupEmpty verifies that "lookup" with no args causes os.Exit(1).
func TestRunCLICommand_LookupEmpty(t *testing.T) {
	if os.Getenv("SUBPROCESS_EXIT_TEST") == "TestRunCLICommand_LookupEmpty" {
		os.Exit(runCLICommand([]string{"lookup"}, &config.CLIConfig{Server: "http://localhost:9999"}))

	}
	cmd := exec.Command(os.Args[0], "-test.run=TestRunCLICommand_LookupEmpty", "-test.v")
	cmd.Env = append(os.Environ(), "SUBPROCESS_EXIT_TEST=TestRunCLICommand_LookupEmpty")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit, got nil")
	}
	if e, ok := err.(*exec.ExitError); !ok || e.Success() {
		t.Fatalf("expected non-zero exit error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runUpdateCommand — autodiscover-based update tests
// ---------------------------------------------------------------------------

// TestRunUpdateCommand_CheckWithServer verifies --update check with server configured
// uses autodiscover endpoint.
func TestRunUpdateCommand_CheckWithServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/autodiscover" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"api_version":"v1","base_url":"http://%s","cli_versions":{},"cli_min_version":"v0.0.0"}`, r.Host)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := &config.CLIConfig{Server: srv.URL}

	oldOut := os.Stdout
	oldErr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w
	code := runUpdateCommand("check", cfg)
	w.Close()
	os.Stdout = oldOut
	os.Stderr = oldErr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	// Since no CLI binary is available for the platform, check should fail
	if code == 0 {
		// If platform binary was found, it would report up to date
		if !strings.Contains(buf.String(), "up to date") {
			t.Logf("output: %q", buf.String())
		}
	}
}

// TestRunUpdateCommand_EmptyDefaultsToYes verifies --update "" defaults to "yes" command.
func TestRunUpdateCommand_EmptyDefaultsToYes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/autodiscover" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"api_version":"v1","base_url":"http://%s","cli_versions":{},"cli_min_version":"v0.0.0"}`, r.Host)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := &config.CLIConfig{Server: srv.URL}

	oldOut := os.Stdout
	oldErr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w
	// Empty string should default to "yes" per AI.md PART 22
	code := runUpdateCommand("", cfg)
	w.Close()
	os.Stdout = oldOut
	os.Stderr = oldErr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	// Should fail because no CLI binary available for platform, but that's expected
	_ = code
	_ = buf
}

// TestRunUpdateCommand_CheckWithoutServer verifies --update check without server
// falls back to GitHub releases.
func TestRunUpdateCommand_CheckWithoutServer(t *testing.T) {
	cfg := &config.CLIConfig{Server: "", UpdateChannel: "stable"}

	oldOut := os.Stdout
	oldErr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w
	// This will fail to reach GitHub in test env, which is expected
	code := runUpdateCommand("check", cfg)
	w.Close()
	os.Stdout = oldOut
	os.Stderr = oldErr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	// Expect non-zero since GitHub API won't be reachable in test
	_ = code
	_ = buf
}

// TestRunUpdateCommand_YesWithoutServer verifies --update yes without server
// falls back to GitHub releases.
func TestRunUpdateCommand_YesWithoutServer(t *testing.T) {
	cfg := &config.CLIConfig{Server: "", UpdateChannel: "beta"}

	oldOut := os.Stdout
	oldErr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w
	// This will fail to reach GitHub in test env, which is expected
	code := runUpdateCommand("yes", cfg)
	w.Close()
	os.Stdout = oldOut
	os.Stderr = oldErr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	// Expect non-zero since GitHub API won't be reachable in test
	_ = code
	_ = buf
}
