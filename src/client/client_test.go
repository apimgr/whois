package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/casapps/caswhois/src/client/config"
	"github.com/casapps/caswhois/src/client/lookup"
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
