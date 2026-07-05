package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	v := New("testapp", "1.0.0", "abc123", "2025-01-01")

	if v.Name != "testapp" {
		t.Errorf("Name = %q, want %q", v.Name, "testapp")
	}
	if v.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", v.Version, "1.0.0")
	}
	if v.Commit != "abc123" {
		t.Errorf("Commit = %q, want %q", v.Commit, "abc123")
	}
	if v.BuildDate != "2025-01-01" {
		t.Errorf("BuildDate = %q, want %q", v.BuildDate, "2025-01-01")
	}
	if v.GoVersion != runtime.Version() {
		t.Errorf("GoVersion = %q, want %q", v.GoVersion, runtime.Version())
	}
}

func TestInfo_String(t *testing.T) {
	v := New("testapp", "1.0.0", "abc123", "2025-01-01")
	s := v.String()

	// Should match format: {name} version {version} ({commit}) built on {date} for {os}/{arch}
	if !strings.HasPrefix(s, "testapp version 1.0.0 (abc123)") {
		t.Errorf("String() format incorrect: %s", s)
	}
	if !strings.Contains(s, "built on 2025-01-01") {
		t.Errorf("String() missing build date: %s", s)
	}
	if !strings.Contains(s, runtime.GOOS+"/"+runtime.GOARCH) {
		t.Errorf("String() missing platform: %s", s)
	}
}

func TestInfo_Short(t *testing.T) {
	v := New("testapp", "1.0.0", "abc123", "2025-01-01")
	s := v.Short()

	if s != "testapp 1.0.0" {
		t.Errorf("Short() = %q, want %q", s, "testapp 1.0.0")
	}
}

func TestInfo_Full(t *testing.T) {
	v := New("testapp", "1.0.0", "abc123", "2025-01-01")
	s := v.Full()

	if !strings.Contains(s, "testapp") {
		t.Error("Full() missing name")
	}
	if !strings.Contains(s, "1.0.0") {
		t.Error("Full() missing version")
	}
	if !strings.Contains(s, "abc123") {
		t.Error("Full() missing commit")
	}
	if !strings.Contains(s, "2025-01-01") {
		t.Error("Full() missing build date")
	}
	if !strings.Contains(s, runtime.Version()) {
		t.Error("Full() missing Go version")
	}
}

func TestInfo_Map(t *testing.T) {
	v := New("testapp", "1.0.0", "abc123", "2025-01-01")
	m := v.Map()

	if m["name"] != "testapp" {
		t.Errorf("Map()[name] = %q", m["name"])
	}
	if m["version"] != "1.0.0" {
		t.Errorf("Map()[version] = %q", m["version"])
	}
	if m["commit"] != "abc123" {
		t.Errorf("Map()[commit] = %q", m["commit"])
	}
	if m["os"] != runtime.GOOS {
		t.Errorf("Map()[os] = %q", m["os"])
	}
	if m["arch"] != runtime.GOARCH {
		t.Errorf("Map()[arch] = %q", m["arch"])
	}
}

func TestPlatform(t *testing.T) {
	p := Platform()
	expected := runtime.GOOS + "/" + runtime.GOARCH
	if p != expected {
		t.Errorf("Platform() = %q, want %q", p, expected)
	}
}

func TestGoVer(t *testing.T) {
	if GoVer() != runtime.Version() {
		t.Errorf("GoVer() = %q, want %q", GoVer(), runtime.Version())
	}
}
