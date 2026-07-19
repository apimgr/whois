package mode

import (
	"os"
	"testing"
)

func resetMode() {
	currentMode = Production
	debugEnabled = false
}

func TestAppModeString(t *testing.T) {
	cases := []struct {
		mode AppMode
		want string
	}{
		{Production, "production"},
		{Development, "development"},
		{AppMode(99), "production"},
	}
	for _, tc := range cases {
		if got := tc.mode.String(); got != tc.want {
			t.Errorf("AppMode(%d).String() = %q, want %q", tc.mode, got, tc.want)
		}
	}
}

func TestSetAppMode(t *testing.T) {
	defer resetMode()

	cases := []struct {
		input string
		want  AppMode
	}{
		{"dev", Development},
		{"devel", Development},
		{"development", Development},
		{"DEVELOPMENT", Development},
		{"production", Production},
		{"", Production},
		{"unknown", Production},
	}
	for _, tc := range cases {
		SetAppMode(tc.input)
		if GetCurrentAppMode() != tc.want {
			t.Errorf("SetAppMode(%q) -> GetCurrentAppMode() = %v, want %v", tc.input, GetCurrentAppMode(), tc.want)
		}
	}
}

func TestSetAppModeDebugAlias(t *testing.T) {
	defer resetMode()

	SetAppMode("debug")
	if !IsAppModeDev() {
		t.Error("SetAppMode(\"debug\") did not switch to development mode")
	}
	if !IsDebugEnabled() {
		t.Error("SetAppMode(\"debug\") did not enable debug")
	}
}

func TestIsAppModeDevProd(t *testing.T) {
	defer resetMode()

	SetAppMode("production")
	if !IsAppModeProd() || IsAppModeDev() {
		t.Error("production mode not reflected by IsAppModeProd/IsAppModeDev")
	}

	SetAppMode("development")
	if !IsAppModeDev() || IsAppModeProd() {
		t.Error("development mode not reflected by IsAppModeProd/IsAppModeDev")
	}
}

func TestSetDebugEnabled(t *testing.T) {
	defer resetMode()

	SetDebugEnabled(true)
	if !IsDebugEnabled() {
		t.Error("SetDebugEnabled(true) did not enable debug")
	}
	SetDebugEnabled(false)
	if IsDebugEnabled() {
		t.Error("SetDebugEnabled(false) did not disable debug")
	}
}

func TestGetAppModeString(t *testing.T) {
	defer resetMode()

	SetAppMode("production")
	SetDebugEnabled(false)
	if got := GetAppModeString(); got != "production" {
		t.Errorf("GetAppModeString() = %q, want %q", got, "production")
	}

	SetDebugEnabled(true)
	if got := GetAppModeString(); got != "production [debugging]" {
		t.Errorf("GetAppModeString() = %q, want %q", got, "production [debugging]")
	}
}

func TestFromEnvMode(t *testing.T) {
	defer resetMode()
	defer os.Unsetenv("MODE")
	defer os.Unsetenv("DEBUG")

	os.Setenv("MODE", "development")
	os.Unsetenv("DEBUG")
	FromEnv()

	if !IsAppModeDev() {
		t.Error("FromEnv() with MODE=development did not set development mode")
	}
}

func TestFromEnvDebugOverridesAlias(t *testing.T) {
	defer resetMode()
	defer os.Unsetenv("MODE")
	defer os.Unsetenv("DEBUG")

	os.Setenv("MODE", "debug")
	os.Setenv("DEBUG", "false")
	FromEnv()

	if !IsAppModeDev() {
		t.Error("FromEnv() with MODE=debug did not set development mode")
	}
	if IsDebugEnabled() {
		t.Error("FromEnv() with explicit DEBUG=false did not override the debug alias")
	}
}

func TestFromEnvNoVars(t *testing.T) {
	defer resetMode()
	os.Unsetenv("MODE")
	os.Unsetenv("DEBUG")

	SetAppMode("development")
	SetDebugEnabled(true)
	FromEnv()

	if !IsAppModeDev() || !IsDebugEnabled() {
		t.Error("FromEnv() with no env vars set should leave mode/debug unchanged")
	}
}
