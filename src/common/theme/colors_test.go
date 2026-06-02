package theme

import (
	"testing"
)

// TestThemePaletteDark verifies that the dark palette variables are populated
// with the documented hex values and that no field is empty.
func TestThemePaletteDark(t *testing.T) {
	p := ThemePaletteDark
	fields := map[string]string{
		"Background": p.Background,
		"Foreground": p.Foreground,
		"Primary":    p.Primary,
		"Secondary":  p.Secondary,
		"Accent":     p.Accent,
		"Success":    p.Success,
		"Warning":    p.Warning,
		"Error":      p.Error,
		"Info":       p.Info,
		"Surface":    p.Surface,
		"SurfaceAlt": p.SurfaceAlt,
		"Border":     p.Border,
		"Muted":      p.Muted,
	}
	for field, val := range fields {
		if val == "" {
			t.Errorf("ThemePaletteDark.%s is empty", field)
		}
	}
	// Spot-check specific documented values.
	if p.Background != "#1a1b26" {
		t.Errorf("ThemePaletteDark.Background = %q, want \"#1a1b26\"", p.Background)
	}
	if p.Primary != "#7aa2f7" {
		t.Errorf("ThemePaletteDark.Primary = %q, want \"#7aa2f7\"", p.Primary)
	}
}

// TestThemePaletteLight verifies all light palette fields are populated and
// spot-checks documented values.
func TestThemePaletteLight(t *testing.T) {
	p := ThemePaletteLight
	fields := map[string]string{
		"Background": p.Background,
		"Foreground": p.Foreground,
		"Primary":    p.Primary,
		"Secondary":  p.Secondary,
		"Accent":     p.Accent,
		"Success":    p.Success,
		"Warning":    p.Warning,
		"Error":      p.Error,
		"Info":       p.Info,
		"Surface":    p.Surface,
		"SurfaceAlt": p.SurfaceAlt,
		"Border":     p.Border,
		"Muted":      p.Muted,
	}
	for field, val := range fields {
		if val == "" {
			t.Errorf("ThemePaletteLight.%s is empty", field)
		}
	}
	if p.Background != "#ffffff" {
		t.Errorf("ThemePaletteLight.Background = %q, want \"#ffffff\"", p.Background)
	}
	if p.Primary != "#2e7de9" {
		t.Errorf("ThemePaletteLight.Primary = %q, want \"#2e7de9\"", p.Primary)
	}
}

// TestGetThemePalette_ExplicitModes verifies that "dark" and "light" return
// the correct palettes without consulting environment variables.
func TestGetThemePalette_ExplicitModes(t *testing.T) {
	cases := []struct {
		name       string
		mode       string
		wantBg     string
		wantPalette ThemePalette
	}{
		{name: "dark mode", mode: "dark", wantBg: "#1a1b26", wantPalette: ThemePaletteDark},
		{name: "light mode", mode: "light", wantBg: "#ffffff", wantPalette: ThemePaletteLight},
		{name: "empty defaults to dark", mode: "", wantBg: "#1a1b26", wantPalette: ThemePaletteDark},
		{name: "unknown defaults to dark", mode: "sepia", wantBg: "#1a1b26", wantPalette: ThemePaletteDark},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GetThemePalette(tc.mode)
			if got.Background != tc.wantBg {
				t.Errorf("GetThemePalette(%q).Background = %q, want %q", tc.mode, got.Background, tc.wantBg)
			}
			if got != tc.wantPalette {
				t.Errorf("GetThemePalette(%q) palette mismatch", tc.mode)
			}
		})
	}
}

// TestGetThemePalette_Auto_DarkEnvironment verifies that "auto" returns the
// dark palette when the environment signals a dark terminal via NO_COLOR.
func TestGetThemePalette_Auto_DarkEnvironment(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("COLORFGBG", "")

	got := GetThemePalette("auto")
	if got.Background != ThemePaletteDark.Background {
		t.Errorf("GetThemePalette(\"auto\") with NO_COLOR: Background = %q, want dark %q",
			got.Background, ThemePaletteDark.Background)
	}
}

// TestGetThemePalette_Auto_LightEnvironment verifies that "auto" returns the
// light palette when COLORFGBG signals a light (high-number background) terminal.
func TestGetThemePalette_Auto_LightEnvironment(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("COLORFGBG", "0;15")

	got := GetThemePalette("auto")
	if got.Background != ThemePaletteLight.Background {
		t.Errorf("GetThemePalette(\"auto\") with COLORFGBG=0;15: Background = %q, want light %q",
			got.Background, ThemePaletteLight.Background)
	}
}

// TestIsSystemDarkTheme_NO_COLOR verifies that NO_COLOR set to any non-empty
// value is treated as a dark environment.
func TestIsSystemDarkTheme_NO_COLOR(t *testing.T) {
	cases := []struct {
		name    string
		noColor string
		want    bool
	}{
		{name: "NO_COLOR=1", noColor: "1", want: true},
		{name: "NO_COLOR=true", noColor: "true", want: true},
		{name: "NO_COLOR empty (unset)", noColor: "", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NO_COLOR", tc.noColor)
			// Clear COLORFGBG so only NO_COLOR is in play.
			t.Setenv("COLORFGBG", "")
			got := IsSystemDarkTheme()
			if got != tc.want {
				t.Errorf("IsSystemDarkTheme() with NO_COLOR=%q = %v, want %v", tc.noColor, got, tc.want)
			}
		})
	}
}

// TestIsSystemDarkTheme_COLORFGBG verifies the COLORFGBG parsing: a background
// digit 0-7 signals dark; 8-15 (or other) signals light.
func TestIsSystemDarkTheme_COLORFGBG(t *testing.T) {
	cases := []struct {
		name      string
		colorFgBg string
		want      bool
	}{
		{name: "bg=0 (dark)", colorFgBg: "15;0", want: true},
		{name: "bg=7 (dark boundary)", colorFgBg: "0;7", want: true},
		{name: "bg=8 (light)", colorFgBg: "0;8", want: false},
		{name: "bg=15 (light)", colorFgBg: "0;15", want: false},
		{name: "single segment no semicolon", colorFgBg: "15", want: true},
		{name: "multiple semicolons last segment dark", colorFgBg: "15;12;0", want: true},
		{name: "multiple semicolons last segment light", colorFgBg: "15;12;9", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NO_COLOR", "")
			t.Setenv("COLORFGBG", tc.colorFgBg)
			got := IsSystemDarkTheme()
			if got != tc.want {
				t.Errorf("IsSystemDarkTheme() with COLORFGBG=%q = %v, want %v",
					tc.colorFgBg, got, tc.want)
			}
		})
	}
}

// TestIsSystemDarkTheme_Default verifies that when no environment variables are
// set the function returns true (dark is the default).
func TestIsSystemDarkTheme_Default(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("COLORFGBG", "")

	if got := IsSystemDarkTheme(); !got {
		t.Error("IsSystemDarkTheme() with no env vars should default to true (dark)")
	}
}

// TestThemePalette_DarkAndLightDiffer verifies that the two palettes are not
// identical, catching an accidental copy-paste error.
func TestThemePalette_DarkAndLightDiffer(t *testing.T) {
	if ThemePaletteDark == ThemePaletteLight {
		t.Error("ThemePaletteDark and ThemePaletteLight must not be identical")
	}
	if ThemePaletteDark.Background == ThemePaletteLight.Background {
		t.Errorf("dark and light Background are the same (%q)", ThemePaletteDark.Background)
	}
}
