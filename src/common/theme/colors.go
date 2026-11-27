package theme

import "os"

// ThemePalette holds a complete set of UI colors for a single theme variant.
// All colors are hex strings (e.g. "#1a1b26"). Used by web CSS, TUI, CLI, and GUI.
type ThemePalette struct {
	Background string `json:"background"`
	Foreground string `json:"foreground"`
	Primary    string `json:"primary"`
	Secondary  string `json:"secondary"`
	Accent     string `json:"accent"`
	Success    string `json:"success"`
	Warning    string `json:"warning"`
	Error      string `json:"error"`
	Info       string `json:"info"`
	Surface    string `json:"surface"`
	SurfaceAlt string `json:"surface_alt"`
	Border     string `json:"border"`
	Muted      string `json:"muted"`
}

// ThemePaletteDark is the default dark theme palette.
var ThemePaletteDark = ThemePalette{
	Background: "#282a36", Foreground: "#f8f8f2",
	Primary: "#bd93f9", Secondary: "#50fa7b", Accent: "#ff79c6",
	Success: "#50fa7b", Warning: "#ffb86c", Error: "#ff5555", Info: "#8be9fd",
	Surface: "#2b2d3a", SurfaceAlt: "#21222c", Border: "#44475a", Muted: "#939fcc",
}

// ThemePaletteLight is the light theme palette.
var ThemePaletteLight = ThemePalette{
	Background: "#ffffff", Foreground: "#1f2328",
	Primary: "#0969da", Secondary: "#1a7f37", Accent: "#8250df",
	Success: "#1a7f37", Warning: "#9a6700", Error: "#d1242f", Info: "#0969da",
	Surface: "#f6f8fa", SurfaceAlt: "#eff2f5", Border: "#d1d9e0", Muted: "#59636e",
}

// GetThemePalette returns the palette for the given mode ("dark", "light", "auto").
// Unknown values default to dark.
func GetThemePalette(mode string) ThemePalette {
	switch mode {
	case "light":
		return ThemePaletteLight
	case "auto":
		if IsSystemDarkTheme() {
			return ThemePaletteDark
		}
		return ThemePaletteLight
	default:
		return ThemePaletteDark
	}
}

// IsSystemDarkTheme returns true when the host environment prefers a dark color scheme.
// Falls back to true (dark) when detection is not possible.
func IsSystemDarkTheme() bool {
	// NO_COLOR means monochrome — treat as dark (no background assumption)
	if os.Getenv("NO_COLOR") != "" {
		return true
	}
	// COLORFGBG is set by some terminals: "fg;bg" where bg < 8 means dark.
	// Parse the numeric background value; single-character comparison is wrong for values >= 10.
	if v := os.Getenv("COLORFGBG"); v != "" {
		for i := len(v) - 1; i >= 0; i-- {
			if v[i] == ';' {
				bg := v[i+1:]
				n := 0
				for _, c := range bg {
					if c < '0' || c > '9' {
						break
					}
					n = n*10 + int(c-'0')
				}
				return n < 8
			}
		}
	}
	// Default: dark
	return true
}
