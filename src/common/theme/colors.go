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
	Background: "#1a1b26", Foreground: "#c0caf5",
	Primary: "#7aa2f7", Secondary: "#9ece6a", Accent: "#bb9af7",
	Success: "#9ece6a", Warning: "#e0af68", Error: "#f7768e", Info: "#7dcfff",
	Surface: "#24283b", SurfaceAlt: "#1f2335", Border: "#414868", Muted: "#565f89",
}

// ThemePaletteLight is the light theme palette.
var ThemePaletteLight = ThemePalette{
	Background: "#ffffff", Foreground: "#1a1b26",
	Primary: "#2e7de9", Secondary: "#587539", Accent: "#7847bd",
	Success: "#587539", Warning: "#8c6c3e", Error: "#c64343", Info: "#007197",
	Surface: "#f5f5f5", SurfaceAlt: "#e9e9ec", Border: "#c0caf5", Muted: "#6172b0",
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
