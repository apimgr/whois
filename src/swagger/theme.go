package swagger

// Theme identifies a Swagger UI color theme.
type Theme string

const (
	// ThemeDark is the default dark theme (AI.md PART 16 — dark mode default).
	ThemeDark Theme = "dark"
	// ThemeLight is the light theme alternative.
	ThemeLight Theme = "light"
)

// ThemeCSS returns the inline CSS block for the given Swagger UI theme.
// Dark mode uses a filter-invert approach over the upstream Swagger UI
// stylesheet since swagger-ui-dist ships light-only CSS (AI.md PART 16).
func ThemeCSS(theme Theme) string {
	if theme == ThemeLight {
		return `    :root {
      --color-bg: #ffffff;
      --color-fg: #24292f;
    }
    .swagger-ui .topbar { display: none; }`
	}

	return `    :root {
      --color-bg: #0d1117;
      --color-fg: #c9d1d9;
    }
    [data-theme="dark"] body {
      background: var(--color-bg);
    }
    [data-theme="dark"] .swagger-ui {
      filter: invert(88%) hue-rotate(180deg);
    }
    [data-theme="dark"] .swagger-ui img {
      filter: invert(100%) hue-rotate(180deg);
    }
    .swagger-ui .topbar { display: none; }`
}
