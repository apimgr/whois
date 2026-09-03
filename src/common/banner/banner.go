// Package banner provides ASCII banner output with TERM=dumb handling.
package banner

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/apimgr/whois/src/common/terminal"
)

// Banner represents a text banner
type Banner struct {
	// Title is the main text
	Title string
	// Subtitle is optional secondary text
	Subtitle string
	// Version string
	Version string
	// Width override (0 = auto-detect)
	Width int
}

// Print writes the banner to stdout
func (b *Banner) Print() {
	b.Fprint(os.Stdout)
}

// Fprint writes the banner to the given writer
func (b *Banner) Fprint(w io.Writer) {
	if terminal.IsDumbTerminal() {
		b.fprintPlain(w)
		return
	}
	b.fprintStyled(w)
}

// fprintPlain writes a plain text banner (no ANSI, no box drawing)
func (b *Banner) fprintPlain(w io.Writer) {
	fmt.Fprintf(w, "=== %s ===\n", b.Title)
	if b.Subtitle != "" {
		fmt.Fprintf(w, "%s\n", b.Subtitle)
	}
	if b.Version != "" {
		fmt.Fprintf(w, "Version: %s\n", b.Version)
	}
	fmt.Fprintln(w)
}

// fprintStyled writes a styled banner with box drawing
func (b *Banner) fprintStyled(w io.Writer) {
	width := b.Width
	if width == 0 {
		width = 60
		if cols, _, err := terminal.GetStdoutSize(); err == nil && cols > 0 {
			if cols < 60 {
				width = cols
			}
		}
	}

	// Calculate content width
	contentWidth := width - 4
	if contentWidth < 20 {
		contentWidth = 20
	}

	// Top border
	fmt.Fprintf(w, "╔%s╗\n", strings.Repeat("═", contentWidth+2))

	// Title (centered)
	title := centerText(b.Title, contentWidth)
	fmt.Fprintf(w, "║ %s ║\n", title)

	// Subtitle if present
	if b.Subtitle != "" {
		subtitle := centerText(b.Subtitle, contentWidth)
		fmt.Fprintf(w, "║ %s ║\n", subtitle)
	}

	// Version if present
	if b.Version != "" {
		version := centerText("Version: "+b.Version, contentWidth)
		fmt.Fprintf(w, "║ %s ║\n", version)
	}

	// Bottom border
	fmt.Fprintf(w, "╚%s╝\n", strings.Repeat("═", contentWidth+2))
}

// centerText centers text within the given width
func centerText(text string, width int) string {
	if len(text) >= width {
		return text[:width]
	}
	padding := (width - len(text)) / 2
	return fmt.Sprintf("%s%s%s", strings.Repeat(" ", padding), text, strings.Repeat(" ", width-len(text)-padding))
}

// PrintSimple prints a simple one-line banner
func PrintSimple(title string) {
	if terminal.IsDumbTerminal() {
		fmt.Printf("[%s]\n", title)
	} else {
		fmt.Printf("▶ %s\n", title)
	}
}

// PrintStatus prints a status message with appropriate prefix
func PrintStatus(status, message string) {
	if terminal.IsDumbTerminal() {
		fmt.Printf("[%s] %s\n", strings.ToUpper(status), message)
		return
	}

	// Use emojis for styled output
	var prefix string
	switch strings.ToLower(status) {
	case "ok", "success", "done":
		prefix = "✓"
	case "error", "fail", "failed":
		prefix = "✗"
	case "warn", "warning":
		prefix = "⚠"
	case "info":
		prefix = "ℹ"
	default:
		prefix = "•"
	}
	fmt.Printf("%s %s\n", prefix, message)
}

// PrintError prints an error message
func PrintError(message string) {
	PrintStatus("error", message)
}

// PrintSuccess prints a success message
func PrintSuccess(message string) {
	PrintStatus("success", message)
}

// PrintWarning prints a warning message
func PrintWarning(message string) {
	PrintStatus("warning", message)
}

// PrintInfo prints an info message
func PrintInfo(message string) {
	PrintStatus("info", message)
}
