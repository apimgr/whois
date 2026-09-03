package banner

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestBanner_Fprint_Plain(t *testing.T) {
	// Force dumb terminal
	old := os.Getenv("TERM")
	os.Setenv("TERM", "dumb")
	defer os.Setenv("TERM", old)

	b := &Banner{
		Title:    "Test Banner",
		Subtitle: "A subtitle",
		Version:  "1.0.0",
	}

	var buf bytes.Buffer
	b.Fprint(&buf)

	output := buf.String()
	if !strings.Contains(output, "=== Test Banner ===") {
		t.Error("Plain banner should contain title with === markers")
	}
	if !strings.Contains(output, "A subtitle") {
		t.Error("Plain banner should contain subtitle")
	}
	if !strings.Contains(output, "Version: 1.0.0") {
		t.Error("Plain banner should contain version")
	}
}

func TestBanner_Fprint_Styled(t *testing.T) {
	old := os.Getenv("TERM")
	os.Setenv("TERM", "xterm-256color")
	defer os.Setenv("TERM", old)

	b := &Banner{
		Title:   "Test Banner",
		Version: "1.0.0",
		Width:   40,
	}

	var buf bytes.Buffer
	b.Fprint(&buf)

	output := buf.String()
	if !strings.Contains(output, "╔") {
		t.Error("Styled banner should contain box drawing characters")
	}
	if !strings.Contains(output, "Test Banner") {
		t.Error("Styled banner should contain title")
	}
}

func TestBanner_NoSubtitle(t *testing.T) {
	old := os.Getenv("TERM")
	os.Setenv("TERM", "dumb")
	defer os.Setenv("TERM", old)

	b := &Banner{
		Title: "Only Title",
	}

	var buf bytes.Buffer
	b.Fprint(&buf)

	output := buf.String()
	if !strings.Contains(output, "Only Title") {
		t.Error("Banner should contain title")
	}
	// Should not have Version: line when empty
	if strings.Contains(output, "Version:") {
		t.Error("Banner should not have Version line when empty")
	}
}

func TestCenterText(t *testing.T) {
	tests := []struct {
		text  string
		width int
	}{
		{"hello", 20},
		{"x", 10},
		{"long text that exceeds", 10},
	}

	for _, tt := range tests {
		result := centerText(tt.text, tt.width)
		if len(result) != tt.width {
			t.Errorf("centerText(%q, %d) returned len=%d, want %d", tt.text, tt.width, len(result), tt.width)
		}
	}
}

func TestPrintStatus_Dumb(t *testing.T) {
	old := os.Getenv("TERM")
	os.Setenv("TERM", "dumb")
	defer os.Setenv("TERM", old)

	// Capture output - just verify no panic
	PrintStatus("ok", "test message")
	PrintStatus("error", "test error")
	PrintStatus("warning", "test warning")
	PrintStatus("info", "test info")
	PrintStatus("custom", "custom status")
}

func TestPrintStatus_Styled(t *testing.T) {
	old := os.Getenv("TERM")
	os.Setenv("TERM", "xterm")
	defer os.Setenv("TERM", old)

	// Just verify no panic
	PrintStatus("success", "success message")
	PrintStatus("fail", "fail message")
	PrintStatus("warn", "warn message")
}

func TestPrintHelpers(t *testing.T) {
	old := os.Getenv("TERM")
	os.Setenv("TERM", "dumb")
	defer os.Setenv("TERM", old)

	// Just verify no panic
	PrintError("error")
	PrintSuccess("success")
	PrintWarning("warning")
	PrintInfo("info")
	PrintSimple("simple")
}

func TestPrintSimple_Styled(t *testing.T) {
	old := os.Getenv("TERM")
	os.Setenv("TERM", "xterm")
	defer os.Setenv("TERM", old)

	// Just verify no panic - should use arrow
	PrintSimple("styled simple")
}
