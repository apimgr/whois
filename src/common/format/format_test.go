package format

import (
	"testing"
	"time"
)

func TestDuration(t *testing.T) {
	tests := []struct {
		name  string
		value time.Duration
		want  string
	}{
		{name: "seconds singular", value: time.Second, want: "1 second"},
		{name: "seconds plural", value: 45 * time.Second, want: "45 seconds"},
		{name: "two units", value: 2*time.Minute + 5*time.Second, want: "2 minutes 5 seconds"},
		{name: "hours", value: 2 * time.Hour, want: "2 hours"},
		{name: "days", value: 3*24*time.Hour + 4*time.Hour, want: "3 days 4 hours"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Duration(test.value, "en"); got != test.want {
				t.Errorf("Duration(%s) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

func TestSize(t *testing.T) {
	tests := []struct {
		name  string
		bytes uint64
		want  string
	}{
		{name: "singular byte", bytes: 1, want: "1 byte"},
		{name: "bytes", bytes: 512, want: "512 bytes"},
		{name: "kilobyte", bytes: 1024, want: "1 kilobyte"},
		{name: "fraction", bytes: 2560, want: "2.5 kilobytes"},
		{name: "megabyte", bytes: 5 * 1024 * 1024, want: "5 megabytes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Size(test.bytes, "en"); got != test.want {
				t.Errorf("Size(%d) = %q, want %q", test.bytes, got, test.want)
			}
		})
	}
}

func TestCount(t *testing.T) {
	if got := Count(12847, "en"); got != "12,847" {
		t.Errorf("Count(12847) = %q, want %q", got, "12,847")
	}
}
