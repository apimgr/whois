package geoip

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
)

// downloadDatabase downloads a GeoIP database from URL to filepath.
// userAgent must be a real build-injected identifier (e.g. "caswhois/1.2.3"),
// supplied by the caller — never hardcoded here (AI.md: "never hardcode dev
// values — detect at runtime").
func downloadDatabase(ctx context.Context, url, filepath, userAgent string) error {
	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set User-Agent
	if userAgent == "" {
		userAgent = "caswhois"
	}
	req.Header.Set("User-Agent", userAgent)

	// Execute request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "geoip-*.mmdb")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	// Clean up if we fail
	defer os.Remove(tmpPath)

	// Copy response body to temp file
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write database: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Move temp file to final destination
	if err := os.Rename(tmpPath, filepath); err != nil {
		return fmt.Errorf("failed to move database: %w", err)
	}

	return nil
}
