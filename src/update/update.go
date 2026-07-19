package update

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// UpdateChannel represents update channel type
type UpdateChannel string

const (
	ChannelStable UpdateChannel = "stable"
	ChannelBeta   UpdateChannel = "beta"
	ChannelDaily  UpdateChannel = "daily"
)

// Release represents a GitHub release
type Release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []Asset   `json:"assets"`
}

// Asset represents a release asset
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// UpdateInfo contains update information
type UpdateInfo struct {
	Available      bool
	CurrentVersion string
	LatestVersion  string
	ReleaseNotes   string
	DownloadURL    string
	Checksum       string
}

// AutodiscoverResponse mirrors the server's autodiscover response structure.
// Used by CLI to check for updates via server's /api/autodiscover endpoint.
type AutodiscoverResponse struct {
	APIVersion    string                   `json:"api_version"`
	BaseURL       string                   `json:"base_url"`
	CLIVersions   map[string]CLIBinaryInfo `json:"cli_versions"`
	CLIMinVersion string                   `json:"cli_min_version"`
}

// CLIBinaryInfo holds version and checksum for a CLI binary.
type CLIBinaryInfo struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// CheckCLIUpdates checks for CLI updates via server's /api/autodiscover endpoint.
// Per AI.md PART 32, CLI uses autodiscover for version and SHA256 info.
func CheckCLIUpdates(serverURL, currentVersion string) (*UpdateInfo, error) {
	autodiscoverURL := strings.TrimSuffix(serverURL, "/") + "/api/autodiscover"
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(autodiscoverURL)
	if err != nil {
		return nil, fmt.Errorf("autodiscover request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("autodiscover returned status %d", resp.StatusCode)
	}

	var autoResp AutodiscoverResponse
	if err := json.NewDecoder(resp.Body).Decode(&autoResp); err != nil {
		return nil, fmt.Errorf("parse autodiscover response: %w", err)
	}

	// Find CLI binary for this platform
	platformKey := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	binInfo, ok := autoResp.CLIVersions[platformKey]
	if !ok || binInfo.Version == "" {
		return nil, fmt.Errorf("no CLI binary available for platform %s", platformKey)
	}

	available := isNewer(binInfo.Version, currentVersion)
	downloadURL := strings.TrimSuffix(autoResp.BaseURL, "/") + "/cli/binaries/caswhois-cli-" + platformKey

	return &UpdateInfo{
		Available:      available,
		CurrentVersion: currentVersion,
		LatestVersion:  binInfo.Version,
		DownloadURL:    downloadURL,
		Checksum:       binInfo.SHA256,
	}, nil
}

// PerformCLIUpdate downloads and installs CLI update from server.
// Per AI.md PART 32, CLI downloads from server's /cli/binaries/ path.
func PerformCLIUpdate(serverURL, currentVersion string) error {
	info, err := CheckCLIUpdates(serverURL, currentVersion)
	if err != nil {
		return fmt.Errorf("check for updates: %w", err)
	}

	if !info.Available {
		return fmt.Errorf("already on latest version: %s", currentVersion)
	}

	// Download new binary to temp location
	tempFile, err := downloadBinary(info.DownloadURL)
	if err != nil {
		return fmt.Errorf("download binary: %w", err)
	}
	defer os.Remove(tempFile)

	// Verify checksum
	if info.Checksum != "" {
		if err := verifyChecksum(tempFile, info.Checksum); err != nil {
			return fmt.Errorf("checksum verification failed: %w", err)
		}
	}

	// Get current binary path
	currentPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	// Replace binary (platform-specific)
	if err := replaceBinary(currentPath, tempFile); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}

	// Re-exec the new binary with original args
	if err := reexecSelf(); err != nil {
		return fmt.Errorf("re-exec: %w", err)
	}

	return nil
}

// CheckForUpdates checks GitHub for available updates (server self-update).
// Per AI.md PART 22 specification.
func CheckForUpdates(currentVersion string, channel UpdateChannel) (*UpdateInfo, error) {
	// Get latest release from GitHub API
	release, err := getLatestRelease(channel)
	if err != nil {
		return nil, fmt.Errorf("get latest release: %w", err)
	}

	// Compare versions
	available := isNewer(release.TagName, currentVersion)

	// Find appropriate binary for this platform
	binaryName := getBinaryName()
	downloadURL := ""
	checksum := ""

	var assetName string
	for _, asset := range release.Assets {
		if strings.Contains(asset.Name, binaryName) {
			assetName = asset.Name
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		return nil, fmt.Errorf("no binary found for platform: %s", binaryName)
	}

	// Checksum is recorded in the release's single checksums.txt asset
	// (sha256sum format: "{hex-digest}  {filename}" per line), not a
	// per-asset .sha256 file (AI.md PART 22).
	checksum, err = fetchExpectedChecksum(release, assetName)
	if err != nil {
		return nil, fmt.Errorf("fetch checksum: %w", err)
	}

	return &UpdateInfo{
		Available:      available,
		CurrentVersion: currentVersion,
		LatestVersion:  release.TagName,
		ReleaseNotes:   release.Name,
		DownloadURL:    downloadURL,
		Checksum:       checksum,
	}, nil
}

// PerformUpdate downloads and installs the update
// Per AI.md PART 22 specification
func PerformUpdate(currentVersion string, channel UpdateChannel) error {
	// Check for updates
	info, err := CheckForUpdates(currentVersion, channel)
	if err != nil {
		return fmt.Errorf("check for updates: %w", err)
	}

	if !info.Available {
		return fmt.Errorf("already on latest version: %s", currentVersion)
	}

	return InstallUpdate(info)
}

// InstallUpdate downloads and installs a previously discovered update. Used
// by PerformUpdate (manual --update yes) and by the scheduled update_check
// task (AI.md PART 22, server.update.auto_install) so the task installs the
// exact defer-eligible release it found rather than re-resolving the true
// latest release.
func InstallUpdate(info *UpdateInfo) error {
	// Download new binary to temp location
	tempFile, err := downloadBinary(info.DownloadURL)
	if err != nil {
		return fmt.Errorf("download binary: %w", err)
	}
	defer os.Remove(tempFile)

	// Verify checksum
	if err := verifyChecksum(tempFile, info.Checksum); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	// Get current binary path
	currentPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	// Replace binary (platform-specific)
	if err := replaceBinary(currentPath, tempFile); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}

	// Restart self (platform-specific)
	if err := restartSelf(); err != nil {
		return fmt.Errorf("restart: %w", err)
	}

	return nil
}

// SetUpdateChannel sets the update channel and persists to config
func SetUpdateChannel(channel UpdateChannel, configPath string) error {
	// Validate channel
	switch channel {
	case ChannelStable, ChannelBeta, ChannelDaily:
		// Valid
	default:
		return fmt.Errorf("invalid channel: %s (must be: stable, beta, or daily)", channel)
	}

	// Read existing config
	configFile := filepath.Join(configPath, "server.yml")
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	// Locate the "branch:" line nested under the top-level "update:" block
	// (AI.md PART 22 schema: server.update.branch) and replace its value.
	lines := strings.Split(string(data), "\n")
	found := false
	inUpdateBlock := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if trimmed == "update:" && indent == 0 {
			inUpdateBlock = true
			continue
		}
		if inUpdateBlock {
			if indent == 0 && trimmed != "" {
				// Left the update: block without finding branch: — insert it.
				branchLine := fmt.Sprintf("  branch: %s", string(channel))
				lines = append(lines[:i], append([]string{branchLine}, lines[i:]...)...)
				found = true
				break
			}
			if strings.HasPrefix(trimmed, "branch:") {
				lines[i] = fmt.Sprintf("  branch: %s", string(channel))
				found = true
				break
			}
		}
	}

	// If no update: block exists at all, append one.
	if !found {
		lines = append(lines, "update:", fmt.Sprintf("  branch: %s", string(channel)))
	}

	// Write back
	newData := strings.Join(lines, "\n")
	if err := os.WriteFile(configFile, []byte(newData), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

// getLatestRelease fetches latest release from GitHub API
func getLatestRelease(channel UpdateChannel) (*Release, error) {
	// GitHub API endpoint
	apiURL := "https://api.github.com/repos/apimgr/whois/releases"

	// Adjust endpoint based on channel
	switch channel {
	case ChannelStable:
		// /latest returns the most recent non-prerelease release.
		apiURL += "/latest"
	case ChannelBeta, ChannelDaily:
		// Fetch the most recent release (including prereleases) and filter below.
		apiURL += "?per_page=1"
	}

	// Make HTTP request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no updates available (404)")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	// Parse response
	var release Release
	if channel == ChannelStable {
		// Single release object
		if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
	} else {
		// Array of releases
		var releases []Release
		if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		if len(releases) == 0 {
			return nil, fmt.Errorf("no releases found")
		}
		release = releases[0]
	}

	return &release, nil
}

// IsEligibleForAutoUpdate reports whether a release published at publishedAt
// has cleared the defer window. Per AI.md PART 22: "A release is eligible
// only once now - published_at >= defer_days." Manual --update check/yes
// calls never consult this — it only gates the scheduled update_check task.
func IsEligibleForAutoUpdate(publishedAt time.Time, deferDays int) bool {
	if deferDays <= 0 {
		return true
	}
	return time.Since(publishedAt) >= time.Duration(deferDays)*24*time.Hour
}

// CheckForUpdatesScheduled is used by the scheduler's update_check task. It
// scans recent releases on channel for the newest one that is both newer
// than currentVersion and past the defer_days eligibility window, per AI.md
// PART 22. Unlike CheckForUpdates (used by manual --update check/yes, which
// always sees the true latest release), this respects deferDays.
func CheckForUpdatesScheduled(currentVersion string, channel UpdateChannel, deferDays int) (*UpdateInfo, error) {
	releases, err := getRecentReleases(channel)
	if err != nil {
		return nil, fmt.Errorf("get recent releases: %w", err)
	}

	binaryName := getBinaryName()
	for _, release := range releases {
		if !isNewer(release.TagName, currentVersion) {
			continue
		}
		if !IsEligibleForAutoUpdate(release.PublishedAt, deferDays) {
			continue
		}

		var downloadURL, assetName string
		for _, asset := range release.Assets {
			if strings.Contains(asset.Name, binaryName) {
				assetName = asset.Name
				downloadURL = asset.BrowserDownloadURL
				break
			}
		}
		if downloadURL == "" {
			continue
		}

		checksum, err := fetchExpectedChecksum(&release, assetName)
		if err != nil {
			return nil, fmt.Errorf("fetch checksum: %w", err)
		}

		return &UpdateInfo{
			Available:      true,
			CurrentVersion: currentVersion,
			LatestVersion:  release.TagName,
			ReleaseNotes:   release.Name,
			DownloadURL:    downloadURL,
			Checksum:       checksum,
		}, nil
	}

	return &UpdateInfo{Available: false, CurrentVersion: currentVersion}, nil
}

// getRecentReleases fetches recent releases from GitHub for channel,
// newest first, so callers can find the newest release that is both newer
// than the running version and past the defer_days eligibility window.
func getRecentReleases(channel UpdateChannel) ([]Release, error) {
	apiURL := "https://api.github.com/repos/apimgr/whois/releases?per_page=20"

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var releases []Release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	filtered := releases[:0]
	for _, r := range releases {
		if channel == ChannelStable && r.Prerelease {
			continue
		}
		filtered = append(filtered, r)
	}

	return filtered, nil
}

// isNewer returns true when latest is a higher semver than current.
// Strips the leading 'v' prefix before comparing, then compares numeric
// major/minor/patch segments so "1.10.0" > "1.9.0" works correctly.
func isNewer(latest, current string) bool {
	latest = strings.TrimPrefix(latest, "v")
	current = strings.TrimPrefix(current, "v")
	if latest == current {
		return false
	}
	return semverGreater(latest, current)
}

// semverGreater returns true when a is numerically greater than b.
// Non-numeric segments fall back to lexicographic comparison so the function
// is safe to call on any tag-like string.
func semverGreater(a, b string) bool {
	aParts := strings.SplitN(a, ".", 3)
	bParts := strings.SplitN(b, ".", 3)
	for len(aParts) < 3 {
		aParts = append(aParts, "0")
	}
	for len(bParts) < 3 {
		bParts = append(bParts, "0")
	}
	for i := 0; i < 3; i++ {
		av := parseVersionSegment(aParts[i])
		bv := parseVersionSegment(bParts[i])
		if av != bv {
			return av > bv
		}
	}
	return false
}

// parseVersionSegment converts a version segment string to an integer.
// Returns -1 for non-numeric segments so they sort below any valid number.
func parseVersionSegment(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// getBinaryName returns the platform-specific binary name
func getBinaryName() string {
	// Format: caswhois-{os}-{arch}
	// Example: caswhois-linux-amd64, caswhois-darwin-arm64
	return fmt.Sprintf("caswhois-%s-%s", runtime.GOOS, runtime.GOARCH)
}

// downloadBinary downloads binary to temp file
func downloadBinary(url string) (string, error) {
	// Create temp file
	tempFile, err := os.CreateTemp("", "caswhois-update-*")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer tempFile.Close()

	// Download file
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	// Copy content
	if _, err := io.Copy(tempFile, resp.Body); err != nil {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("copy content: %w", err)
	}

	// Make executable
	if err := os.Chmod(tempFile.Name(), 0755); err != nil {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("set executable: %w", err)
	}

	return tempFile.Name(), nil
}

// fetchExpectedChecksum downloads the release's single checksums.txt asset
// and returns the SHA-256 digest recorded for assetName. The file is in
// standard sha256sum format: "{hex-digest}  {filename}" per line (AI.md PART 22).
func fetchExpectedChecksum(release *Release, assetName string) (string, error) {
	var checksumsURL string
	for _, asset := range release.Assets {
		if asset.Name == "checksums.txt" {
			checksumsURL = asset.BrowserDownloadURL
			break
		}
	}
	if checksumsURL == "" {
		return "", fmt.Errorf("checksums.txt not found in release assets")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(checksumsURL)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read content: %w", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		// sha256sum output may prefix the filename with "*" for binary mode.
		name := strings.TrimPrefix(fields[1], "*")
		if name == assetName {
			return fields[0], nil
		}
	}

	return "", fmt.Errorf("no checksum entry for %s", assetName)
}

// verifyChecksum verifies file SHA-256 checksum
func verifyChecksum(filePath, expectedChecksum string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	// Calculate SHA-256
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("calculate checksum: %w", err)
	}

	actualChecksum := hex.EncodeToString(h.Sum(nil))

	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	return nil
}

// replaceBinary and restartSelf are platform-specific
// See update_unix.go and update_windows.go
