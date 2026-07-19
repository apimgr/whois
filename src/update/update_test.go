//go:build !windows
// +build !windows

package update

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// redirectTransport rewrites every request URL to point at a test server,
// preserving the original path and query so handler routing still works.
// This is needed because getLatestRelease and fetchExpectedChecksum create their
// own http.Client{} values that fall through to http.DefaultTransport.
type redirectTransport struct {
	target string
	base   http.RoundTripper
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = rt.target
	return rt.base.RoundTrip(clone)
}

// patchDefaultTransport replaces http.DefaultTransport for the duration of one
// test and restores it when the returned cleanup function is called.
func patchDefaultTransport(target string) func() {
	orig := http.DefaultTransport
	http.DefaultTransport = &redirectTransport{target: target, base: orig}
	return func() { http.DefaultTransport = orig }
}

// --- isNewer tests -----------------------------------------------------------
// Covers: identical versions, v-prefix stripping, newer/older comparisons,
// empty strings, pre-release ordering, patch/major increments.

func TestIsNewer(t *testing.T) {
	cases := []struct {
		name    string
		latest  string
		current string
		want    bool
	}{
		{name: "newer version", latest: "v1.2.0", current: "v1.1.0", want: true},
		{name: "same version", latest: "v1.1.0", current: "v1.1.0", want: false},
		{name: "older version", latest: "v1.0.0", current: "v1.1.0", want: false},
		{name: "newer without v prefix", latest: "1.2.0", current: "1.1.0", want: true},
		{name: "same without v prefix", latest: "1.1.0", current: "1.1.0", want: false},
		{name: "latest has v, current does not", latest: "v1.2.0", current: "1.1.0", want: true},
		{name: "latest lacks v, current has it", latest: "1.2.0", current: "v1.1.0", want: true},
		{name: "both empty", latest: "", current: "", want: false},
		{name: "latest empty, current set", latest: "", current: "v1.0.0", want: false},
		{name: "patch increment", latest: "v1.0.1", current: "v1.0.0", want: true},
		{name: "major increment", latest: "v2.0.0", current: "v1.9.9", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isNewer(tc.latest, tc.current)
			if got != tc.want {
				t.Errorf("isNewer(%q, %q) = %v, want %v", tc.latest, tc.current, got, tc.want)
			}
		})
	}
}

// --- getBinaryName tests -----------------------------------------------------
// Covers: return format matches runtime.GOOS + runtime.GOARCH and is non-empty.

func TestGetBinaryName(t *testing.T) {
	got := getBinaryName()

	wantContainOS := runtime.GOOS
	wantContainArch := runtime.GOARCH
	wantPrefix := "caswhois-"

	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("getBinaryName() = %q, want prefix %q", got, wantPrefix)
	}
	if !strings.Contains(got, wantContainOS) {
		t.Errorf("getBinaryName() = %q, want to contain GOOS %q", got, wantContainOS)
	}
	if !strings.Contains(got, wantContainArch) {
		t.Errorf("getBinaryName() = %q, want to contain GOARCH %q", got, wantContainArch)
	}
	want := fmt.Sprintf("caswhois-%s-%s", runtime.GOOS, runtime.GOARCH)
	if got != want {
		t.Errorf("getBinaryName() = %q, want %q", got, want)
	}
}

// --- verifyChecksum tests ----------------------------------------------------
// Covers: matching checksum passes, mismatched checksum errors, missing file,
// empty file, idempotency (same file run twice).

func TestVerifyChecksum_Match(t *testing.T) {
	content := []byte("hello caswhois update")
	h := sha256.Sum256(content)
	expected := hex.EncodeToString(h[:])

	f, err := os.CreateTemp("", "caswhois-checksum-test-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.Write(content); err != nil {
		t.Fatalf("Write: %v", err)
	}
	f.Close()

	if err := verifyChecksum(f.Name(), expected); err != nil {
		t.Errorf("verifyChecksum with correct hash returned error: %v", err)
	}
}

func TestVerifyChecksum_Mismatch(t *testing.T) {
	content := []byte("real content")
	f, err := os.CreateTemp("", "caswhois-checksum-mismatch-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.Write(content); err != nil {
		t.Fatalf("Write: %v", err)
	}
	f.Close()

	wrongChecksum := strings.Repeat("0", 64)
	if err := verifyChecksum(f.Name(), wrongChecksum); err == nil {
		t.Error("verifyChecksum with wrong hash expected error, got nil")
	}
}

func TestVerifyChecksum_MissingFile(t *testing.T) {
	err := verifyChecksum("/tmp/caswhois-nonexistent-file-xyz.bin", strings.Repeat("a", 64))
	if err == nil {
		t.Error("verifyChecksum with missing file expected error, got nil")
	}
}

func TestVerifyChecksum_EmptyFile(t *testing.T) {
	h := sha256.Sum256([]byte{})
	expected := hex.EncodeToString(h[:])

	f, err := os.CreateTemp("", "caswhois-empty-checksum-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	f.Close()
	defer os.Remove(f.Name())

	if err := verifyChecksum(f.Name(), expected); err != nil {
		t.Errorf("verifyChecksum on empty file with correct hash: %v", err)
	}
}

// TestVerifyChecksum_Idempotent verifies calling verifyChecksum twice gives same result.
func TestVerifyChecksum_Idempotent(t *testing.T) {
	content := []byte("idempotent check")
	h := sha256.Sum256(content)
	expected := hex.EncodeToString(h[:])

	f, err := os.CreateTemp("", "caswhois-idempotent-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(content); err != nil {
		t.Fatalf("Write: %v", err)
	}
	f.Close()

	err1 := verifyChecksum(f.Name(), expected)
	err2 := verifyChecksum(f.Name(), expected)
	if err1 != nil || err2 != nil {
		t.Errorf("idempotent calls: err1=%v err2=%v", err1, err2)
	}
}

// --- SetUpdateChannel tests --------------------------------------------------
// Covers: valid channels written/updated in YAML, invalid channel rejected,
// line replaced in-place, appended when absent, idempotent same-channel call.

func TestSetUpdateChannel_ValidChannels(t *testing.T) {
	cases := []struct {
		channel UpdateChannel
	}{
		{ChannelStable},
		{ChannelBeta},
		{ChannelDaily},
	}

	for _, tc := range cases {
		t.Run(string(tc.channel), func(t *testing.T) {
			dir, err := os.MkdirTemp("", "caswhois-update-channel-*")
			if err != nil {
				t.Fatalf("MkdirTemp: %v", err)
			}
			defer os.RemoveAll(dir)

			yaml := "mode: production\nupdate:\n  branch: stable\n"
			if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte(yaml), 0600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			if err := SetUpdateChannel(tc.channel, dir); err != nil {
				t.Fatalf("SetUpdateChannel(%q) returned error: %v", tc.channel, err)
			}

			data, err := os.ReadFile(filepath.Join(dir, "server.yml"))
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			wantLine := fmt.Sprintf("branch: %s", string(tc.channel))
			if !strings.Contains(string(data), wantLine) {
				t.Errorf("config does not contain %q after update;\nfile:\n%s", wantLine, string(data))
			}
		})
	}
}

func TestSetUpdateChannel_InvalidChannel(t *testing.T) {
	dir, err := os.MkdirTemp("", "caswhois-invalid-channel-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	yaml := "mode: production\n"
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte(yaml), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err = SetUpdateChannel("nightly", dir)
	if err == nil {
		t.Error("SetUpdateChannel(\"nightly\") expected error, got nil")
	}
}

func TestSetUpdateChannel_MissingFile(t *testing.T) {
	dir, err := os.MkdirTemp("", "caswhois-missing-yaml-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	err = SetUpdateChannel(ChannelBeta, dir)
	if err == nil {
		t.Error("SetUpdateChannel with missing server.yml expected error, got nil")
	}
}

// TestSetUpdateChannel_KeyNotPresentIsAppended verifies the key is appended when absent.
func TestSetUpdateChannel_KeyNotPresentIsAppended(t *testing.T) {
	dir, err := os.MkdirTemp("", "caswhois-append-channel-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	yaml := "mode: production\nport: 64500\n"
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte(yaml), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := SetUpdateChannel(ChannelBeta, dir); err != nil {
		t.Fatalf("SetUpdateChannel: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "server.yml"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "branch: beta") {
		t.Errorf("expected appended key; file:\n%s", string(data))
	}
}

// TestSetUpdateChannel_InPlaceReplacement verifies only the existing line is changed.
func TestSetUpdateChannel_InPlaceReplacement(t *testing.T) {
	dir, err := os.MkdirTemp("", "caswhois-replace-channel-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	yaml := "mode: production\nupdate:\n  branch: stable\nport: 64500\n"
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte(yaml), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := SetUpdateChannel(ChannelDaily, dir); err != nil {
		t.Fatalf("SetUpdateChannel: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "server.yml"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "branch: daily") {
		t.Errorf("new channel not found; file:\n%s", content)
	}
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "branch:") &&
			strings.Contains(line, "stable") {
			t.Errorf("old channel still present in line: %q", line)
		}
	}
}

// TestSetUpdateChannel_IdempotentSameChannel verifies calling twice with same channel is safe.
func TestSetUpdateChannel_IdempotentSameChannel(t *testing.T) {
	dir, err := os.MkdirTemp("", "caswhois-idempotent-channel-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	yaml := "mode: production\nupdate:\n  branch: stable\n"
	if err := os.WriteFile(filepath.Join(dir, "server.yml"), []byte(yaml), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := SetUpdateChannel(ChannelStable, dir); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := SetUpdateChannel(ChannelStable, dir); err != nil {
		t.Fatalf("second call: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "server.yml"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	count := strings.Count(string(data), "branch:")
	if count != 1 {
		t.Errorf("expected 1 branch line, got %d; file:\n%s", count, string(data))
	}
}

// --- helpers -----------------------------------------------------------------

// buildTestRelease creates a Release with assets matching the current platform.
// The asset download URLs use a placeholder host that the test server will serve.
func buildTestRelease(tag string, prerelease bool, serverHost string) Release {
	binaryName := getBinaryName()
	base := "http://" + serverHost
	return Release{
		TagName:     tag,
		Name:        "Release " + tag,
		Prerelease:  prerelease,
		PublishedAt: time.Now(),
		Assets: []Asset{
			{
				Name:               binaryName,
				BrowserDownloadURL: base + "/asset/" + binaryName,
				Size:               1024,
			},
			{
				Name:               "checksums.txt",
				BrowserDownloadURL: base + "/asset/checksums.txt",
				Size:               65,
			},
		},
	}
}

// buildChecksumContent returns a GNU sha256sum-style checksum line for the given content.
func buildChecksumContent(content []byte) (checksumLine string, hexHash string) {
	h := sha256.Sum256(content)
	hexHash = hex.EncodeToString(h[:])
	checksumLine = hexHash + "  " + getBinaryName()
	return
}

// --- getLatestRelease tests (via redirectTransport) --------------------------
// Covers: stable channel (single-object JSON), beta/daily channel (array JSON),
// 404 response, non-200/non-404 status, invalid JSON, and empty release list.

// TestGetLatestRelease_StableChannel drives the stable (single-object) decode path.
func TestGetLatestRelease_StableChannel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve only the /repos/apimgr/whois/releases/latest path
		if !strings.Contains(r.URL.Path, "releases/latest") {
			http.NotFound(w, r)
			return
		}
		release := buildTestRelease("v1.5.0", false, r.Host)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release)
	}))
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	got, err := getLatestRelease(ChannelStable)
	if err != nil {
		t.Fatalf("getLatestRelease(stable): %v", err)
	}
	if got.TagName != "v1.5.0" {
		t.Errorf("TagName = %q, want %q", got.TagName, "v1.5.0")
	}
	if len(got.Assets) != 2 {
		t.Errorf("Assets count = %d, want 2", len(got.Assets))
	}
}

// TestGetLatestRelease_BetaChannel drives the beta (array) decode path.
func TestGetLatestRelease_BetaChannel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Beta channel hits /releases?per_page=1
		if !strings.Contains(r.URL.Path, "releases") {
			http.NotFound(w, r)
			return
		}
		releases := []Release{buildTestRelease("v2.0.0-beta.1", true, r.Host)}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(releases)
	}))
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	got, err := getLatestRelease(ChannelBeta)
	if err != nil {
		t.Fatalf("getLatestRelease(beta): %v", err)
	}
	if got.TagName != "v2.0.0-beta.1" {
		t.Errorf("TagName = %q, want %q", got.TagName, "v2.0.0-beta.1")
	}
}

// TestGetLatestRelease_DailyChannel drives the daily (array) decode path.
func TestGetLatestRelease_DailyChannel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		releases := []Release{buildTestRelease("v2.1.0-daily.20260101", true, r.Host)}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(releases)
	}))
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	got, err := getLatestRelease(ChannelDaily)
	if err != nil {
		t.Fatalf("getLatestRelease(daily): %v", err)
	}
	if got.TagName != "v2.1.0-daily.20260101" {
		t.Errorf("TagName = %q, want %q", got.TagName, "v2.1.0-daily.20260101")
	}
}

// TestGetLatestRelease_404 verifies the 404 branch returns an error.
func TestGetLatestRelease_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	_, err := getLatestRelease(ChannelStable)
	if err == nil {
		t.Error("getLatestRelease on 404 expected error, got nil")
	}
}

// TestGetLatestRelease_NonOKStatus verifies a 503 response is rejected.
func TestGetLatestRelease_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	_, err := getLatestRelease(ChannelStable)
	if err == nil {
		t.Error("getLatestRelease on 503 expected error, got nil")
	}
}

// TestGetLatestRelease_InvalidJSON verifies malformed JSON returns a parse error.
func TestGetLatestRelease_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "not valid json {{{")
	}))
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	_, err := getLatestRelease(ChannelStable)
	if err == nil {
		t.Error("getLatestRelease with invalid JSON expected error, got nil")
	}
}

// TestGetLatestRelease_EmptyReleaseList verifies empty array returns an error.
func TestGetLatestRelease_EmptyReleaseList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "[]")
	}))
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	_, err := getLatestRelease(ChannelBeta)
	if err == nil {
		t.Error("getLatestRelease with empty release list expected error, got nil")
	}
}

// --- CheckForUpdates tests (via redirectTransport) ---------------------------
// Covers: update available (newer version), already up to date (same version),
// current version is newer than latest, HTTP error, non-200 response,
// invalid JSON, and no binary asset for platform.

// testServerForCheckForUpdates creates an httptest.Server that serves both the
// releases API endpoint and the binary/checksum asset downloads in one handler.
// It returns the server, binary content used, and the expected checksum hex string.
func testServerForCheckForUpdates(t *testing.T, tag string, binaryContent []byte) (*httptest.Server, string) {
	t.Helper()
	checksumLine, hexHash := buildChecksumContent(binaryContent)
	binaryName := getBinaryName()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "releases/latest"):
			release := buildTestRelease(tag, false, srv.Listener.Addr().String())
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(release)

		case strings.HasSuffix(r.URL.Path, "checksums.txt"):
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, checksumLine)

		case strings.HasSuffix(r.URL.Path, binaryName):
			w.WriteHeader(http.StatusOK)
			w.Write(binaryContent)

		default:
			http.NotFound(w, r)
		}
	}))
	return srv, hexHash
}

// TestCheckForUpdates_NewerVersionAvailable verifies update available is true when latest > current.
func TestCheckForUpdates_NewerVersionAvailable(t *testing.T) {
	binaryContent := []byte("fake binary v2")
	srv, _ := testServerForCheckForUpdates(t, "v2.0.0", binaryContent)
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	info, err := CheckForUpdates("v1.0.0", ChannelStable)
	if err != nil {
		t.Fatalf("CheckForUpdates: %v", err)
	}
	if !info.Available {
		t.Error("Available = false, want true")
	}
	if info.LatestVersion != "v2.0.0" {
		t.Errorf("LatestVersion = %q, want %q", info.LatestVersion, "v2.0.0")
	}
	if info.CurrentVersion != "v1.0.0" {
		t.Errorf("CurrentVersion = %q, want %q", info.CurrentVersion, "v1.0.0")
	}
	if info.DownloadURL == "" {
		t.Error("DownloadURL should not be empty")
	}
	if info.Checksum == "" {
		t.Error("Checksum should not be empty")
	}
}

// TestCheckForUpdates_AlreadyUpToDate verifies Available is false when versions match.
func TestCheckForUpdates_AlreadyUpToDate(t *testing.T) {
	binaryContent := []byte("fake binary v1.0.0")
	srv, _ := testServerForCheckForUpdates(t, "v1.0.0", binaryContent)
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	info, err := CheckForUpdates("v1.0.0", ChannelStable)
	if err != nil {
		t.Fatalf("CheckForUpdates: %v", err)
	}
	if info.Available {
		t.Error("Available = true, want false when already on latest")
	}
}

// TestCheckForUpdates_CurrentNewerThanLatest verifies Available is false when current > latest.
func TestCheckForUpdates_CurrentNewerThanLatest(t *testing.T) {
	binaryContent := []byte("fake binary v1.0.0")
	srv, _ := testServerForCheckForUpdates(t, "v1.0.0", binaryContent)
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	info, err := CheckForUpdates("v2.0.0", ChannelStable)
	if err != nil {
		t.Fatalf("CheckForUpdates: %v", err)
	}
	if info.Available {
		t.Error("Available = true, want false when current > latest")
	}
}

// TestCheckForUpdates_HTTPError verifies a connection failure propagates as error.
func TestCheckForUpdates_HTTPError(t *testing.T) {
	// Point at a server that immediately closes connections
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack the connection to simulate a network error
		w.WriteHeader(http.StatusInternalServerError)
	}))
	srv.Close() // Close immediately so all requests fail

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	_, err := CheckForUpdates("v1.0.0", ChannelStable)
	if err == nil {
		t.Error("CheckForUpdates with closed server expected error, got nil")
	}
}

// TestCheckForUpdates_Non200Response verifies a non-200 GitHub API response is an error.
func TestCheckForUpdates_Non200Response(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	_, err := CheckForUpdates("v1.0.0", ChannelStable)
	if err == nil {
		t.Error("CheckForUpdates on 500 expected error, got nil")
	}
}

// TestCheckForUpdates_InvalidJSON verifies malformed JSON from the releases API is an error.
func TestCheckForUpdates_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "{invalid json}")
	}))
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	_, err := CheckForUpdates("v1.0.0", ChannelStable)
	if err == nil {
		t.Error("CheckForUpdates with invalid JSON expected error, got nil")
	}
}

// TestCheckForUpdates_NoBinaryAssetForPlatform verifies an error when the release
// has no asset matching the current platform binary name.
func TestCheckForUpdates_NoBinaryAssetForPlatform(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases/latest") {
			// Release with assets for a different platform only
			release := Release{
				TagName: "v9.0.0",
				Name:    "New Release",
				Assets: []Asset{
					{
						Name:               "caswhois-plan9-mips64",
						BrowserDownloadURL: "http://" + r.Host + "/asset/caswhois-plan9-mips64",
						Size:               1024,
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(release)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	_, err := CheckForUpdates("v1.0.0", ChannelStable)
	if err == nil {
		t.Error("CheckForUpdates with no platform binary expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no binary found for platform") {
		t.Errorf("error = %q, want 'no binary found for platform' message", err.Error())
	}
}

// TestCheckForUpdates_ChecksumDownloadError verifies an error when the checksum
// asset exists in the release but the download returns a non-200 status.
func TestCheckForUpdates_ChecksumDownloadError(t *testing.T) {
	binaryName := getBinaryName()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "releases/latest"):
			var addr string
			// Use the dynamically assigned server address
			addr = r.Host
			release := Release{
				TagName: "v9.9.9",
				Name:    "Release v9.9.9",
				Assets: []Asset{
					{
						Name:               binaryName,
						BrowserDownloadURL: "http://" + addr + "/asset/" + binaryName,
						Size:               1024,
					},
					{
						Name:               "checksums.txt",
						BrowserDownloadURL: "http://" + addr + "/asset/checksums.txt",
						Size:               65,
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(release)

		case strings.HasSuffix(r.URL.Path, "checksums.txt"):
			// Return error status for checksum download
			w.WriteHeader(http.StatusNotFound)

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	_, err := CheckForUpdates("v1.0.0", ChannelStable)
	if err == nil {
		t.Error("CheckForUpdates with checksum download failure expected error, got nil")
	}
}

// --- PerformUpdate tests -----------------------------------------------------
// Covers: already up to date (returns error), successful download+verify path.

// TestPerformUpdate_AlreadyUpToDate verifies an error is returned when no update is available.
func TestPerformUpdate_AlreadyUpToDate(t *testing.T) {
	binaryContent := []byte("same binary")
	srv, _ := testServerForCheckForUpdates(t, "v1.0.0", binaryContent)
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	err := PerformUpdate("v1.0.0", ChannelStable)
	if err == nil {
		t.Error("PerformUpdate when already up to date expected error, got nil")
	}
	if !strings.Contains(err.Error(), "already on latest version") {
		t.Errorf("error = %q, want 'already on latest version' message", err.Error())
	}
}

// TestPerformUpdate_CheckForUpdatesError verifies the check-error path propagates.
func TestPerformUpdate_CheckForUpdatesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	restore := patchDefaultTransport(srv.Listener.Addr().String())
	defer restore()

	err := PerformUpdate("v1.0.0", ChannelStable)
	if err == nil {
		t.Error("PerformUpdate with API error expected error, got nil")
	}
}

// --- downloadBinary tests ----------------------------------------------------
// Covers: happy path (content written + executable), 404, 500.

// TestDownloadBinary_HappyPath verifies downloadBinary creates an executable temp file.
func TestDownloadBinary_HappyPath(t *testing.T) {
	content := []byte("binary content here")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(content)
	}))
	defer srv.Close()

	path, err := downloadBinary(srv.URL + "/caswhois-linux-amd64")
	if err != nil {
		t.Fatalf("downloadBinary: %v", err)
	}
	defer os.Remove(path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	if info.Size() == 0 {
		t.Error("downloaded file is empty")
	}
	if info.Mode()&0111 == 0 {
		t.Errorf("file mode = %v, want executable bits set", info.Mode())
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("file content = %q, want %q", string(got), string(content))
	}
}

// TestDownloadBinary_404 verifies downloadBinary returns error on 404.
func TestDownloadBinary_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	_, err := downloadBinary(srv.URL + "/nonexistent-binary")
	if err == nil {
		t.Error("downloadBinary on 404 expected error, got nil")
	}
}

// TestDownloadBinary_ServerError verifies downloadBinary returns error on 500.
func TestDownloadBinary_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := downloadBinary(srv.URL + "/error-binary")
	if err == nil {
		t.Error("downloadBinary on 500 expected error, got nil")
	}
}

// TestDownloadBinary_BadURL verifies downloadBinary returns error for an unreachable URL.
func TestDownloadBinary_BadURL(t *testing.T) {
	_, err := downloadBinary("http://127.0.0.1:1/no-server-here")
	if err == nil {
		t.Error("downloadBinary with unreachable URL expected error, got nil")
	}
}

// --- fetchExpectedChecksum tests ---------------------------------------------
// Covers: single checksums.txt asset in standard "hash  filename" sha256sum
// format (AI.md PART 22), missing entry, missing checksums.txt asset, 404,
// unreachable host.

// TestFetchExpectedChecksum_Success verifies the digest is extracted for the
// matching filename out of a standard sha256sum-format checksums.txt body.
func TestFetchExpectedChecksum_Success(t *testing.T) {
	content := []byte("test data")
	h := sha256.Sum256(content)
	expectedHash := hex.EncodeToString(h[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  caswhois-linux-amd64\n%s  caswhois-linux-arm64\n", expectedHash, expectedHash)
	}))
	defer srv.Close()

	release := &Release{Assets: []Asset{
		{Name: "checksums.txt", BrowserDownloadURL: srv.URL + "/checksums.txt"},
	}}

	gotHash, err := fetchExpectedChecksum(release, "caswhois-linux-amd64")
	if err != nil {
		t.Fatalf("fetchExpectedChecksum: %v", err)
	}
	if gotHash != expectedHash {
		t.Errorf("gotHash = %q, want %q", gotHash, expectedHash)
	}
}

// TestFetchExpectedChecksum_BinaryModePrefix verifies the leading "*" that
// sha256sum emits in binary mode is stripped from the filename before matching.
func TestFetchExpectedChecksum_BinaryModePrefix(t *testing.T) {
	content := []byte("solo hash")
	h := sha256.Sum256(content)
	expectedHash := hex.EncodeToString(h[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s *caswhois-linux-amd64\n", expectedHash)
	}))
	defer srv.Close()

	release := &Release{Assets: []Asset{
		{Name: "checksums.txt", BrowserDownloadURL: srv.URL + "/checksums.txt"},
	}}

	gotHash, err := fetchExpectedChecksum(release, "caswhois-linux-amd64")
	if err != nil {
		t.Fatalf("fetchExpectedChecksum: %v", err)
	}
	if gotHash != expectedHash {
		t.Errorf("gotHash = %q, want %q", gotHash, expectedHash)
	}
}

// TestFetchExpectedChecksum_NoEntryForAsset verifies an error is returned when
// checksums.txt does not contain a line for the requested asset name.
func TestFetchExpectedChecksum_NoEntryForAsset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "deadbeef  caswhois-darwin-amd64\n")
	}))
	defer srv.Close()

	release := &Release{Assets: []Asset{
		{Name: "checksums.txt", BrowserDownloadURL: srv.URL + "/checksums.txt"},
	}}

	_, err := fetchExpectedChecksum(release, "caswhois-linux-amd64")
	if err == nil {
		t.Error("fetchExpectedChecksum with no matching entry expected error, got nil")
	}
}

// TestFetchExpectedChecksum_MissingAsset verifies an error is returned when the
// release has no checksums.txt asset at all.
func TestFetchExpectedChecksum_MissingAsset(t *testing.T) {
	release := &Release{Assets: []Asset{
		{Name: "caswhois-linux-amd64", BrowserDownloadURL: "http://127.0.0.1:1/bin"},
	}}

	_, err := fetchExpectedChecksum(release, "caswhois-linux-amd64")
	if err == nil {
		t.Error("fetchExpectedChecksum with missing checksums.txt asset expected error, got nil")
	}
}

// TestFetchExpectedChecksum_404 verifies fetchExpectedChecksum returns an error
// when the checksums.txt asset cannot be downloaded.
func TestFetchExpectedChecksum_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	release := &Release{Assets: []Asset{
		{Name: "checksums.txt", BrowserDownloadURL: srv.URL + "/checksums.txt"},
	}}

	_, err := fetchExpectedChecksum(release, "caswhois-linux-amd64")
	if err == nil {
		t.Error("fetchExpectedChecksum on 404 expected error, got nil")
	}
}

// TestFetchExpectedChecksum_BadURL verifies fetchExpectedChecksum returns an
// error for an unreachable checksums.txt URL.
func TestFetchExpectedChecksum_BadURL(t *testing.T) {
	release := &Release{Assets: []Asset{
		{Name: "checksums.txt", BrowserDownloadURL: "http://127.0.0.1:1/checksums.txt"},
	}}

	_, err := fetchExpectedChecksum(release, "caswhois-linux-amd64")
	if err == nil {
		t.Error("fetchExpectedChecksum with unreachable URL expected error, got nil")
	}
}

// --- replaceBinary tests (Unix-only) ----------------------------------------
// Covers: successful replacement, source does not exist, destination dir does
// not exist, permissions restored, backup removed after success.

// TestReplaceBinary_HappyPath verifies the binary is replaced with correct permissions.
func TestReplaceBinary_HappyPath(t *testing.T) {
	dir, err := os.MkdirTemp("", "caswhois-replace-binary-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	currentPath := filepath.Join(dir, "caswhois")
	newBinaryPath := filepath.Join(dir, "caswhois-new")

	// Write the "current" binary with a known permission
	if err := os.WriteFile(currentPath, []byte("old binary"), 0755); err != nil {
		t.Fatalf("WriteFile current: %v", err)
	}

	// Write the new binary to a separate temp file
	if err := os.WriteFile(newBinaryPath, []byte("new binary"), 0600); err != nil {
		t.Fatalf("WriteFile new: %v", err)
	}

	if err := replaceBinary(currentPath, newBinaryPath); err != nil {
		t.Fatalf("replaceBinary: %v", err)
	}

	// Current path must now hold the new content
	got, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatalf("ReadFile after replace: %v", err)
	}
	if string(got) != "new binary" {
		t.Errorf("content = %q, want %q", string(got), "new binary")
	}

	// Permissions must match the original binary (0755)
	info, err := os.Stat(currentPath)
	if err != nil {
		t.Fatalf("Stat after replace: %v", err)
	}
	if info.Mode().Perm() != 0755 {
		t.Errorf("mode = %v, want 0755", info.Mode().Perm())
	}

	// Backup must have been cleaned up
	if _, err := os.Stat(currentPath + ".old"); err == nil {
		t.Error("backup file still exists after successful replace")
	}
}

// TestReplaceBinary_CurrentPathMissing verifies an error when the current binary is absent.
func TestReplaceBinary_CurrentPathMissing(t *testing.T) {
	dir, err := os.MkdirTemp("", "caswhois-replace-missing-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	newBinaryPath := filepath.Join(dir, "caswhois-new")
	if err := os.WriteFile(newBinaryPath, []byte("new binary"), 0755); err != nil {
		t.Fatalf("WriteFile new: %v", err)
	}

	err = replaceBinary(filepath.Join(dir, "nonexistent"), newBinaryPath)
	if err == nil {
		t.Error("replaceBinary with missing current path expected error, got nil")
	}
}

// TestReplaceBinary_NewPathMissing verifies an error when the new binary does not exist.
func TestReplaceBinary_NewPathMissing(t *testing.T) {
	dir, err := os.MkdirTemp("", "caswhois-replace-newmissing-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	currentPath := filepath.Join(dir, "caswhois")
	if err := os.WriteFile(currentPath, []byte("old binary"), 0755); err != nil {
		t.Fatalf("WriteFile current: %v", err)
	}

	// The new binary path does not exist
	err = replaceBinary(currentPath, filepath.Join(dir, "nonexistent-new"))
	if err == nil {
		t.Error("replaceBinary with missing new binary expected error, got nil")
	}

	// After failure the original binary must still be at currentPath
	if _, statErr := os.Stat(currentPath); statErr != nil {
		t.Error("original binary missing after failed replace — backup not restored")
	}
}

// TestReplaceBinary_Idempotent verifies replacing twice leaves the last new binary in place.
func TestReplaceBinary_Idempotent(t *testing.T) {
	dir, err := os.MkdirTemp("", "caswhois-replace-idempotent-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	currentPath := filepath.Join(dir, "caswhois")
	if err := os.WriteFile(currentPath, []byte("v1"), 0755); err != nil {
		t.Fatalf("WriteFile v1: %v", err)
	}

	// First replacement: v1 → v2
	newV2 := filepath.Join(dir, "caswhois-v2")
	if err := os.WriteFile(newV2, []byte("v2"), 0755); err != nil {
		t.Fatalf("WriteFile v2: %v", err)
	}
	if err := replaceBinary(currentPath, newV2); err != nil {
		t.Fatalf("replaceBinary v1→v2: %v", err)
	}

	// Second replacement: v2 → v3
	newV3 := filepath.Join(dir, "caswhois-v3")
	if err := os.WriteFile(newV3, []byte("v3"), 0755); err != nil {
		t.Fatalf("WriteFile v3: %v", err)
	}
	if err := replaceBinary(currentPath, newV3); err != nil {
		t.Fatalf("replaceBinary v2→v3: %v", err)
	}

	got, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "v3" {
		t.Errorf("content = %q, want %q", string(got), "v3")
	}
}

// --- UpdateChannel constant values ------------------------------------------

func TestUpdateChannelConstants(t *testing.T) {
	cases := []struct {
		channel UpdateChannel
		want    string
	}{
		{ChannelStable, "stable"},
		{ChannelBeta, "beta"},
		{ChannelDaily, "daily"},
	}
	for _, tc := range cases {
		if string(tc.channel) != tc.want {
			t.Errorf("UpdateChannel %q = %q, want %q", tc.channel, string(tc.channel), tc.want)
		}
	}
}

// --- Release / Asset struct JSON round-trip ---------------------------------

func TestReleaseJSONRoundTrip(t *testing.T) {
	original := Release{
		TagName:     "v3.1.4",
		Name:        "Pi release",
		Prerelease:  true,
		PublishedAt: time.Date(2025, 3, 14, 0, 0, 0, 0, time.UTC),
		Assets: []Asset{
			{
				Name:               "caswhois-linux-amd64",
				BrowserDownloadURL: "https://example.com/download",
				Size:               2048,
			},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var got Release
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if got.TagName != original.TagName {
		t.Errorf("TagName = %q, want %q", got.TagName, original.TagName)
	}
	if got.Prerelease != original.Prerelease {
		t.Errorf("Prerelease = %v, want %v", got.Prerelease, original.Prerelease)
	}
	if len(got.Assets) != 1 {
		t.Fatalf("Assets count = %d, want 1", len(got.Assets))
	}
	if got.Assets[0].Name != original.Assets[0].Name {
		t.Errorf("Asset.Name = %q, want %q", got.Assets[0].Name, original.Assets[0].Name)
	}
	if got.Assets[0].Size != original.Assets[0].Size {
		t.Errorf("Asset.Size = %d, want %d", got.Assets[0].Size, original.Assets[0].Size)
	}
}

// --- CheckCLIUpdates tests (via /api/autodiscover) --------------------------
// Covers: update available, already up to date, server error, no platform binary.

func TestCheckCLIUpdates_NewerVersionAvailable(t *testing.T) {
	platformKey := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/autodiscover" {
			http.NotFound(w, r)
			return
		}
		resp := AutodiscoverResponse{
			APIVersion: "v1",
			BaseURL:    "http://" + r.Host,
			CLIVersions: map[string]CLIBinaryInfo{
				platformKey: {Version: "v2.0.0", SHA256: strings.Repeat("a", 64)},
			},
			CLIMinVersion: "v1.0.0",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	info, err := CheckCLIUpdates(srv.URL, "v1.0.0")
	if err != nil {
		t.Fatalf("CheckCLIUpdates: %v", err)
	}
	if !info.Available {
		t.Error("Available = false, want true")
	}
	if info.LatestVersion != "v2.0.0" {
		t.Errorf("LatestVersion = %q, want %q", info.LatestVersion, "v2.0.0")
	}
	if info.Checksum != strings.Repeat("a", 64) {
		t.Errorf("Checksum = %q, want %q", info.Checksum, strings.Repeat("a", 64))
	}
}

func TestCheckCLIUpdates_AlreadyUpToDate(t *testing.T) {
	platformKey := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := AutodiscoverResponse{
			APIVersion: "v1",
			BaseURL:    "http://" + r.Host,
			CLIVersions: map[string]CLIBinaryInfo{
				platformKey: {Version: "v1.0.0", SHA256: strings.Repeat("b", 64)},
			},
			CLIMinVersion: "v1.0.0",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	info, err := CheckCLIUpdates(srv.URL, "v1.0.0")
	if err != nil {
		t.Fatalf("CheckCLIUpdates: %v", err)
	}
	if info.Available {
		t.Error("Available = true, want false when already up to date")
	}
}

func TestCheckCLIUpdates_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := CheckCLIUpdates(srv.URL, "v1.0.0")
	if err == nil {
		t.Error("CheckCLIUpdates with server error expected error, got nil")
	}
}

func TestCheckCLIUpdates_NoPlatformBinary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := AutodiscoverResponse{
			APIVersion: "v1",
			BaseURL:    "http://" + r.Host,
			CLIVersions: map[string]CLIBinaryInfo{
				"plan9-mips64": {Version: "v2.0.0", SHA256: "abc"},
			},
			CLIMinVersion: "v1.0.0",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	_, err := CheckCLIUpdates(srv.URL, "v1.0.0")
	if err == nil {
		t.Error("CheckCLIUpdates with no platform binary expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no CLI binary available") {
		t.Errorf("error = %q, want 'no CLI binary available' message", err.Error())
	}
}

func TestCheckCLIUpdates_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "not valid json {{{")
	}))
	defer srv.Close()

	_, err := CheckCLIUpdates(srv.URL, "v1.0.0")
	if err == nil {
		t.Error("CheckCLIUpdates with invalid JSON expected error, got nil")
	}
}

// --- PerformCLIUpdate tests --------------------------------------------------

func TestPerformCLIUpdate_AlreadyUpToDate(t *testing.T) {
	platformKey := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := AutodiscoverResponse{
			APIVersion: "v1",
			BaseURL:    "http://" + r.Host,
			CLIVersions: map[string]CLIBinaryInfo{
				platformKey: {Version: "v1.0.0", SHA256: strings.Repeat("c", 64)},
			},
			CLIMinVersion: "v1.0.0",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	err := PerformCLIUpdate(srv.URL, "v1.0.0")
	if err == nil {
		t.Error("PerformCLIUpdate when already up to date expected error, got nil")
	}
	if !strings.Contains(err.Error(), "already on latest version") {
		t.Errorf("error = %q, want 'already on latest version' message", err.Error())
	}
}

func TestPerformCLIUpdate_CheckError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := PerformCLIUpdate(srv.URL, "v1.0.0")
	if err == nil {
		t.Error("PerformCLIUpdate with server error expected error, got nil")
	}
}

// --- AutodiscoverResponse / CLIBinaryInfo JSON round-trip --------------------

func TestAutodiscoverResponse_JSONRoundTrip(t *testing.T) {
	original := AutodiscoverResponse{
		APIVersion: "v1",
		BaseURL:    "https://example.com",
		CLIVersions: map[string]CLIBinaryInfo{
			"linux-amd64":  {Version: "v1.2.3", SHA256: strings.Repeat("a", 64)},
			"darwin-arm64": {Version: "v1.2.3", SHA256: strings.Repeat("b", 64)},
		},
		CLIMinVersion: "v1.0.0",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var got AutodiscoverResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if got.APIVersion != original.APIVersion {
		t.Errorf("APIVersion = %q, want %q", got.APIVersion, original.APIVersion)
	}
	if got.BaseURL != original.BaseURL {
		t.Errorf("BaseURL = %q, want %q", got.BaseURL, original.BaseURL)
	}
	if len(got.CLIVersions) != 2 {
		t.Errorf("CLIVersions count = %d, want 2", len(got.CLIVersions))
	}
	if got.CLIMinVersion != original.CLIMinVersion {
		t.Errorf("CLIMinVersion = %q, want %q", got.CLIMinVersion, original.CLIMinVersion)
	}
}

// --- UpdateInfo fields -------------------------------------------------------

func TestUpdateInfo_FieldsSetCorrectly(t *testing.T) {
	info := UpdateInfo{
		Available:      true,
		CurrentVersion: "v1.0.0",
		LatestVersion:  "v2.0.0",
		ReleaseNotes:   "Big release",
		DownloadURL:    "https://example.com/caswhois",
		Checksum:       strings.Repeat("a", 64),
	}

	if !info.Available {
		t.Error("Available should be true")
	}
	if info.CurrentVersion != "v1.0.0" {
		t.Errorf("CurrentVersion = %q", info.CurrentVersion)
	}
	if info.LatestVersion != "v2.0.0" {
		t.Errorf("LatestVersion = %q", info.LatestVersion)
	}
	if len(info.Checksum) != 64 {
		t.Errorf("Checksum length = %d, want 64", len(info.Checksum))
	}
}
