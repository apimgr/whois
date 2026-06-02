package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// sqliteHeader returns a minimal valid SQLite file (100+ bytes with correct magic).
func sqliteHeader() []byte {
	header := []byte("SQLite format 3\x00")
	header = append(header, make([]byte, 100)...)
	return header
}

// makeFixtures creates server.yml and server.db inside configDir/dataDir and
// returns their paths.
func makeFixtures(t *testing.T, configDir, dataDir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(configDir, "server.yml"), []byte("port: 64001\n"), 0600); err != nil {
		t.Fatalf("write server.yml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "server.db"), sqliteHeader(), 0600); err != nil {
		t.Fatalf("write server.db: %v", err)
	}
}

// buildTarGz returns raw bytes of a tar.gz archive containing the given files
// (name -> content).
func buildTarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	for name, data := range files {
		hdr := &tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("tar write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

// ---- Create tests ----

func TestCreate_PlainNoPassword(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}
	makeFixtures(t, configDir, dataDir)

	outFile := filepath.Join(dir, "test.tar.gz")
	opts := &BackupOptions{
		ConfigDir:  configDir,
		DataDir:    dataDir,
		OutputFile: outFile,
		AdminUser:  "testuser",
		AppVersion: "1.0.0",
	}

	if err := Create(opts); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	info, err := os.Stat(outFile)
	if err != nil {
		t.Fatalf("output file missing: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("output file is empty")
	}
}

func TestCreate_WithPassword(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}
	makeFixtures(t, configDir, dataDir)

	outFile := filepath.Join(dir, "test.tar.gz.enc")
	opts := &BackupOptions{
		ConfigDir:  configDir,
		DataDir:    dataDir,
		OutputFile: outFile,
		Password:   "s3cr3t",
		AdminUser:  "testuser",
		AppVersion: "1.0.0",
	}

	if err := Create(opts); err != nil {
		t.Fatalf("Create() with password error: %v", err)
	}

	info, err := os.Stat(outFile)
	if err != nil {
		t.Fatalf("output file missing: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("output file is empty")
	}
}

func TestCreate_AutoFilename_Plain(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}
	makeFixtures(t, configDir, dataDir)

	// Change to the temp dir so the auto-named file lands there.
	origWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	opts := &BackupOptions{
		ConfigDir:  configDir,
		DataDir:    dataDir,
		AdminUser:  "auto",
		AppVersion: "1.0.0",
	}

	if err := Create(opts); err != nil {
		t.Fatalf("Create() auto-filename error: %v", err)
	}
	// OutputFile should have been set by Create.
	if opts.OutputFile == "" {
		t.Fatal("OutputFile not set after auto-name generation")
	}
	if _, err := os.Stat(opts.OutputFile); err != nil {
		t.Fatalf("auto-named file not found: %v", err)
	}
}

func TestCreate_AutoFilename_Encrypted(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}
	makeFixtures(t, configDir, dataDir)

	origWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	opts := &BackupOptions{
		ConfigDir:  configDir,
		DataDir:    dataDir,
		Password:   "autopass",
		AdminUser:  "auto",
		AppVersion: "1.0.0",
	}

	if err := Create(opts); err != nil {
		t.Fatalf("Create() encrypted auto-filename error: %v", err)
	}
	if opts.OutputFile == "" {
		t.Fatal("OutputFile not set")
	}
	// Encrypted auto-filename must end with .tar.gz.enc
	if filepath.Ext(opts.OutputFile) != ".enc" {
		t.Fatalf("expected .enc extension, got: %s", opts.OutputFile)
	}
}

func TestCreate_MissingConfigDir(t *testing.T) {
	dir := t.TempDir()
	opts := &BackupOptions{
		ConfigDir:  filepath.Join(dir, "no-such-config"),
		DataDir:    filepath.Join(dir, "no-such-data"),
		OutputFile: filepath.Join(dir, "out.tar.gz"),
	}
	if err := Create(opts); err == nil {
		t.Fatal("expected error for missing config dir")
	}
}

func TestCreate_WithTemplatesAndSSL(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}
	makeFixtures(t, configDir, dataDir)

	// Create optional directories that get included.
	for _, sub := range []string{"template", "theme", "ssl"} {
		if err := os.MkdirAll(filepath.Join(configDir, sub), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(configDir, sub, "file.txt"), []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	outFile := filepath.Join(dir, "full.tar.gz")
	opts := &BackupOptions{
		ConfigDir:  configDir,
		DataDir:    dataDir,
		OutputFile: outFile,
		IncludeSSL: true,
	}

	if err := Create(opts); err != nil {
		t.Fatalf("Create() with extras error: %v", err)
	}
	if info, err := os.Stat(outFile); err != nil || info.Size() == 0 {
		t.Fatal("output file missing or empty")
	}
}

func TestCreate_WithDataDir(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}
	makeFixtures(t, configDir, dataDir)
	if err := os.WriteFile(filepath.Join(dataDir, "extra.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	outFile := filepath.Join(dir, "with-data.tar.gz")
	opts := &BackupOptions{
		ConfigDir:   configDir,
		DataDir:     dataDir,
		OutputFile:  outFile,
		IncludeData: true,
	}

	if err := Create(opts); err != nil {
		t.Fatalf("Create() with IncludeData error: %v", err)
	}
	if info, err := os.Stat(outFile); err != nil || info.Size() == 0 {
		t.Fatal("output file missing or empty")
	}
}

// ---- VerifyBackup tests ----

func makePlainBackup(t *testing.T) (configDir, dataDir, outFile string) {
	t.Helper()
	dir := t.TempDir()
	configDir = filepath.Join(dir, "config")
	dataDir = filepath.Join(dir, "data")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}
	makeFixtures(t, configDir, dataDir)

	outFile = filepath.Join(dir, "plain.tar.gz")
	opts := &BackupOptions{
		ConfigDir:  configDir,
		DataDir:    dataDir,
		OutputFile: outFile,
		AdminUser:  "tester",
		AppVersion: "1.0.0",
	}
	if err := Create(opts); err != nil {
		t.Fatalf("setup Create: %v", err)
	}
	return
}

func makeEncryptedBackup(t *testing.T, password string) (outFile string) {
	t.Helper()
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}
	makeFixtures(t, configDir, dataDir)

	outFile = filepath.Join(dir, "enc.tar.gz.enc")
	opts := &BackupOptions{
		ConfigDir:  configDir,
		DataDir:    dataDir,
		OutputFile: outFile,
		Password:   password,
		AdminUser:  "tester",
		AppVersion: "1.0.0",
	}
	if err := Create(opts); err != nil {
		t.Fatalf("setup Create (encrypted): %v", err)
	}
	return
}

func TestVerifyBackup_PlainSuccess(t *testing.T) {
	_, _, outFile := makePlainBackup(t)
	if err := VerifyBackup(outFile, ""); err != nil {
		t.Fatalf("VerifyBackup plain: %v", err)
	}
}

func TestVerifyBackup_EncryptedSuccess(t *testing.T) {
	outFile := makeEncryptedBackup(t, "correct-password")
	if err := VerifyBackup(outFile, "correct-password"); err != nil {
		t.Fatalf("VerifyBackup encrypted: %v", err)
	}
}

func TestVerifyBackup_WrongPassword(t *testing.T) {
	outFile := makeEncryptedBackup(t, "correct-password")
	err := VerifyBackup(outFile, "wrong-password")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestVerifyBackup_EncryptedNoPassword(t *testing.T) {
	outFile := makeEncryptedBackup(t, "somepass")
	err := VerifyBackup(outFile, "")
	if err == nil {
		t.Fatal("expected error when no password given for encrypted backup")
	}
}

func TestVerifyBackup_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	emptyFile := filepath.Join(dir, "empty.tar.gz")
	if err := os.WriteFile(emptyFile, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	err := VerifyBackup(emptyFile, "")
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestVerifyBackup_MissingFile(t *testing.T) {
	err := VerifyBackup("/no/such/backup.tar.gz", "")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestVerifyBackup_CorruptData(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.tar.gz")
	if err := os.WriteFile(corrupt, []byte("this is not a gzip file at all"), 0600); err != nil {
		t.Fatal(err)
	}
	err := VerifyBackup(corrupt, "")
	if err == nil {
		t.Fatal("expected error for corrupt data")
	}
}

// ---- ApplyRetentionPolicy tests ----

// retentionFilename returns a filename whose base[17:27] parses as the given date.
// The code uses base[17:27], so prefix must be exactly 17 chars.
// "caswhois_backup_" is 16 chars; adding an extra '_' makes 17.
func retentionFilename(date time.Time, suffix string) string {
	// caswhois_backup__YYYY-MM-DD_HHMMSS.tar.gz
	// positions:       0123456789...
	// index 17 = first char of YYYY
	return "caswhois_backup__" + date.Format("2006-01-02") + "_120000" + suffix
}

func TestApplyRetentionPolicy_NoFiles(t *testing.T) {
	dir := t.TempDir()
	if err := ApplyRetentionPolicy(dir, 7, 4, 3, 2); err != nil {
		t.Fatalf("ApplyRetentionPolicy on empty dir: %v", err)
	}
}

func TestApplyRetentionPolicy_KeepsAll_WhenWithinLimit(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	// Create 3 backup files, limit = 7 — all should be kept.
	for i := 0; i < 3; i++ {
		date := now.AddDate(0, 0, -i)
		name := retentionFilename(date, ".tar.gz")
		if err := os.WriteFile(filepath.Join(dir, name), []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	if err := ApplyRetentionPolicy(dir, 7, 4, 3, 2); err != nil {
		t.Fatalf("ApplyRetentionPolicy: %v", err)
	}

	remaining, _ := filepath.Glob(filepath.Join(dir, "caswhois_backup_*.tar.gz*"))
	if len(remaining) != 3 {
		t.Fatalf("expected 3 files kept, got %d", len(remaining))
	}
}

func TestApplyRetentionPolicy_DeletesOldBackups(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	// Create 10 daily backups; limit = 3 — 7 should be deleted.
	for i := 0; i < 10; i++ {
		date := now.AddDate(0, 0, -i)
		// Avoid Sunday / 1st-of-month so retention rules don't interfere.
		// Force all to be a Tuesday-ish mid-month day by adjusting.
		_ = date
		// Use fixed past Tuesdays in the middle of the month.
		fixedDate := time.Date(2025, time.March, 11-i, 0, 0, 0, 0, time.UTC)
		if fixedDate.Weekday() == time.Sunday {
			fixedDate = fixedDate.AddDate(0, 0, -1)
		}
		name := retentionFilename(fixedDate, ".tar.gz")
		if err := os.WriteFile(filepath.Join(dir, name), []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	if err := ApplyRetentionPolicy(dir, 3, 0, 0, 0); err != nil {
		t.Fatalf("ApplyRetentionPolicy: %v", err)
	}

	remaining, _ := filepath.Glob(filepath.Join(dir, "caswhois_backup_*.tar.gz*"))
	if len(remaining) > 3 {
		t.Fatalf("expected at most 3 files, got %d", len(remaining))
	}
}

func TestApplyRetentionPolicy_SkipsIncrementals(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2025, time.March, 5, 0, 0, 0, 0, time.UTC)

	// Full backup (should be subject to retention).
	fullName := retentionFilename(now, ".tar.gz")
	if err := os.WriteFile(filepath.Join(dir, fullName), []byte("full"), 0600); err != nil {
		t.Fatal(err)
	}

	// Incremental backups (should be skipped by retention).
	for _, inc := range []string{
		"caswhois_backup_2025-03-05-daily.tar.gz",
		"caswhois_backup_2025-03-05-hourly.tar.gz",
	} {
		if err := os.WriteFile(filepath.Join(dir, inc), []byte("inc"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	if err := ApplyRetentionPolicy(dir, 1, 0, 0, 0); err != nil {
		t.Fatalf("ApplyRetentionPolicy: %v", err)
	}

	// Incrementals must still exist.
	for _, inc := range []string{
		"caswhois_backup_2025-03-05-daily.tar.gz",
		"caswhois_backup_2025-03-05-hourly.tar.gz",
	} {
		if _, err := os.Stat(filepath.Join(dir, inc)); err != nil {
			t.Fatalf("incremental %s was unexpectedly deleted: %v", inc, err)
		}
	}
}

func TestApplyRetentionPolicy_EncryptedFilesHandled(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2025, time.April, 10, 0, 0, 0, 0, time.UTC)

	// Create .tar.gz.enc backup (glob includes *.tar.gz* so it matches).
	name := retentionFilename(now, ".tar.gz.enc")
	if err := os.WriteFile(filepath.Join(dir, name), []byte("enc"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := ApplyRetentionPolicy(dir, 1, 0, 0, 0); err != nil {
		t.Fatalf("ApplyRetentionPolicy with .enc file: %v", err)
	}
}

// ---- CreateIncremental tests ----

func TestCreateIncremental_Daily(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}
	makeFixtures(t, configDir, dataDir)

	origWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	opts := &BackupOptions{
		ConfigDir:  configDir,
		DataDir:    dataDir,
		AppVersion: "1.0.0",
	}

	if err := CreateIncremental(opts, "daily"); err != nil {
		t.Fatalf("CreateIncremental daily: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "caswhois-daily.tar.gz")); err != nil {
		t.Fatalf("daily backup file missing: %v", err)
	}
}

func TestCreateIncremental_Hourly(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}
	makeFixtures(t, configDir, dataDir)

	origWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	opts := &BackupOptions{
		ConfigDir:  configDir,
		DataDir:    dataDir,
		AppVersion: "1.0.0",
	}

	if err := CreateIncremental(opts, "hourly"); err != nil {
		t.Fatalf("CreateIncremental hourly: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "caswhois-hourly.tar.gz")); err != nil {
		t.Fatalf("hourly backup file missing: %v", err)
	}
}

func TestCreateIncremental_Encrypted(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}
	makeFixtures(t, configDir, dataDir)

	origWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	opts := &BackupOptions{
		ConfigDir:  configDir,
		DataDir:    dataDir,
		Password:   "incpass",
		AppVersion: "1.0.0",
	}

	if err := CreateIncremental(opts, "daily"); err != nil {
		t.Fatalf("CreateIncremental encrypted daily: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "caswhois-daily.tar.gz.enc")); err != nil {
		t.Fatalf("encrypted daily backup file missing: %v", err)
	}
}

// ---- contains / hasSubstring helper tests ----

func TestContains(t *testing.T) {
	tests := []struct {
		s, sub string
		want   bool
	}{
		{"hello world", "world", true},
		{"hello world", "hello", true},
		{"hello world", "lo wo", true},
		{"hello world", "xyz", false},
		{"hello world", "hello world extra", false},
		{"", "x", false},
		{"x", "x", true},
		{"abc", "", true},
		{"", "", true},
	}

	for _, tc := range tests {
		got := contains(tc.s, tc.sub)
		if got != tc.want {
			t.Errorf("contains(%q, %q) = %v, want %v", tc.s, tc.sub, got, tc.want)
		}
	}
}

func TestHasSubstring(t *testing.T) {
	tests := []struct {
		s, sub string
		want   bool
	}{
		{"foobar", "oba", true},
		{"foobar", "baz", false},
		{"foobar", "foobar", true},
		{"foobar", "foobarz", false},
		{"a", "a", true},
	}

	for _, tc := range tests {
		got := hasSubstring(tc.s, tc.sub)
		if got != tc.want {
			t.Errorf("hasSubstring(%q, %q) = %v, want %v", tc.s, tc.sub, got, tc.want)
		}
	}
}

// ---- fileExists / dirExists tests ----

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(existing, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	if !fileExists(existing) {
		t.Error("expected true for existing file")
	}
	if fileExists(filepath.Join(dir, "ghost.txt")) {
		t.Error("expected false for non-existent file")
	}
	// A directory must not count as a file.
	if fileExists(dir) {
		t.Error("expected false for directory path")
	}
}

func TestDirExists(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "subdir")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}

	if !dirExists(sub) {
		t.Error("expected true for existing directory")
	}
	if dirExists(filepath.Join(dir, "nosuchdir")) {
		t.Error("expected false for non-existent directory")
	}
	// A regular file must not count as a directory.
	f := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if dirExists(f) {
		t.Error("expected false for regular file path")
	}
}

// ---- extractTarGz tests ----

func TestExtractTarGz_Success(t *testing.T) {
	files := map[string][]byte{
		"manifest.json": []byte(`{"version":"1.0.0"}`),
		"server.yml":    []byte("port: 64001\n"),
	}
	data := buildTarGz(t, files)
	dest := t.TempDir()

	if err := extractTarGz(data, dest); err != nil {
		t.Fatalf("extractTarGz: %v", err)
	}

	for name, content := range files {
		got, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil {
			t.Fatalf("read extracted %s: %v", name, err)
		}
		if !bytes.Equal(got, content) {
			t.Errorf("extracted %s content mismatch", name)
		}
	}
}

func TestExtractTarGz_PathTraversalRejected(t *testing.T) {
	// Build an archive with a path-traversal entry.
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	evil := "../../../etc/evil"
	hdr := &tar.Header{Name: evil, Mode: 0600, Size: 4}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("evil")); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gzw.Close()

	dest := t.TempDir()
	err := extractTarGz(buf.Bytes(), dest)
	if err == nil {
		t.Fatal("expected error for path traversal attempt")
	}
}

func TestExtractTarGz_InvalidGzip(t *testing.T) {
	dest := t.TempDir()
	err := extractTarGz([]byte("not gzip data"), dest)
	if err == nil {
		t.Fatal("expected error for invalid gzip")
	}
}

func TestExtractTarGz_DirectoryEntry(t *testing.T) {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	// Directory entry
	hdr := &tar.Header{
		Typeflag: tar.TypeDir,
		Name:     "subdir/",
		Mode:     0755,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}

	// File inside directory
	content := []byte("nested content")
	hdr2 := &tar.Header{
		Name: "subdir/file.txt",
		Mode: 0600,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr2); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}

	_ = tw.Close()
	_ = gzw.Close()

	dest := t.TempDir()
	if err := extractTarGz(buf.Bytes(), dest); err != nil {
		t.Fatalf("extractTarGz with directory entry: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "subdir", "file.txt"))
	if err != nil {
		t.Fatalf("read nested file: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Error("nested file content mismatch")
	}
}

// ---- decryptBackupData tests ----

func TestDecryptBackupData_TooShort(t *testing.T) {
	_, err := decryptBackupData([]byte("short"), "pass")
	if err == nil {
		t.Fatal("expected error for too-short input")
	}
}

func TestDecryptBackupData_WrongPassword(t *testing.T) {
	// Encrypt with one password, decrypt with another.
	plain := []byte("hello backup")
	encrypted, err := encryptBackup(plain, "correct")
	if err != nil {
		t.Fatalf("encryptBackup: %v", err)
	}

	_, err = decryptBackupData(encrypted, "wrong")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestDecryptBackupData_RoundTrip(t *testing.T) {
	plain := []byte("round-trip test data 12345")
	encrypted, err := encryptBackup(plain, "testpass")
	if err != nil {
		t.Fatalf("encryptBackup: %v", err)
	}

	decrypted, err := decryptBackupData(encrypted, "testpass")
	if err != nil {
		t.Fatalf("decryptBackupData: %v", err)
	}

	if !bytes.Equal(decrypted, plain) {
		t.Errorf("round-trip mismatch: got %q, want %q", decrypted, plain)
	}
}

func TestDecryptBackupData_TruncatedCiphertext(t *testing.T) {
	// 32 bytes of salt + fewer bytes than nonceSize (12) → should fail.
	tooShort := make([]byte, 32+8)
	_, err := decryptBackupData(tooShort, "pass")
	if err == nil {
		t.Fatal("expected error for truncated ciphertext")
	}
}

// ---- Restore tests ----

func TestRestore_PlainBackup(t *testing.T) {
	_, _, backupFile := makePlainBackup(t)

	restoreDir := t.TempDir()
	configOut := filepath.Join(restoreDir, "config")
	dataOut := filepath.Join(restoreDir, "data")

	opts := &RestoreOptions{
		BackupFile: backupFile,
		ConfigDir:  configOut,
		DataDir:    dataOut,
		Force:      true,
	}

	if err := Restore(opts); err != nil {
		t.Fatalf("Restore plain: %v", err)
	}

	if _, err := os.Stat(filepath.Join(configOut, "server.yml")); err != nil {
		t.Error("server.yml not restored")
	}
	if _, err := os.Stat(filepath.Join(dataOut, "server.db")); err != nil {
		t.Error("server.db not restored")
	}
}

func TestRestore_EncryptedBackup(t *testing.T) {
	backupFile := makeEncryptedBackup(t, "mypassword")

	restoreDir := t.TempDir()
	configOut := filepath.Join(restoreDir, "config")
	dataOut := filepath.Join(restoreDir, "data")

	opts := &RestoreOptions{
		BackupFile: backupFile,
		Password:   "mypassword",
		ConfigDir:  configOut,
		DataDir:    dataOut,
		Force:      true,
	}

	if err := Restore(opts); err != nil {
		t.Fatalf("Restore encrypted: %v", err)
	}

	if _, err := os.Stat(filepath.Join(configOut, "server.yml")); err != nil {
		t.Error("server.yml not restored after encrypted restore")
	}
}

func TestRestore_MissingFile(t *testing.T) {
	opts := &RestoreOptions{
		BackupFile: "/no/such/backup.tar.gz",
		ConfigDir:  t.TempDir(),
		DataDir:    t.TempDir(),
	}
	if err := Restore(opts); err == nil {
		t.Fatal("expected error for missing backup file")
	}
}

func TestRestore_EncryptedNoPassword(t *testing.T) {
	backupFile := makeEncryptedBackup(t, "somepass")

	opts := &RestoreOptions{
		BackupFile: backupFile,
		ConfigDir:  t.TempDir(),
		DataDir:    t.TempDir(),
	}
	if err := Restore(opts); err == nil {
		t.Fatal("expected error when password missing for encrypted backup")
	}
}

func TestRestore_EncryptedWrongPassword(t *testing.T) {
	backupFile := makeEncryptedBackup(t, "correct")

	opts := &RestoreOptions{
		BackupFile: backupFile,
		Password:   "wrong",
		ConfigDir:  t.TempDir(),
		DataDir:    t.TempDir(),
	}
	if err := Restore(opts); err == nil {
		t.Fatal("expected error for wrong decryption password")
	}
}

// ---- Manifest helper tests ----

func TestLoadManifest_Valid(t *testing.T) {
	dir := t.TempDir()
	content := []byte(`{
		"version": "1.0.0",
		"created_at": "2025-01-15T12:00:00Z",
		"encrypted": false,
		"contents": ["server.yml", "server.db"],
		"checksum": "sha256:abc123"
	}`)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), content, 0600); err != nil {
		t.Fatal(err)
	}

	m, err := loadManifest(dir)
	if err != nil {
		t.Fatalf("loadManifest: %v", err)
	}
	if m.Version != "1.0.0" {
		t.Errorf("version mismatch: %s", m.Version)
	}
	if m.Checksum != "sha256:abc123" {
		t.Errorf("checksum mismatch: %s", m.Checksum)
	}
}

func TestLoadManifest_Missing(t *testing.T) {
	_, err := loadManifest(t.TempDir())
	if err == nil {
		t.Fatal("expected error for missing manifest.json")
	}
}

func TestLoadManifest_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{not json}"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := loadManifest(dir)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
