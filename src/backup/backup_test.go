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
	if err := ApplyRetentionPolicy(dir, 7, 4, 3, 2, ""); err != nil {
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

	if err := ApplyRetentionPolicy(dir, 7, 4, 3, 2, ""); err != nil {
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

	if err := ApplyRetentionPolicy(dir, 3, 0, 0, 0, ""); err != nil {
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

	if err := ApplyRetentionPolicy(dir, 1, 0, 0, 0, ""); err != nil {
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

	if err := ApplyRetentionPolicy(dir, 1, 0, 0, 0, ""); err != nil {
		t.Fatalf("ApplyRetentionPolicy with .enc file: %v", err)
	}
}

// TestApplyRetentionPolicy_ShortFilenameSkipped verifies that filenames shorter
// than 28 characters are skipped rather than causing a slice-bounds panic.
func TestApplyRetentionPolicy_ShortFilenameSkipped(t *testing.T) {
	dir := t.TempDir()
	// A filename that matches the glob (*.tar.gz) but is too short for date parsing.
	if err := os.WriteFile(filepath.Join(dir, "short.tar.gz"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	// Must complete without error or panic.
	if err := ApplyRetentionPolicy(dir, 7, 4, 3, 2, ""); err != nil {
		t.Fatalf("ApplyRetentionPolicy with short filename: %v", err)
	}
}

// TestApplyRetentionPolicy_YearlyRetention verifies that a January-1st backup
// is kept when the yearly limit has not been reached.
func TestApplyRetentionPolicy_YearlyRetention(t *testing.T) {
	dir := t.TempDir()

	// Create one Jan-1 backup (qualifies for yearly keep) and several daily backups.
	jan1 := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	jan1File := retentionFilename(jan1, ".tar.gz")
	if err := os.WriteFile(filepath.Join(dir, jan1File), []byte("yearly"), 0600); err != nil {
		t.Fatal(err)
	}

	// Create more regular backups than the keep limit so the policy has to decide.
	for i := 1; i <= 10; i++ {
		date := time.Date(2025, time.March, i, 0, 0, 0, 0, time.UTC)
		name := retentionFilename(date, ".tar.gz")
		if err := os.WriteFile(filepath.Join(dir, name), []byte("daily"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// keepYearly=1 keeps the Jan 1 backup; keepMonthly=0, keepWeekly=0, keepDaily=2.
	if err := ApplyRetentionPolicy(dir, 2, 0, 0, 1, ""); err != nil {
		t.Fatalf("ApplyRetentionPolicy yearly: %v", err)
	}

	// The January 1 backup must still exist.
	if _, err := os.Stat(filepath.Join(dir, jan1File)); err != nil {
		t.Errorf("Jan-1 yearly backup was deleted: %v", err)
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

// ---- copyDir tests ----

// TestCopyDir_BasicCopy verifies that copyDir duplicates all files and
// subdirectories from source to destination.
func TestCopyDir_BasicCopy(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	// Create nested structure in src.
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "root.txt"), []byte("root"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "nested.txt"), []byte("nested"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := copyDir(src, dst); err != nil {
		t.Fatalf("copyDir: %v", err)
	}

	// Verify all files were copied.
	rootData, err := os.ReadFile(filepath.Join(dst, "root.txt"))
	if err != nil {
		t.Fatalf("root.txt missing: %v", err)
	}
	if string(rootData) != "root" {
		t.Errorf("root.txt content = %q, want \"root\"", rootData)
	}

	nestedData, err := os.ReadFile(filepath.Join(dst, "sub", "nested.txt"))
	if err != nil {
		t.Fatalf("sub/nested.txt missing: %v", err)
	}
	if string(nestedData) != "nested" {
		t.Errorf("sub/nested.txt content = %q, want \"nested\"", nestedData)
	}
}

// TestCopyDir_EmptyDirectory verifies copyDir handles an empty source gracefully.
func TestCopyDir_EmptyDirectory(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	if err := copyDir(src, dst); err != nil {
		t.Fatalf("copyDir on empty dir: %v", err)
	}
}

// TestCopyDir_MissingSource verifies copyDir returns an error for a non-existent source.
func TestCopyDir_MissingSource(t *testing.T) {
	err := copyDir("/no/such/source/dir", t.TempDir())
	if err == nil {
		t.Fatal("copyDir with missing source expected error, got nil")
	}
}

// ---- copyFile tests ----

// TestCopyFile_BasicCopy verifies file content and mode are preserved.
func TestCopyFile_BasicCopy(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")

	if err := os.WriteFile(src, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("copyFile content = %q, want \"hello\"", got)
	}
}

// TestCopyFile_CreatesParentDir verifies copyFile creates missing parent directories.
func TestCopyFile_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "deep", "nested", "dst.txt")

	if err := os.WriteFile(src, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile into deep path: %v", err)
	}

	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("dst file missing: %v", err)
	}
}

// TestCopyFile_MissingSource verifies copyFile returns an error for a missing source.
func TestCopyFile_MissingSource(t *testing.T) {
	err := copyFile("/no/such/file.txt", filepath.Join(t.TempDir(), "dst.txt"))
	if err == nil {
		t.Fatal("copyFile with missing source expected error, got nil")
	}
}

// ---- Restore with optional directories tests ----

// TestRestore_WithTemplatesAndThemes verifies that a backup containing template
// and theme directories is fully restored.
func TestRestore_WithTemplatesAndThemes(t *testing.T) {
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

	// Add template and theme directories.
	for _, sub := range []string{"template", "theme"} {
		subDir := filepath.Join(configDir, sub)
		if err := os.MkdirAll(subDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("content"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	outFile := filepath.Join(dir, "backup.tar.gz")
	if err := Create(&BackupOptions{
		ConfigDir:  configDir,
		DataDir:    dataDir,
		OutputFile: outFile,
		AdminUser:  "test",
		AppVersion: "1.0.0",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	restoreDir := t.TempDir()
	configOut := filepath.Join(restoreDir, "config")
	dataOut := filepath.Join(restoreDir, "data")

	if err := Restore(&RestoreOptions{
		BackupFile: outFile,
		ConfigDir:  configOut,
		DataDir:    dataOut,
		Force:      true,
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Verify template and theme directories were restored.
	for _, sub := range []string{"template", "theme"} {
		path := filepath.Join(configOut, sub, "file.txt")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s/file.txt not restored: %v", sub, err)
		}
	}
}

// TestRestore_WithSSLAndData verifies restore of SSL and data directories.
func TestRestore_WithSSLAndData(t *testing.T) {
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

	// Add ssl and extra data file.
	sslDir := filepath.Join(configDir, "ssl")
	if err := os.MkdirAll(sslDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sslDir, "cert.pem"), []byte("CERT"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "extra.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	outFile := filepath.Join(dir, "backup.tar.gz")
	if err := Create(&BackupOptions{
		ConfigDir:   configDir,
		DataDir:     dataDir,
		OutputFile:  outFile,
		IncludeSSL:  true,
		IncludeData: true,
		AdminUser:   "test",
		AppVersion:  "1.0.0",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	restoreDir := t.TempDir()
	configOut := filepath.Join(restoreDir, "config")
	dataOut := filepath.Join(restoreDir, "data")

	if err := Restore(&RestoreOptions{
		BackupFile: outFile,
		ConfigDir:  configOut,
		DataDir:    dataOut,
		Force:      true,
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// SSL cert should be restored.
	if _, err := os.Stat(filepath.Join(configOut, "ssl", "cert.pem")); err != nil {
		t.Errorf("ssl/cert.pem not restored: %v", err)
	}
}

// TestRestore_UsersDB verifies that users.db is restored when present in the backup.
func TestRestore_UsersDB(t *testing.T) {
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

	// Also create users.db with a valid SQLite header.
	if err := os.WriteFile(filepath.Join(dataDir, "users.db"), sqliteHeader(), 0600); err != nil {
		t.Fatal(err)
	}

	outFile := filepath.Join(dir, "backup.tar.gz")
	if err := Create(&BackupOptions{
		ConfigDir:  configDir,
		DataDir:    dataDir,
		OutputFile: outFile,
		AdminUser:  "test",
		AppVersion: "1.0.0",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	restoreDir := t.TempDir()
	configOut := filepath.Join(restoreDir, "config")
	dataOut := filepath.Join(restoreDir, "data")

	if err := Restore(&RestoreOptions{
		BackupFile: outFile,
		ConfigDir:  configOut,
		DataDir:    dataOut,
		Force:      true,
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dataOut, "users.db")); err != nil {
		t.Errorf("users.db not restored: %v", err)
	}
}

// TestAddFileToTar verifies that addFileToTar writes both header and content
// to the tar writer correctly.
func TestAddFileToTar(t *testing.T) {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	data := []byte("test file content")
	if err := addFileToTar(tw, "test.txt", data); err != nil {
		t.Fatalf("addFileToTar: %v", err)
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}

	// Extract and verify the written file.
	dest := t.TempDir()
	if err := extractTarGz(buf.Bytes(), dest); err != nil {
		t.Fatalf("extractTarGz: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "test.txt"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("addFileToTar content = %q, want %q", got, data)
	}
}

// ---- verifyBackupIntegrity tests ----

// TestVerifyBackupIntegrity_Valid verifies that a freshly created backup
// passes the integrity check.
func TestVerifyBackupIntegrity_Valid(t *testing.T) {
	_, _, backupFile := makePlainBackup(t)
	data, err := os.ReadFile(backupFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBackupIntegrity(data); err != nil {
		t.Fatalf("verifyBackupIntegrity: %v", err)
	}
}

// TestVerifyBackupIntegrity_Corrupt verifies that corrupted archive data
// returns an error.
func TestVerifyBackupIntegrity_Corrupt(t *testing.T) {
	err := verifyBackupIntegrity([]byte("not-a-gzip"))
	if err == nil {
		t.Fatal("expected error for corrupt data")
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

// ---- parseSizeCap tests ----

func TestParseSizeCap_Empty(t *testing.T) {
	n, err := parseSizeCap("", "")
	if err != nil || n != 0 {
		t.Fatalf("empty cap: got %d, %v; want 0, nil", n, err)
	}
}

func TestParseSizeCap_Zero(t *testing.T) {
	n, err := parseSizeCap("", "0")
	if err != nil || n != 0 {
		t.Fatalf("zero cap: got %d, %v; want 0, nil", n, err)
	}
}

func TestParseSizeCap_AbsoluteBytes(t *testing.T) {
	cases := []struct {
		input string
		want  int64
	}{
		{"100", 100},
		{"1K", 1024},
		{"2KB", 2 * 1024},
		{"3M", 3 * 1024 * 1024},
		{"4MB", 4 * 1024 * 1024},
		{"1G", 1 << 30},
		{"2GB", 2 * (1 << 30)},
		{"1T", 1 << 40},
		{"1TB", 1 << 40},
		{"5B", 5},
	}
	for _, c := range cases {
		got, err := parseSizeCap("", c.input)
		if err != nil {
			t.Errorf("parseSizeCap(%q): unexpected error: %v", c.input, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseSizeCap(%q): got %d, want %d", c.input, got, c.want)
		}
	}
}

func TestParseSizeCap_InvalidAbsolute(t *testing.T) {
	_, err := parseSizeCap("", "notanumber")
	if err == nil {
		t.Fatal("expected error for invalid absolute cap")
	}
}

func TestParseSizeCap_InvalidPercent(t *testing.T) {
	_, err := parseSizeCap(t.TempDir(), "abc%")
	if err == nil {
		t.Fatal("expected error for invalid percent cap")
	}
}

func TestParseSizeCap_PercentOfDevice(t *testing.T) {
	dir := t.TempDir()
	n, err := parseSizeCap(dir, "100%")
	if err != nil {
		t.Fatalf("parseSizeCap 100%%: %v", err)
	}
	if n <= 0 {
		t.Fatalf("parseSizeCap 100%% returned %d; expected positive", n)
	}
}

// ---- enforceSizeCap tests ----

func TestEnforceSizeCap_NoFiles(t *testing.T) {
	dir := t.TempDir()
	if err := enforceSizeCap(dir, "1G"); err != nil {
		t.Fatalf("enforceSizeCap on empty dir: %v", err)
	}
}

func TestEnforceSizeCap_UnderCap(t *testing.T) {
	dir := t.TempDir()
	name := "caswhois_backup_2025-03-05.tar.gz"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("small"), 0600); err != nil {
		t.Fatal(err)
	}
	// 1 TB cap — no files should be deleted.
	if err := enforceSizeCap(dir, "1T"); err != nil {
		t.Fatalf("enforceSizeCap under cap: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Fatalf("file was incorrectly deleted: %v", err)
	}
}

func TestEnforceSizeCap_DeletesOldestWhenOverCap(t *testing.T) {
	dir := t.TempDir()
	// Two files, each 10 bytes. Cap = 1 byte so both should end up deleted
	// (oldest first; after deleting oldest total goes to 10 which is still over 1,
	// then second is deleted leaving 0).
	for i, d := range []string{"2025-01-01", "2025-06-01"} {
		name := "caswhois_backup_" + d + ".tar.gz"
		payload := make([]byte, 10+i) // slightly different sizes to avoid flakiness
		if err := os.WriteFile(filepath.Join(dir, name), payload, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// 1-byte cap: all files should be deleted.
	if err := enforceSizeCap(dir, "1B"); err != nil {
		t.Fatalf("enforceSizeCap: %v", err)
	}
	remaining, _ := filepath.Glob(filepath.Join(dir, "caswhois_backup_*.tar.gz"))
	if len(remaining) != 0 {
		t.Fatalf("expected 0 files remaining, got %d: %v", len(remaining), remaining)
	}
}

// TestApplyRetentionPolicy_SizeCap checks that ApplyRetentionPolicy enforces
// the maxTotalSize cap through the integrated path.
func TestApplyRetentionPolicy_SizeCap(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	// Create 5 backup files, each 100 bytes. Keep limit = 10 (won't trigger count
	// limit). Size cap = 1B so all files will be deleted by size enforcement.
	for i := 0; i < 5; i++ {
		date := now.AddDate(0, 0, -i)
		name := retentionFilename(date, ".tar.gz")
		payload := make([]byte, 100)
		if err := os.WriteFile(filepath.Join(dir, name), payload, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := ApplyRetentionPolicy(dir, 10, 0, 0, 0, "1B"); err != nil {
		t.Fatalf("ApplyRetentionPolicy with size cap: %v", err)
	}
	remaining, _ := filepath.Glob(filepath.Join(dir, "caswhois_backup_*.tar.gz"))
	if len(remaining) != 0 {
		t.Fatalf("expected 0 files after 1B cap, got %d", len(remaining))
	}
}
