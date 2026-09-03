package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
)

// Manifest represents the backup manifest (AI.md PART 21)
type Manifest struct {
	Version          string    `json:"version"`
	CreatedAt        time.Time `json:"created_at"`
	CreatedBy        string    `json:"created_by"`
	AppVersion       string    `json:"app_version"`
	Contents         []string  `json:"contents"`
	Encrypted        bool      `json:"encrypted"`
	EncryptionMethod string    `json:"encryption_method,omitempty"`
	Checksum         string    `json:"checksum"`
}

// BackupOptions configures backup behavior
type BackupOptions struct {
	ConfigDir  string
	DataDir    string
	OutputFile string
	// Password is an optional encryption passphrase; leave empty for unencrypted backup
	Password    string
	IncludeSSL  bool
	IncludeData bool
	// AdminUser is the username of the admin initiating the backup (for audit log)
	AdminUser string
	// AppVersion is the current application version embedded in the backup manifest
	AppVersion string
}

// Create creates a backup per AI.md PART 21 specification
func Create(opts *BackupOptions) error {
	// Generate default filename if not specified
	if opts.OutputFile == "" {
		timestamp := time.Now().Format("2006-01-02_150405")
		ext := ".tar.gz"
		if opts.Password != "" {
			ext = ".tar.gz.enc"
		}
		opts.OutputFile = fmt.Sprintf("caswhois_backup_%s%s", timestamp, ext)
	}

	// Create backup in memory first (for encryption)
	backupData, manifest, err := createBackupArchive(opts)
	if err != nil {
		return fmt.Errorf("create backup archive: %w", err)
	}

	// Encrypt if password provided
	var finalData []byte
	if opts.Password != "" {
		encrypted, err := encryptBackup(backupData, opts.Password)
		if err != nil {
			return fmt.Errorf("encrypt backup: %w", err)
		}
		finalData = encrypted
		manifest.Encrypted = true
		manifest.EncryptionMethod = "AES-256-GCM"
	} else {
		finalData = backupData
	}

	// Write to file
	if err := os.WriteFile(opts.OutputFile, finalData, 0600); err != nil {
		return fmt.Errorf("write backup file: %w", err)
	}

	return nil
}

// createBackupArchive creates tar.gz archive of backup contents
func createBackupArchive(opts *BackupOptions) ([]byte, *Manifest, error) {
	manifest := &Manifest{
		Version:    "1.0.0",
		CreatedAt:  time.Now(),
		CreatedBy:  opts.AdminUser,
		AppVersion: opts.AppVersion,
		Contents:   []string{},
		Encrypted:  false,
	}

	// Pass 1: build archive without manifest to compute checksum over content.
	contentBuf, err := buildContentArchive(opts, manifest)
	if err != nil {
		return nil, nil, err
	}

	// Compute checksum of the content-only archive.
	checksum := sha256.Sum256(contentBuf)
	manifest.Checksum = "sha256:" + hex.EncodeToString(checksum[:])

	// Pass 2: rebuild archive with manifest.json (now containing the checksum) first.
	finalBuf, err := buildFinalArchive(opts, manifest, contentBuf)
	if err != nil {
		return nil, nil, err
	}

	return finalBuf, manifest, nil
}

// buildContentArchive assembles all backup entries except manifest.json and
// returns the raw tar.gz bytes. It also populates manifest.Contents.
func buildContentArchive(opts *BackupOptions, manifest *Manifest) ([]byte, error) {
	var buf []byte
	w := &memoryWriter{data: &buf}
	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)

	// Add server.yml (always included)
	if err := addPathToTar(tw, opts.ConfigDir, "server.yml", &manifest.Contents); err != nil {
		return nil, err
	}

	// Add server.db (always included)
	if err := addPathToTar(tw, opts.DataDir, "server.db", &manifest.Contents); err != nil {
		return nil, err
	}

	// Add users.db if exists
	usersDB := filepath.Join(opts.DataDir, "users.db")
	if fileExists(usersDB) {
		if err := addPathToTar(tw, opts.DataDir, "users.db", &manifest.Contents); err != nil {
			return nil, err
		}
	}

	// Add custom templates if exist
	templatesDir := filepath.Join(opts.ConfigDir, "template")
	if dirExists(templatesDir) {
		if err := addDirToTar(tw, templatesDir, "template", &manifest.Contents); err != nil {
			return nil, err
		}
	}

	// Add custom themes if exist
	themesDir := filepath.Join(opts.ConfigDir, "theme")
	if dirExists(themesDir) {
		if err := addDirToTar(tw, themesDir, "theme", &manifest.Contents); err != nil {
			return nil, err
		}
	}

	// Add SSL certificates if requested
	if opts.IncludeSSL {
		sslDir := filepath.Join(opts.ConfigDir, "ssl")
		if dirExists(sslDir) {
			if err := addDirToTar(tw, sslDir, "ssl", &manifest.Contents); err != nil {
				return nil, err
			}
		}
	}

	// Add data directory if requested
	if opts.IncludeData {
		if dirExists(opts.DataDir) {
			if err := addDirToTar(tw, opts.DataDir, "data", &manifest.Contents); err != nil {
				return nil, err
			}
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar writer: %w", err)
	}
	if err := gzw.Close(); err != nil {
		return nil, fmt.Errorf("close gzip writer: %w", err)
	}

	return buf, nil
}

// buildFinalArchive builds the definitive tar.gz: manifest.json (with checksum)
// first, followed by the content entries from contentBuf re-streamed.
func buildFinalArchive(opts *BackupOptions, manifest *Manifest, contentBuf []byte) ([]byte, error) {
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}

	var buf []byte
	w := &memoryWriter{data: &buf}
	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)

	// Write manifest first
	if err := addFileToTar(tw, "manifest.json", manifestJSON); err != nil {
		return nil, err
	}

	// Re-stream the content entries from the first-pass archive.
	gzr, err := gzip.NewReader(&bytesReader{data: contentBuf})
	if err != nil {
		return nil, fmt.Errorf("open content archive: %w", err)
	}
	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("re-stream content: %w", err)
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("write re-stream header: %w", err)
		}
		if _, err := io.Copy(tw, tr); err != nil {
			return nil, fmt.Errorf("copy re-stream entry: %w", err)
		}
	}
	gzr.Close()

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close final tar writer: %w", err)
	}
	if err := gzw.Close(); err != nil {
		return nil, fmt.Errorf("close final gzip writer: %w", err)
	}

	return buf, nil
}

// encryptBackup encrypts backup data using AES-256-GCM with Argon2id key derivation
// Per AI.md PART 21 specification
func encryptBackup(data []byte, password string) ([]byte, error) {
	// Generate salt for Argon2id
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	// Derive 256-bit key using Argon2id
	// Parameters: time=1, memory=64MB, threads=4, keyLen=32
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Prepend salt to ciphertext (needed for decryption)
	result := append(salt, ciphertext...)

	return result, nil
}

// Helper functions

type memoryWriter struct {
	data *[]byte
}

func (w *memoryWriter) Write(p []byte) (n int, err error) {
	*w.data = append(*w.data, p...)
	return len(p), nil
}

func addFileToTar(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name: name,
		Mode: 0600,
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(data); err != nil {
		return err
	}
	return nil
}

func addPathToTar(tw *tar.Writer, baseDir, relPath string, contents *[]string) error {
	fullPath := filepath.Join(baseDir, relPath)

	f, err := os.Open(fullPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", relPath, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", relPath, err)
	}

	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return fmt.Errorf("create header for %s: %w", relPath, err)
	}
	hdr.Name = relPath

	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write header for %s: %w", relPath, err)
	}

	if _, err := io.Copy(tw, f); err != nil {
		return fmt.Errorf("write %s to tar: %w", relPath, err)
	}

	*contents = append(*contents, relPath)
	return nil
}

func addDirToTar(tw *tar.Writer, srcDir, tarPath string, contents *[]string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		tarName := filepath.Join(tarPath, relPath)

		// Create tar header
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = tarName

		// Write header
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		// Write file content (skip directories)
		if !info.IsDir() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()

			if _, err := io.Copy(tw, f); err != nil {
				return err
			}

			*contents = append(*contents, tarName)
		}

		return nil
	})
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// VerifyBackup performs comprehensive backup verification per AI.md PART 21
// All 7 checks must pass:
// 1. File exists
// 2. Size > 0
// 3. Checksum valid
// 4. Decrypt test (if encrypted)
// 5. Manifest readable
// 6. Content extraction test
// 7. Database integrity
func VerifyBackup(backupFile string, password string) error {
	// Check 1: File exists
	info, err := os.Stat(backupFile)
	if err != nil {
		return fmt.Errorf("backup file not found: %w", err)
	}

	// Check 2: Size > 0
	if info.Size() == 0 {
		return fmt.Errorf("backup file is empty")
	}

	// Read backup file
	data, err := os.ReadFile(backupFile)
	if err != nil {
		return fmt.Errorf("read backup file: %w", err)
	}

	// Check if encrypted
	encrypted := filepath.Ext(backupFile) == ".enc"

	// Check 4: Decrypt test (if encrypted)
	var archiveData []byte
	if encrypted {
		if password == "" {
			return fmt.Errorf("backup is encrypted but no password provided")
		}
		decrypted, err := decryptBackupData(data, password)
		if err != nil {
			return fmt.Errorf("decrypt backup: %w", err)
		}
		archiveData = decrypted
	} else {
		archiveData = data
	}

	// Check 5: Manifest readable & Check 6: Content extraction test
	// Extract to temporary directory
	tempDir, err := os.MkdirTemp("", "backup-verify-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Extract archive
	if err := extractTarGz(archiveData, tempDir); err != nil {
		return fmt.Errorf("extract archive: %w", err)
	}

	// Read manifest
	manifestPath := filepath.Join(tempDir, "manifest.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}

	// Check 3: Checksum valid — reconstruct content-only archive (no manifest.json)
	// and compare against the stored checksum, matching how Create computes it.
	contentBuf, err := rebuildContentArchive(archiveData)
	if err != nil {
		return fmt.Errorf("rebuild content archive for checksum: %w", err)
	}
	checksum := sha256.Sum256(contentBuf)
	checksumStr := "sha256:" + hex.EncodeToString(checksum[:])

	// Verify checksum matches
	if manifest.Checksum != checksumStr {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", manifest.Checksum, checksumStr)
	}

	// Check 7: Database integrity (verify SQLite databases)
	// Check server.db
	serverDB := filepath.Join(tempDir, "server.db")
	if fileExists(serverDB) {
		if err := verifyDatabaseIntegrity(serverDB); err != nil {
			return fmt.Errorf("server.db integrity check failed: %w", err)
		}
	}

	// Check users.db if exists
	usersDB := filepath.Join(tempDir, "users.db")
	if fileExists(usersDB) {
		if err := verifyDatabaseIntegrity(usersDB); err != nil {
			return fmt.Errorf("users.db integrity check failed: %w", err)
		}
	}

	return nil
}

// extractTarGz extracts a tar.gz archive to destination directory
func extractTarGz(data []byte, dest string) error {
	gzr, err := gzip.NewReader(&bytesReader{data: data})
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}

		// Security: prevent path traversal
		if !filepath.IsLocal(hdr.Name) {
			return fmt.Errorf("illegal path in archive: %s", hdr.Name)
		}

		target := filepath.Join(dest, hdr.Name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("create directory %s: %w", target, err)
			}
		case tar.TypeReg:
			// Ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("create parent directory for %s: %w", target, err)
			}

			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}

			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("write file %s: %w", target, err)
			}
			f.Close()
		}
	}

	return nil
}

// bytesReader wraps byte slice to implement io.Reader
type bytesReader struct {
	data []byte
	pos  int
}

func (r *bytesReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// rebuildContentArchive re-streams a full backup archive, omitting the
// manifest.json entry, and returns the resulting tar.gz bytes.
// This mirrors buildContentArchive so VerifyBackup can reproduce the same
// bytes that were hashed during Create.
func rebuildContentArchive(archiveData []byte) ([]byte, error) {
	gzr, err := gzip.NewReader(&bytesReader{data: archiveData})
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	defer gzr.Close()

	var buf []byte
	w := &memoryWriter{data: &buf}
	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read entry: %w", err)
		}
		if hdr.Name == "manifest.json" {
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return nil, err
			}
			continue
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := io.Copy(tw, tr); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}
	if err := gzw.Close(); err != nil {
		return nil, fmt.Errorf("close gzip: %w", err)
	}

	return buf, nil
}

// verifyDatabaseIntegrity checks SQLite database integrity
func verifyDatabaseIntegrity(dbPath string) error {
	// Basic check: file exists and is readable
	f, err := os.Open(dbPath)
	if err != nil {
		return fmt.Errorf("cannot open database: %w", err)
	}
	defer f.Close()

	// Check SQLite header (first 16 bytes should be "SQLite format 3\000")
	header := make([]byte, 16)
	if _, err := f.Read(header); err != nil {
		return fmt.Errorf("cannot read database header: %w", err)
	}

	expectedHeader := []byte("SQLite format 3\x00")
	for i := 0; i < len(expectedHeader); i++ {
		if header[i] != expectedHeader[i] {
			return fmt.Errorf("invalid SQLite header")
		}
	}

	return nil
}

// decryptBackupData decrypts backup data (internal use for verification)
func decryptBackupData(data []byte, password string) ([]byte, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extract salt (first 32 bytes)
	salt := data[:32]
	ciphertext := data[32:]

	// Derive key using same parameters as encryption
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// ApplyRetentionPolicy deletes old backups based on retention settings.
// maxTotalSize is a hard cap expressed as a percent of the backup device ("10%")
// or an absolute size ("50G", "500M"); "0" or empty disables the cap.
// Per AI.md PART 21 specification.
func ApplyRetentionPolicy(backupDir string, maxBackups, keepWeekly, keepMonthly, keepYearly int, maxTotalSize string) error {
	// List all backup files (exclude incrementals: -daily, -hourly)
	files, err := filepath.Glob(filepath.Join(backupDir, "caswhois_backup_*.tar.gz*"))
	if err != nil {
		return fmt.Errorf("list backups: %w", err)
	}

	// Parse backup dates
	type backupFile struct {
		path string
		date time.Time
		keep bool
	}

	var backups []backupFile
	for _, f := range files {
		// Skip incrementals
		base := filepath.Base(f)
		if contains(base, "-daily") || contains(base, "-hourly") {
			continue
		}

		// Parse date from filename: caswhois_backup_YYYY-MM-DD_HHMMSS.tar.gz[.enc]
		// Extract YYYY-MM-DD portion
		if len(base) < 28 {
			continue
		}
		// Example: "2025-01-15"
		dateStr := base[17:27]
		date, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			continue
		}

		backups = append(backups, backupFile{path: f, date: date, keep: false})
	}

	// Sort by date (newest first)
	for i := 0; i < len(backups); i++ {
		for j := i + 1; j < len(backups); j++ {
			if backups[i].date.Before(backups[j].date) {
				backups[i], backups[j] = backups[j], backups[i]
			}
		}
	}

	// Apply retention rules (priority: yearly > monthly > weekly > daily)

	// Mark yearly backups (January 1st)
	yearlyCount := 0
	for i := range backups {
		if backups[i].date.Month() == time.January && backups[i].date.Day() == 1 {
			if yearlyCount < keepYearly {
				backups[i].keep = true
				yearlyCount++
			}
		}
	}

	// Mark monthly backups (1st of month)
	monthlyCount := 0
	for i := range backups {
		if !backups[i].keep && backups[i].date.Day() == 1 {
			if monthlyCount < keepMonthly {
				backups[i].keep = true
				monthlyCount++
			}
		}
	}

	// Mark weekly backups (Sunday)
	weeklyCount := 0
	for i := range backups {
		if !backups[i].keep && backups[i].date.Weekday() == time.Sunday {
			if weeklyCount < keepWeekly {
				backups[i].keep = true
				weeklyCount++
			}
		}
	}

	// Mark daily backups (most recent)
	dailyCount := 0
	for i := range backups {
		if !backups[i].keep {
			if dailyCount < maxBackups {
				backups[i].keep = true
				dailyCount++
			}
		}
	}

	// Delete unmarked backups
	for _, backup := range backups {
		if !backup.keep {
			if err := os.Remove(backup.path); err != nil {
				return fmt.Errorf("delete %s: %w", backup.path, err)
			}
		}
	}

	// Enforce hard size cap — oldest backups first until total is under cap.
	if maxTotalSize != "" && maxTotalSize != "0" {
		if err := enforceSizeCap(backupDir, maxTotalSize); err != nil {
			return fmt.Errorf("enforce size cap: %w", err)
		}
	}

	return nil
}

// enforceSizeCap deletes oldest backup files until total size is under the cap.
// cap may be a percent of the backup volume ("10%") or an absolute byte count
// with optional suffix: B, K/KB, M/MB, G/GB, T/TB.
func enforceSizeCap(backupDir, cap string) error {
	capBytes, err := parseSizeCap(backupDir, cap)
	if err != nil || capBytes == 0 {
		return err
	}

	// Collect backup files sorted oldest first.
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return fmt.Errorf("read backup dir: %w", err)
	}

	type sizedFile struct {
		path string
		size int64
		mod  time.Time
	}
	var files []sizedFile
	var totalBytes int64

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "caswhois_backup_") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, sizedFile{
			path: filepath.Join(backupDir, name),
			size: info.Size(),
			mod:  info.ModTime(),
		})
		totalBytes += info.Size()
	}

	if totalBytes <= capBytes {
		return nil
	}

	// Sort oldest first (ascending mod time).
	for i := 0; i < len(files); i++ {
		for j := i + 1; j < len(files); j++ {
			if files[i].mod.After(files[j].mod) {
				files[i], files[j] = files[j], files[i]
			}
		}
	}

	for _, f := range files {
		if totalBytes <= capBytes {
			break
		}
		if err := os.Remove(f.path); err != nil {
			return fmt.Errorf("remove %s: %w", f.path, err)
		}
		totalBytes -= f.size
	}
	return nil
}

// parseSizeCap converts a size-cap string to bytes.
// Percent values (e.g. "10%") are resolved against the device holding backupDir.
func parseSizeCap(backupDir, cap string) (int64, error) {
	cap = strings.TrimSpace(cap)
	if cap == "" || cap == "0" {
		return 0, nil
	}

	if strings.HasSuffix(cap, "%") {
		pctStr := strings.TrimSuffix(cap, "%")
		pct, err := strconv.ParseFloat(pctStr, 64)
		if err != nil || pct <= 0 {
			return 0, fmt.Errorf("invalid percent size cap %q", cap)
		}

		var st syscall.Statfs_t
		if err := syscall.Statfs(backupDir, &st); err != nil {
			return 0, fmt.Errorf("statfs %s: %w", backupDir, err)
		}
		totalBytes := int64(st.Blocks) * int64(st.Bsize)
		return int64(float64(totalBytes) * pct / 100.0), nil
	}

	// Absolute size with optional unit suffix.
	upper := strings.ToUpper(cap)
	units := []struct {
		suffix string
		mult   int64
	}{
		{"TB", 1 << 40},
		{"GB", 1 << 30},
		{"MB", 1 << 20},
		{"KB", 1 << 10},
		{"T", 1 << 40},
		{"G", 1 << 30},
		{"M", 1 << 20},
		{"K", 1 << 10},
		{"B", 1},
	}
	for _, u := range units {
		if strings.HasSuffix(upper, u.suffix) {
			numStr := upper[:len(upper)-len(u.suffix)]
			n, err := strconv.ParseFloat(strings.TrimSpace(numStr), 64)
			if err != nil {
				return 0, fmt.Errorf("invalid size cap %q", cap)
			}
			return int64(n * float64(u.mult)), nil
		}
	}

	// Plain integer = bytes.
	n, err := strconv.ParseInt(cap, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size cap %q", cap)
	}
	return n, nil
}

// CreateIncremental creates an incremental backup (daily or hourly)
// Per AI.md PART 21 specification
func CreateIncremental(opts *BackupOptions, backupType string) error {
	// Determine filename
	ext := ".tar.gz"
	if opts.Password != "" {
		ext = ".tar.gz.enc"
	}
	opts.OutputFile = fmt.Sprintf("caswhois-%s%s", backupType, ext)

	// Create backup (same as full backup)
	return Create(opts)
}

// contains checks if string contains substring (helper for retention)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && hasSubstring(s, substr)
}

func hasSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
