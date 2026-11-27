package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/apimgr/whois/src/common/constants"
	"github.com/apimgr/whois/src/common/tempdir"
	"github.com/apimgr/whois/src/db"
	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

var (
	ErrNoFullBackup          = errors.New("no full backup exists")
	ErrBackupPasswordChanged = errors.New("backup password changed")
	ErrCorruptBackupBase     = errors.New("incremental base is corrupt")
)

// EnsureBackupDir creates the configured directory and verifies it is writable.
func EnsureBackupDir(backupDir string) error {
	if err := os.MkdirAll(backupDir, backupDirectoryMode()); err != nil {
		return fmt.Errorf("create backup directory %s: %w", backupDir, err)
	}
	probe, err := os.CreateTemp(backupDir, ".write-test-*")
	if err == nil {
		name := probe.Name()
		if closeErr := probe.Close(); closeErr != nil {
			err = closeErr
		}
		_ = os.Remove(name)
	}
	if err != nil {
		info, statErr := os.Stat(backupDir)
		mode, owner := "unknown", "unknown"
		if statErr == nil {
			mode = info.Mode().Perm().String()
			owner = backupDirectoryOwner(info)
		}
		current, _ := user.Current()
		running := "unknown"
		if current != nil {
			running = current.Username
		}
		return fmt.Errorf("backup directory %s is not writable (owner %s, mode %s, running user %s): %w", backupDir, owner, mode, running, err)
	}
	return nil
}

// SweepBackupArtifacts removes only hidden unpublished temporary archives.
func SweepBackupArtifacts(backupDir string) error {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return fmt.Errorf("read backup directory %s: %w", backupDir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".backup-") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(backupDir, entry.Name())); err != nil {
			return fmt.Errorf("remove incomplete backup artifact %s: %w", entry.Name(), err)
		}
	}
	return nil
}

// Manifest represents the backup manifest (AI.md PART 21)
type Manifest struct {
	Version          string       `json:"version"`
	CreatedAt        time.Time    `json:"created_at"`
	CreatedBy        string       `json:"created_by"`
	AppVersion       string       `json:"app_version"`
	Contents         []string     `json:"contents"`
	Encrypted        bool         `json:"encrypted"`
	EncryptionMethod string       `json:"encryption_method,omitempty"`
	Checksum         string       `json:"sha256"`
	Type             string       `json:"type"`
	SnapshotAt       time.Time    `json:"snapshot_at"`
	Files            []FileRecord `json:"files"`
	BaseBackup       string       `json:"base_backup,omitempty"`
	BaseChecksum     string       `json:"base_sha256,omitempty"`
	Deleted          []string     `json:"deleted,omitempty"`
}

// FileRecord describes one content file covered by the canonical manifest checksum.
type FileRecord struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	MTime  int64  `json:"mtime"`
	SHA256 string `json:"sha256"`
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
	BackupDir   string
	// AdminUser is the username of the admin initiating the backup (for audit log)
	AdminUser string
	// AppVersion is the current application version embedded in the backup manifest
	AppVersion         string
	SnapshotAt         time.Time
	AppSecrets         map[string]string
	ConnectionTLSFiles []string
	ExternalTLSFiles   []ExternalTLSFile
}

type ExternalTLSFile struct{ Name, Path string }

// Create creates a backup per AI.md PART 21 specification
func Create(opts *BackupOptions) error {
	if opts == nil {
		return fmt.Errorf("backup options are required")
	}
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
	backupData, _, err := createBackupArchive(opts)
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
	} else {
		finalData = backupData
	}

	return publishBackupData(opts, finalData)
}

func publishBackupData(opts *BackupOptions, finalData []byte) error {
	outputDir := filepath.Dir(opts.OutputFile)
	tempFile, err := os.CreateTemp(outputDir, ".backup-*"+filepath.Ext(opts.OutputFile))
	if err != nil {
		return fmt.Errorf("create temporary backup file: %w", err)
	}
	tempPath := tempFile.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if err := tempFile.Chmod(0600); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("secure temporary backup: %w", err)
	}
	if _, err := tempFile.Write(finalData); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("write temporary backup: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("sync temporary backup: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temporary backup: %w", err)
	}
	if err := VerifyBackup(tempPath, opts.Password); err != nil {
		return fmt.Errorf("verify backup before publish: %w", err)
	}
	if isReplaceableIncremental(opts.OutputFile) {
		if err := os.Rename(tempPath, opts.OutputFile); err != nil {
			return fmt.Errorf("publish incremental backup: %w", err)
		}
		return nil
	}
	destination, err := os.OpenFile(opts.OutputFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create backup file without overwriting: %w", err)
	}
	source, err := os.Open(tempPath)
	if err != nil {
		_ = destination.Close()
		_ = os.Remove(opts.OutputFile)
		return fmt.Errorf("open verified backup: %w", err)
	}
	_, copyErr := io.Copy(destination, source)
	closeSourceErr := source.Close()
	if copyErr != nil || closeSourceErr != nil {
		_ = destination.Close()
		_ = os.Remove(opts.OutputFile)
		if copyErr != nil {
			return fmt.Errorf("write backup file: %w", copyErr)
		}
		return fmt.Errorf("close verified backup: %w", closeSourceErr)
	}
	if err := destination.Sync(); err != nil {
		_ = destination.Close()
		_ = os.Remove(opts.OutputFile)
		return fmt.Errorf("sync backup file: %w", err)
	}
	if err := destination.Close(); err != nil {
		_ = os.Remove(opts.OutputFile)
		return fmt.Errorf("close backup file: %w", err)
	}
	if err := VerifyBackup(opts.OutputFile, opts.Password); err != nil {
		_ = os.Remove(opts.OutputFile)
		return fmt.Errorf("verify published backup: %w", err)
	}

	return nil
}

func isReplaceableIncremental(path string) bool {
	name := filepath.Base(path)
	return strings.HasPrefix(name, "caswhois-daily.tar.gz") || strings.HasPrefix(name, "caswhois-hourly.tar.gz")
}

func filterContentArchive(data []byte, include map[string]bool) ([]byte, error) {
	input, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open content archive: %w", err)
	}
	defer func() { _ = input.Close() }()
	var output []byte
	outGzip := gzip.NewWriter(&memoryWriter{data: &output})
	outTar := tar.NewWriter(outGzip)
	reader := tar.NewReader(input)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read content archive: %w", err)
		}
		if !include[header.Name] {
			if _, err := io.Copy(io.Discard, reader); err != nil {
				return nil, err
			}
			continue
		}
		if err := outTar.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := io.Copy(outTar, reader); err != nil {
			return nil, err
		}
	}
	if err := outTar.Close(); err != nil {
		return nil, err
	}
	if err := outGzip.Close(); err != nil {
		return nil, err
	}
	return output, nil
}

func readArchiveManifest(data []byte) (*Manifest, error) {
	dir, err := tempdir.Create()
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := extractTarGz(data, dir); err != nil {
		return nil, err
	}
	return loadManifest(dir)
}

func readBackupArchive(path, password string) ([]byte, *Manifest, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("backup is not a regular file")
	}
	limits, err := effectiveRestoreLimits(RestoreLimits{})
	if err != nil {
		return nil, nil, err
	}
	if info.Size() > limits.maxArchiveSize {
		return nil, nil, restoreLimitError("archive size %d bytes exceeds configured maximum %d bytes", info.Size(), limits.maxArchiveSize)
	}
	if err := VerifyBackup(path, password); err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if strings.HasSuffix(path, ".enc") {
		data, err = decryptBackupData(data, password)
		if err != nil {
			return nil, nil, err
		}
	} else if password == "" {
		// Unencrypted archives do not need a password.
	}
	if err := verifyBackupIntegrity(data); err != nil {
		return nil, nil, err
	}
	manifest, err := readArchiveManifest(data)
	return data, manifest, err
}

// SelectLatestFullBackup chooses a full archive by its UTC filename date;
// modification time breaks ties for timestamped or same-day fulls.
func SelectLatestFullBackup(backupDir, projectName string) (string, error) {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return "", fmt.Errorf("read backup directory: %w", err)
	}
	prefix := projectName + "_backup_"
	var selected string
	var selectedDate time.Time
	var selectedMod time.Time
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".tar.gz") && !strings.HasSuffix(name, ".tar.gz.enc") {
			continue
		}
		name = strings.TrimSuffix(strings.TrimSuffix(name, ".enc"), ".tar.gz")
		stamp := strings.TrimPrefix(name, prefix)
		datePart := strings.SplitN(stamp, "_", 2)[0]
		date, parseErr := time.Parse("2006-01-02", datePart)
		if parseErr == nil && stamp != datePart {
			if _, parseErr = time.Parse("2006-01-02_150405", stamp); parseErr != nil {
				continue
			}
		}
		if parseErr != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if selected == "" || date.After(selectedDate) || (date.Equal(selectedDate) && info.ModTime().After(selectedMod)) {
			selected = filepath.Join(backupDir, entry.Name())
			selectedDate = date
			selectedMod = info.ModTime()
		}
	}
	if selected == "" {
		return "", ErrNoFullBackup
	}
	return selected, nil
}

// createBackupArchive creates tar.gz archive of backup contents
func createBackupArchive(opts *BackupOptions) ([]byte, *Manifest, error) {
	snapshotAt := opts.SnapshotAt
	if snapshotAt.IsZero() {
		snapshotAt = time.Now().UTC()
	}
	manifest := &Manifest{
		Version:    "1.0.0",
		CreatedAt:  snapshotAt,
		CreatedBy:  opts.AdminUser,
		AppVersion: opts.AppVersion,
		Contents:   []string{},
		Encrypted:  opts.Password != "",
	}
	if manifest.Encrypted {
		manifest.EncryptionMethod = "AES-256-GCM"
	}

	// Pass 1: build archive without manifest to compute checksum over content.
	contentBuf, err := buildContentArchive(opts, manifest)
	if err != nil {
		return nil, nil, err
	}

	manifest.Type = "full"
	manifest.SnapshotAt = snapshotAt.UTC()
	manifest.Files, err = fileRecordsFromArchive(contentBuf)
	if err != nil {
		return nil, nil, err
	}
	manifest.Checksum = checksumFileRecords(manifest.Files)

	// Pass 2: rebuild archive with manifest.json (now containing the checksum) first.
	finalBuf, err := buildFinalArchive(opts, manifest, contentBuf)
	if err != nil {
		return nil, nil, err
	}

	return finalBuf, manifest, nil
}

func fileRecordsFromArchive(data []byte) ([]FileRecord, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("read content archive: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	var records []FileRecord
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read content entry: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		h := sha256.New()
		if _, err := io.Copy(h, tr); err != nil {
			return nil, fmt.Errorf("hash %s: %w", hdr.Name, err)
		}
		records = append(records, FileRecord{Path: hdr.Name, Size: hdr.Size, MTime: hdr.ModTime.Unix(), SHA256: hex.EncodeToString(h.Sum(nil))})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	return records, nil
}

func checksumFileRecords(records []FileRecord) string {
	sorted := append([]FileRecord(nil), records...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	h := sha256.New()
	for _, record := range sorted {
		_, _ = fmt.Fprintf(h, "%s  %s\n", record.SHA256, record.Path)
	}
	return hex.EncodeToString(h.Sum(nil))
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
	for _, directory := range []string{"yaml.d", "assets"} {
		path := filepath.Join(opts.ConfigDir, directory)
		if dirExists(path) {
			if err := addDirToTar(tw, path, directory, &manifest.Contents); err != nil {
				return nil, err
			}
		}
	}

	// Include a sanitized copy of secrets.yml when it exists.
	secretsPath := filepath.Join(opts.ConfigDir, "secrets.yml")
	if fileExists(secretsPath) {
		data, err := os.ReadFile(secretsPath)
		if err != nil {
			return nil, fmt.Errorf("read secrets.yml: %w", err)
		}
		var secrets map[string]any
		if err := yaml.Unmarshal(data, &secrets); err != nil {
			return nil, fmt.Errorf("parse secrets.yml: %w", err)
		}
		server, _ := secrets["server"].(map[string]any)
		if server != nil {
			server["token"] = ""
			backup, _ := server["backup"].(map[string]any)
			if backup != nil {
				backup["encryption_password"] = ""
			}
		}
		sanitized, err := yaml.Marshal(secrets)
		if err != nil {
			return nil, fmt.Errorf("sanitize secrets.yml: %w", err)
		}
		if err := addFileToTar(tw, "secrets.yml", sanitized); err != nil {
			return nil, err
		}
		manifest.Contents = append(manifest.Contents, "secrets.yml")
	}

	// Add the local SQLite database only when one exists; remote databases are external.
	serverDB := filepath.Join(opts.DataDir, "server.db")
	if fileExists(serverDB) {
		snapshotDir, err := tempdir.Create()
		if err != nil {
			return nil, fmt.Errorf("create database snapshot directory: %w", err)
		}
		defer func() { _ = os.RemoveAll(snapshotDir) }()
		snapshotPath := filepath.Join(snapshotDir, "server.db")
		if err := db.SnapshotSQLite(context.Background(), serverDB, snapshotPath); err != nil {
			return nil, fmt.Errorf("snapshot server.db: %w", err)
		}
		if err := addPathToTar(tw, snapshotDir, "server.db", &manifest.Contents); err != nil {
			return nil, err
		}
	}
	appSecrets := opts.AppSecrets
	if appSecrets == nil {
		appSecrets = map[string]string{}
	}
	secretsJSON, err := json.Marshal(appSecrets)
	if err != nil {
		return nil, fmt.Errorf("encode app_secrets.json: %w", err)
	}
	if err := addFileToTar(tw, "app_secrets.json", secretsJSON); err != nil {
		return nil, err
	}
	manifest.Contents = append(manifest.Contents, "app_secrets.json")

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
	customThemeDir := filepath.Join(opts.ConfigDir, "theme")
	if dirExists(customThemeDir) {
		if err := addDirToTar(tw, customThemeDir, "theme", &manifest.Contents); err != nil {
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
	seenTLS := make(map[string]string)
	for _, name := range opts.ConnectionTLSFiles {
		if strings.TrimSpace(name) == "" {
			continue
		}
		clean := filepath.Clean(name)
		if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
			return nil, fmt.Errorf("connection TLS path must stay inside config_dir/ssl: %q", name)
		}
		source := filepath.Join(opts.ConfigDir, "ssl", clean)
		archiveName := filepath.ToSlash(filepath.Join("ssl", clean))
		if previous, exists := seenTLS[archiveName]; exists {
			if previous != source {
				return nil, fmt.Errorf("multiple TLS files map to %s", archiveName)
			}
			continue
		}
		if err := addFilePathToTar(tw, source, archiveName); err != nil {
			return nil, fmt.Errorf("include connection TLS file %s: %w", name, err)
		}
		seenTLS[archiveName] = source
		manifest.Contents = append(manifest.Contents, archiveName)
	}
	sslRoot, err := filepath.Abs(filepath.Join(opts.ConfigDir, "ssl"))
	if err != nil {
		return nil, err
	}
	for _, configuredFile := range opts.ExternalTLSFiles {
		if strings.TrimSpace(configuredFile.Path) == "" {
			continue
		}
		source := configuredFile.Path
		if !filepath.IsAbs(source) {
			source = filepath.Join(opts.ConfigDir, source)
		}
		source, err = filepath.Abs(source)
		if err != nil {
			return nil, err
		}
		rel, relErr := filepath.Rel(sslRoot, source)
		insideSSL := relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
		archiveName := filepath.ToSlash(filepath.Join("ssl-external", filepath.Base(configuredFile.Name)))
		if insideSSL {
			archiveName = filepath.ToSlash(filepath.Join("ssl", rel))
		}
		if previous, exists := seenTLS[archiveName]; exists {
			if previous != source {
				return nil, fmt.Errorf("multiple TLS files map to %s", archiveName)
			}
			continue
		}
		if err := addFilePathToTar(tw, source, archiveName); err != nil {
			return nil, fmt.Errorf("include external TLS file %s: %w", source, err)
		}
		seenTLS[archiveName] = source
		manifest.Contents = append(manifest.Contents, archiveName)
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
	if err := gzr.Close(); err != nil {
		return nil, fmt.Errorf("close source gzip reader: %w", err)
	}

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
	return encryptBackupWithBase(data, password, "")
}

func encryptBackupWithBase(data []byte, password, baseName string) ([]byte, error) {
	if len(baseName) > 255 || strings.ContainsAny(baseName, `/\\`) {
		return nil, fmt.Errorf("invalid base backup name")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	memory, iterations, parallelism := uint32(65536), uint32(3), uint32(4)
	key := argon2.IDKey([]byte(password), salt, iterations, memory, uint8(parallelism), 32)

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

	header := make([]byte, 0, 55+len(baseName))
	header = append(header, []byte("BKUP1")...)
	header = append(header, salt...)
	var numeric [4]byte
	for _, value := range []uint32{memory, iterations, parallelism} {
		binary.BigEndian.PutUint32(numeric[:], value)
		header = append(header, numeric[:]...)
	}
	header = append(header, nonce...)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("key-id"))
	header = append(header, []byte(hex.EncodeToString(mac.Sum(nil)[:4]))...)
	var baseLength [2]byte
	binary.BigEndian.PutUint16(baseLength[:], uint16(len(baseName)))
	header = append(header, baseLength[:]...)
	header = append(header, []byte(baseName)...)
	ciphertext := gcm.Seal(nil, nonce, data, header)
	result := append(header, ciphertext...)

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

func addFilePathToTar(tw *tar.Writer, source, archiveName string) error {
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = archiveName
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err = io.Copy(tw, file)
	return err
}

func addPathToTar(tw *tar.Writer, baseDir, relPath string, contents *[]string) error {
	fullPath := filepath.Join(baseDir, relPath)
	linkInfo, err := os.Lstat(fullPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", relPath, err)
	}
	if !linkInfo.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", relPath)
	}

	f, err := os.Open(fullPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", relPath, err)
	}
	defer func() { _ = f.Close() }()

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
		// cache.db is a derived replica and is never part of a backup.
		if !info.IsDir() && info.Name() == "cache.db" {
			return nil
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported backup file type %s", path)
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
			defer func() { _ = f.Close() }()

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
	limits, err := effectiveRestoreLimits(RestoreLimits{})
	if err != nil {
		return err
	}
	if info.Size() > limits.maxArchiveSize {
		return restoreLimitError("archive size %d bytes exceeds configured maximum %d bytes", info.Size(), limits.maxArchiveSize)
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
	if err := checkRestoreArchiveLimits(archiveData, limits); err != nil {
		return err
	}

	// Check 5: Manifest readable & Check 6: Content extraction test
	// Extract to temporary directory
	tempDir, err := tempdir.Create()
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Extract archive
	if err := extractBackup(archiveData, tempDir, limits); err != nil {
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
	records, err := fileRecordsFromArchive(contentBuf)
	if err != nil {
		return fmt.Errorf("read content records: %w", err)
	}
	checksumStr := checksumFileRecords(records)
	if (manifest.Type != "incremental" && len(manifest.Files) == 0) || !sameFileRecords(manifest.Files, records) {
		return fmt.Errorf("manifest file records do not match archive contents")
	}

	// Verify checksum matches
	if manifest.Checksum != checksumStr {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", manifest.Checksum, checksumStr)
	}
	if manifest.Type == "incremental" {
		if manifest.BaseBackup == "" || filepath.Base(manifest.BaseBackup) != manifest.BaseBackup {
			return fmt.Errorf("ERR_BASE_CORRUPT: invalid base backup name")
		}
		if encrypted {
			headerBase, err := encryptedBackupBaseName(data)
			if err != nil || headerBase != manifest.BaseBackup {
				return fmt.Errorf("ERR_BASE_CORRUPT: encrypted header does not name the manifest base")
			}
		}
		basePath := filepath.Join(filepath.Dir(backupFile), manifest.BaseBackup)
		baseInfo, err := os.Stat(basePath)
		if err != nil {
			return fmt.Errorf("ERR_BASE_MISSING: %s", manifest.BaseBackup)
		}
		if !baseInfo.Mode().IsRegular() {
			return fmt.Errorf("ERR_BASE_CORRUPT: base backup is not a regular file")
		}
		if strings.HasSuffix(basePath, ".enc") != encrypted {
			return fmt.Errorf("ERR_BASE_CORRUPT: incremental and base encryption do not match")
		}
		baseData, err := os.ReadFile(basePath)
		if err != nil {
			return fmt.Errorf("read base backup: %w", err)
		}
		if strings.HasSuffix(basePath, ".enc") {
			baseData, err = decryptBackupData(baseData, password)
			if err != nil {
				return fmt.Errorf("ERR_BASE_CORRUPT: decrypt base backup: %w", err)
			}
		}
		baseManifest, err := readArchiveManifest(baseData)
		if err != nil || baseManifest.Type != "full" || baseManifest.Checksum != manifest.BaseChecksum {
			return fmt.Errorf("ERR_BASE_CORRUPT: base checksum mismatch")
		}
		if err := VerifyBackup(basePath, password); err != nil {
			return fmt.Errorf("ERR_BASE_CORRUPT: verify base backup: %w", err)
		}
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

func sameFileRecords(a, b []FileRecord) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// extractTarGz extracts a tar.gz archive to destination directory
func extractTarGz(data []byte, dest string) error {
	gzr, err := gzip.NewReader(&bytesReader{data: data})
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer func() { _ = gzr.Close() }()

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
				_ = f.Close()
				return fmt.Errorf("write file %s: %w", target, err)
			}
			_ = f.Close()
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
	defer func() { _ = gzr.Close() }()

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

// verifyDatabaseIntegrity runs SQLite's full database integrity check.
func verifyDatabaseIntegrity(dbPath string) error {
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(dbPath), RawQuery: "mode=ro"}).String()
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("cannot open SQLite database: %w", err)
	}
	defer func() { _ = database.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rows, err := database.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return fmt.Errorf("run SQLite integrity check: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var result string
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return fmt.Errorf("read SQLite integrity result: %w", err)
		}
		return errors.New("SQLite integrity check returned no result")
	}
	if err := rows.Scan(&result); err != nil {
		return fmt.Errorf("read SQLite integrity result: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("SQLite integrity check failed: %s", result)
	}
	if rows.Next() {
		return errors.New("SQLite integrity check returned additional errors")
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read SQLite integrity result: %w", err)
	}
	return nil
}

// decryptBackupData decrypts backup data (internal use for verification)
func decryptBackupData(data []byte, password string) ([]byte, error) {
	if len(data) < 55 || string(data[:5]) != "BKUP1" {
		return nil, fmt.Errorf("invalid encrypted archive header")
	}
	baseLength := int(binary.BigEndian.Uint16(data[53:55]))
	if baseLength > 255 || len(data) < 55+baseLength {
		return nil, fmt.Errorf("invalid encrypted archive header length")
	}
	headerLength := 55 + baseLength
	header := data[:headerLength]
	baseName := data[55:headerLength]
	if !utf8.Valid(baseName) || strings.ContainsAny(string(baseName), `/\\`) {
		return nil, fmt.Errorf("invalid encrypted archive base name")
	}
	memory := binary.BigEndian.Uint32(data[21:25])
	iterations := binary.BigEndian.Uint32(data[25:29])
	parallelism := binary.BigEndian.Uint32(data[29:33])
	if memory < 8192 || memory > 1048576 || iterations < 1 || iterations > 10 || parallelism < 1 || parallelism > 16 || memory < 8*parallelism {
		return nil, fmt.Errorf("invalid encrypted archive Argon2 parameters")
	}
	key := argon2.IDKey([]byte(password), data[5:21], iterations, memory, uint8(parallelism), 32)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("key-id"))
	if !hmac.Equal(data[45:53], []byte(hex.EncodeToString(mac.Sum(nil)[:4]))) {
		return nil, fmt.Errorf("invalid password or key id")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return gcm.Open(nil, data[33:45], data[headerLength:], header)
}

func encryptedBackupBaseName(data []byte) (string, error) {
	if len(data) < 55 || string(data[:5]) != "BKUP1" {
		return "", fmt.Errorf("invalid encrypted archive header")
	}
	length := int(binary.BigEndian.Uint16(data[53:55]))
	if length > 255 || len(data) < 55+length {
		return "", fmt.Errorf("invalid encrypted archive base name length")
	}
	name := data[55 : 55+length]
	if !utf8.Valid(name) || strings.ContainsAny(string(name), `/\\`) {
		return "", fmt.Errorf("invalid encrypted archive base name")
	}
	return string(name), nil
}

func encryptedBackupPasswordMatches(data []byte, password string) (bool, error) {
	if len(data) < 55 || string(data[:5]) != "BKUP1" {
		return false, fmt.Errorf("invalid encrypted archive header")
	}
	baseLength := int(binary.BigEndian.Uint16(data[53:55]))
	if baseLength > 255 || len(data) < 55+baseLength {
		return false, fmt.Errorf("invalid encrypted archive header length")
	}
	memory := binary.BigEndian.Uint32(data[21:25])
	iterations := binary.BigEndian.Uint32(data[25:29])
	parallelism := binary.BigEndian.Uint32(data[29:33])
	if memory < 8192 || memory > 1048576 || iterations < 1 || iterations > 10 || parallelism < 1 || parallelism > 16 || memory < 8*parallelism {
		return false, fmt.Errorf("invalid encrypted archive Argon2 parameters")
	}
	key := argon2.IDKey([]byte(password), data[5:21], iterations, memory, uint8(parallelism), 32)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("key-id"))
	return hmac.Equal(data[45:53], []byte(hex.EncodeToString(mac.Sum(nil)[:4]))), nil
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
	protected := incrementalBaseFiles(backupDir)
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

		backups = append(backups, backupFile{path: f, date: date, keep: protected[f]})
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
		path      string
		size      int64
		mod       time.Time
		protected bool
	}
	var files []sizedFile
	var totalBytes int64
	protected := incrementalBaseFiles(backupDir)

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !isApplicationBackup(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, sizedFile{
			path:      filepath.Join(backupDir, name),
			size:      info.Size(),
			mod:       info.ModTime(),
			protected: protected[filepath.Join(backupDir, name)],
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
		if f.protected {
			continue
		}
		if err := os.Remove(f.path); err != nil {
			return fmt.Errorf("remove %s: %w", f.path, err)
		}
		totalBytes -= f.size
	}
	if totalBytes > capBytes {
		log.Printf("WARN: backup.cap_exceeded_protected_base: backup pair exceeds size cap by %d bytes", totalBytes-capBytes)
	}
	return nil
}

func isApplicationBackup(name string) bool {
	return strings.HasPrefix(name, constants.InternalName+"_backup_") || name == constants.InternalName+"-daily.tar.gz" || name == constants.InternalName+"-daily.tar.gz.enc" || name == constants.InternalName+"-hourly.tar.gz" || name == constants.InternalName+"-hourly.tar.gz.enc"
}

func incrementalBaseFiles(backupDir string) map[string]bool {
	protected := make(map[string]bool)
	for _, kind := range []string{"daily", "hourly"} {
		for _, suffix := range []string{".tar.gz", ".tar.gz.enc"} {
			path := filepath.Join(backupDir, constants.InternalName+"-"+kind+suffix)
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			baseName := ""
			if strings.HasSuffix(path, ".enc") {
				baseName, err = encryptedBackupBaseName(data)
			} else {
				var manifest *Manifest
				manifest, err = readArchiveManifest(data)
				if err == nil {
					baseName = manifest.BaseBackup
				}
			}
			if err == nil && baseName != "" && filepath.Base(baseName) == baseName {
				protected[filepath.Join(backupDir, baseName)] = true
			}
		}
	}
	return protected
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

		totalBytes, err := filesystemTotalBytes(backupDir)
		if err != nil {
			return 0, fmt.Errorf("statfs %s: %w", backupDir, err)
		}
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

// CheckBackupDiskSpace enforces the pre-run free-space and disk-usage guard.
func CheckBackupDiskSpace(backupDir string, threshold int) error {
	total, free, used, err := filesystemSpace(backupDir)
	if err != nil {
		return fmt.Errorf("inspect backup filesystem %s: %w", backupDir, err)
	}
	if threshold < 1 || threshold > 100 {
		threshold = 90
	}
	usage := 0
	if total > 0 {
		usage = int(used * 100 / total)
	}
	latest, err := SelectLatestFullBackup(backupDir, constants.InternalName)
	if err != nil && !errors.Is(err, ErrNoFullBackup) {
		return err
	}
	if err == nil {
		info, statErr := os.Stat(latest)
		if statErr != nil {
			return statErr
		}
		if info.Size() > 0 && free < info.Size()*2 {
			return fmt.Errorf("backup.skipped_disk_full: free space %d bytes is less than twice the latest backup size %d bytes", free, info.Size())
		}
	}
	if usage > threshold {
		return fmt.Errorf("backup.skipped_disk_full: disk usage %d%% exceeds threshold %d%%", usage, threshold)
	}
	return nil
}

// CreateIncremental creates an incremental backup (daily or hourly)
// Per AI.md PART 21 specification
func CreateIncremental(opts *BackupOptions, backupType string) error {
	if opts == nil {
		return fmt.Errorf("backup options are required")
	}
	if backupType != "daily" && backupType != "hourly" {
		return fmt.Errorf("unsupported incremental type %q", backupType)
	}
	backupDir := opts.BackupDir
	if backupDir == "" {
		backupDir = filepath.Dir(opts.OutputFile)
	}
	basePath, err := SelectLatestFullBackup(backupDir, constants.InternalName)
	if err != nil {
		return err
	}
	baseInfo, err := os.Stat(basePath)
	if err != nil || !baseInfo.Mode().IsRegular() {
		return fmt.Errorf("incremental base is not a regular file")
	}
	if baseInfo.Size() > 20<<30 {
		return restoreLimitError("base archive exceeds the configured archive size limit")
	}
	if strings.HasSuffix(basePath, ".enc") {
		raw, readErr := os.ReadFile(basePath)
		if readErr != nil {
			return readErr
		}
		matches, matchErr := encryptedBackupPasswordMatches(raw, opts.Password)
		if matchErr != nil {
			return fmt.Errorf("%w: %v", ErrCorruptBackupBase, matchErr)
		}
		if !matches {
			return ErrBackupPasswordChanged
		}
	} else if opts.Password != "" {
		return ErrBackupPasswordChanged
	}
	baseData, baseManifest, err := readBackupArchive(basePath, opts.Password)
	if err != nil {
		return fmt.Errorf("%w: read incremental base: %v", ErrCorruptBackupBase, err)
	}
	if baseManifest.Type != "full" {
		return fmt.Errorf("incremental base is not a full backup")
	}
	_ = baseData

	snapshotAt := opts.SnapshotAt
	if snapshotAt.IsZero() {
		snapshotAt = time.Now().UTC()
	}
	currentOpts := *opts
	currentOpts.SnapshotAt = snapshotAt
	manifest := &Manifest{Version: "1.0.0", CreatedAt: snapshotAt, SnapshotAt: snapshotAt.UTC(), CreatedBy: opts.AdminUser, AppVersion: opts.AppVersion, Contents: []string{}, Encrypted: opts.Password != "", Type: "incremental", BaseBackup: filepath.Base(basePath), BaseChecksum: baseManifest.Checksum}
	if manifest.Encrypted {
		manifest.EncryptionMethod = "AES-256-GCM"
	}
	content, err := buildContentArchive(&currentOpts, manifest)
	if err != nil {
		return err
	}
	manifest.Files, err = fileRecordsFromArchive(content)
	if err != nil {
		return err
	}
	baseRecords := make(map[string]FileRecord, len(baseManifest.Files))
	for _, record := range baseManifest.Files {
		baseRecords[record.Path] = record
	}
	currentRecords := make(map[string]FileRecord, len(manifest.Files))
	for _, record := range manifest.Files {
		currentRecords[record.Path] = record
	}
	include := make(map[string]bool)
	for _, record := range manifest.Files {
		old, ok := baseRecords[record.Path]
		if !ok || old.Size != record.Size || old.MTime != record.MTime || old.SHA256 != record.SHA256 {
			include[record.Path] = true
		}
	}
	for _, record := range baseManifest.Files {
		if _, ok := currentRecords[record.Path]; !ok {
			manifest.Deleted = append(manifest.Deleted, record.Path)
		}
	}
	sort.Strings(manifest.Deleted)
	content, err = filterContentArchive(content, include)
	if err != nil {
		return err
	}
	manifest.Files, err = fileRecordsFromArchive(content)
	if err != nil {
		return err
	}
	manifest.Checksum = checksumFileRecords(manifest.Files)
	finalData, err := buildFinalArchive(&currentOpts, manifest, content)
	if err != nil {
		return err
	}
	if opts.Password != "" {
		finalData, err = encryptBackupWithBase(finalData, opts.Password, filepath.Base(basePath))
		if err != nil {
			return err
		}
	}
	extension := ".tar.gz"
	if opts.Password != "" {
		extension += ".enc"
	}
	if opts.OutputFile == "" {
		opts.OutputFile = filepath.Join(backupDir, "caswhois-"+backupType+extension)
	}
	if err := publishBackupData(opts, finalData); err != nil {
		return err
	}
	return nil
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
