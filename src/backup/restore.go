package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/apimgr/whois/src/common/tempdir"
	"gopkg.in/yaml.v3"
)

// RestoreOptions configures restore behavior
type RestoreOptions struct {
	BackupFile string
	// Password is required when restoring an encrypted backup
	Password  string
	ConfigDir string
	DataDir   string
	Limits    RestoreLimits
	// Force skips interactive confirmation prompts
	Force              bool
	ApplyRemoteRestore func(string, map[string]string) error
}

// RestoreLimits bounds the operator-supplied archive before extraction.
type RestoreLimits struct {
	MaxArchiveSize  string
	MaxExpandedSize string
	MaxFiles        int
	MaxPathLength   int
}

// Restore restores from backup per AI.md PART 21 specification
func Restore(opts *RestoreOptions) error {
	if opts == nil {
		return fmt.Errorf("restore options are required")
	}
	limits, err := effectiveRestoreLimits(opts.Limits)
	if err != nil {
		return err
	}
	// Verify backup file exists
	info, err := os.Stat(opts.BackupFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("backup file not found: %s", opts.BackupFile)
		}
		return fmt.Errorf("stat backup file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("backup file is not a regular file")
	}
	if info.Size() > limits.maxArchiveSize {
		return restoreLimitError("archive size %d bytes exceeds configured maximum %d bytes", info.Size(), limits.maxArchiveSize)
	}

	// Read backup file
	backupData, err := os.ReadFile(opts.BackupFile)
	if err != nil {
		return fmt.Errorf("read backup file: %w", err)
	}

	// Determine if encrypted
	isEncrypted := strings.HasSuffix(opts.BackupFile, ".enc")

	// Decrypt if encrypted
	var archiveData []byte
	if isEncrypted {
		if opts.Password == "" {
			return fmt.Errorf("encrypted backup requires password")
		}

		decrypted, err := decryptBackup(backupData, opts.Password)
		if err != nil {
			return fmt.Errorf("decrypt backup: %w", err)
		}
		archiveData = decrypted
	} else {
		archiveData = backupData
	}
	if err := checkRestoreArchiveLimits(archiveData, limits); err != nil {
		return err
	}

	// Verify checksum
	if err := verifyBackupIntegrity(archiveData); err != nil {
		return fmt.Errorf("backup verification failed: %w", err)
	}

	// Extract to a private staging directory; live files remain untouched until
	// the archive and (when present) its base have both passed verification.
	tempDir, err := tempdir.Create()
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	if err := extractBackup(archiveData, tempDir, limits); err != nil {
		return fmt.Errorf("extract backup: %w", err)
	}

	// Verify manifest
	manifest, err := loadManifest(tempDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}
	if manifest.Type == "incremental" {
		return restoreIncremental(opts, backupData, archiveData, manifest, limits)
	}
	if manifest.Type != "full" {
		return fmt.Errorf("invalid backup type %q", manifest.Type)
	}

	// Perform atomic restore
	if err := performRestore(tempDir, manifest, opts); err != nil {
		return fmt.Errorf("perform restore: %w", err)
	}

	return nil
}

func restoreIncremental(opts *RestoreOptions, rawIncrementalData, incrementalData []byte, manifest *Manifest, limits restoreLimitValues) error {
	baseName := manifest.BaseBackup
	if baseName == "" || filepath.Base(baseName) != baseName || strings.ContainsAny(baseName, `/\\`) {
		return fmt.Errorf("ERR_BASE_CORRUPT: invalid base backup name")
	}
	if strings.HasSuffix(opts.BackupFile, ".enc") {
		headerBase, err := encryptedBackupBaseName(rawIncrementalData)
		if err != nil || headerBase != baseName {
			return fmt.Errorf("ERR_BASE_CORRUPT: encrypted header does not name the manifest base")
		}
	}
	basePath := filepath.Join(filepath.Dir(opts.BackupFile), baseName)
	baseInfo, err := os.Stat(basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("ERR_BASE_MISSING: %s", baseName)
		}
		return fmt.Errorf("stat base backup: %w", err)
	}
	if !baseInfo.Mode().IsRegular() {
		return fmt.Errorf("ERR_BASE_CORRUPT: base backup is not a regular file")
	}
	if baseInfo.Size() > limits.maxArchiveSize {
		return restoreLimitError("base archive size %d bytes exceeds configured maximum %d bytes", baseInfo.Size(), limits.maxArchiveSize)
	}
	baseData, err := os.ReadFile(basePath)
	if err != nil {
		return fmt.Errorf("read base backup: %w", err)
	}
	if strings.HasSuffix(basePath, ".enc") {
		baseData, err = decryptBackup(baseData, opts.Password)
		if err != nil {
			return fmt.Errorf("ERR_BASE_CORRUPT: decrypt base backup: %w", err)
		}
	} else if strings.HasSuffix(opts.BackupFile, ".enc") {
		return fmt.Errorf("ERR_BASE_CORRUPT: incremental and base encryption do not match")
	}
	baseMetrics, err := inspectRestoreArchive(baseData)
	if err != nil {
		return fmt.Errorf("ERR_BASE_CORRUPT: %w", err)
	}
	incrementalMetrics, err := inspectRestoreArchive(incrementalData)
	if err != nil {
		return err
	}
	if baseMetrics.entries > limits.maxFiles-incrementalMetrics.entries {
		return restoreLimitError("combined base and incremental have more than %d entries", limits.maxFiles)
	}
	if incrementalMetrics.expanded > limits.maxExpandedSize-baseMetrics.expanded {
		return restoreLimitError("combined base and incremental exceed %d expanded bytes", limits.maxExpandedSize)
	}
	if max(baseMetrics.maxPathLength, incrementalMetrics.maxPathLength) > limits.maxPathLength {
		return restoreLimitError("combined base and incremental exceed %d path bytes", limits.maxPathLength)
	}
	if err := verifyBackupIntegrity(baseData); err != nil {
		return fmt.Errorf("ERR_BASE_CORRUPT: %w", err)
	}
	baseDir, err := tempdir.Create()
	if err != nil {
		return fmt.Errorf("create base staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(baseDir) }()
	if err := extractBackup(baseData, baseDir, limits); err != nil {
		return fmt.Errorf("ERR_BASE_CORRUPT: extract base: %w", err)
	}
	baseManifest, err := loadManifest(baseDir)
	if err != nil || baseManifest.Type != "full" {
		return fmt.Errorf("ERR_BASE_CORRUPT: base manifest is not a full backup")
	}
	if manifest.BaseChecksum == "" || baseManifest.Checksum != manifest.BaseChecksum {
		return fmt.Errorf("ERR_BASE_CORRUPT: base checksum mismatch")
	}
	mergedDir, err := tempdir.Create()
	if err != nil {
		return fmt.Errorf("create combined staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(mergedDir) }()
	if err := copyDir(baseDir, mergedDir); err != nil {
		return fmt.Errorf("stage base backup: %w", err)
	}
	if err := extractBackup(incrementalData, mergedDir, limits); err != nil {
		return fmt.Errorf("extract incremental backup: %w", err)
	}
	for _, deleted := range manifest.Deleted {
		if deleted == "manifest.json" || !safeRestoreArchivePath(deleted) {
			return fmt.Errorf("ERR_BASE_CORRUPT: invalid deleted path %q", deleted)
		}
		if err := os.RemoveAll(filepath.Join(mergedDir, filepath.FromSlash(deleted))); err != nil {
			return fmt.Errorf("delete removed path %q: %w", deleted, err)
		}
	}
	if err := performRestore(mergedDir, manifest, opts); err != nil {
		return fmt.Errorf("perform restore: %w", err)
	}
	return nil
}

func applyRestoredAppSecrets(backupDir string, opts *RestoreOptions) error {
	if opts.ApplyRemoteRestore == nil {
		return nil
	}
	secrets := map[string]string{}
	data, err := os.ReadFile(filepath.Join(backupDir, "app_secrets.json"))
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read app_secrets.json: %w", err)
		}
	} else if err := json.Unmarshal(data, &secrets); err != nil {
		return fmt.Errorf("parse app_secrets.json: %w", err)
	}
	if err := opts.ApplyRemoteRestore(filepath.Join(backupDir, "server.db"), secrets); err != nil {
		return fmt.Errorf("restore remote database: %w", err)
	}
	return nil
}

type restoreLimitValues struct {
	maxArchiveSize  int64
	maxExpandedSize int64
	maxFiles        int
	maxPathLength   int
}

func effectiveRestoreLimits(configured RestoreLimits) (restoreLimitValues, error) {
	archiveSize := configured.MaxArchiveSize
	if strings.TrimSpace(archiveSize) == "" {
		archiveSize = "20GB"
	}
	expandedSize := configured.MaxExpandedSize
	if strings.TrimSpace(expandedSize) == "" {
		expandedSize = "50GB"
	}
	maxArchive, err := parseRestoreSize(archiveSize)
	if err != nil {
		return restoreLimitValues{}, fmt.Errorf("invalid restore max_archive_size: %w", err)
	}
	maxExpanded, err := parseRestoreSize(expandedSize)
	if err != nil {
		return restoreLimitValues{}, fmt.Errorf("invalid restore max_expanded_size: %w", err)
	}
	maxFiles := configured.MaxFiles
	if maxFiles < 1 {
		maxFiles = 1000000
	}
	maxPathLength := configured.MaxPathLength
	if maxPathLength < 1 {
		maxPathLength = 4096
	}
	return restoreLimitValues{
		maxArchiveSize:  maxArchive,
		maxExpandedSize: maxExpanded,
		maxFiles:        maxFiles,
		maxPathLength:   maxPathLength,
	}, nil
}

func parseRestoreSize(value string) (int64, error) {
	value = strings.TrimSpace(strings.ToUpper(value))
	units := []struct {
		suffix string
		factor int64
	}{
		{"TB", 1 << 40}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10},
		{"T", 1 << 40}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}, {"B", 1},
	}
	for _, unit := range units {
		if strings.HasSuffix(value, unit.suffix) {
			number := strings.TrimSpace(strings.TrimSuffix(value, unit.suffix))
			parsed, err := strconv.ParseInt(number, 10, 64)
			if err != nil || parsed < 1 || parsed > int64(^uint64(0)>>1)/unit.factor {
				return 0, fmt.Errorf("invalid positive size %q", value)
			}
			return parsed * unit.factor, nil
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 1 {
		return 0, fmt.Errorf("invalid positive size %q", value)
	}
	return parsed, nil
}

func restoreLimitError(format string, args ...any) error {
	return fmt.Errorf("ERR_RESTORE_LIMIT: "+format, args...)
}

func checkRestoreArchiveLimits(data []byte, limits restoreLimitValues) error {
	metrics, err := inspectRestoreArchive(data)
	if err != nil {
		return err
	}
	if metrics.entries > limits.maxFiles {
		return restoreLimitError("archive has more than %d entries", limits.maxFiles)
	}
	if metrics.maxPathLength > limits.maxPathLength {
		return restoreLimitError("entry path is %d bytes; maximum is %d", metrics.maxPathLength, limits.maxPathLength)
	}
	if metrics.expanded > limits.maxExpandedSize {
		return restoreLimitError("expanded archive exceeds %d bytes", limits.maxExpandedSize)
	}
	return nil
}

type restoreArchiveMetrics struct {
	entries       int
	expanded      int64
	maxPathLength int
}

func inspectRestoreArchive(data []byte) (restoreArchiveMetrics, error) {
	var metrics restoreArchiveMetrics
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return metrics, fmt.Errorf("invalid backup format: %w", err)
	}
	defer func() { _ = gz.Close() }()
	archive := tar.NewReader(gz)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return metrics, fmt.Errorf("read backup entry: %w", err)
		}
		metrics.entries++
		if len(header.Name) > metrics.maxPathLength {
			metrics.maxPathLength = len(header.Name)
		}
		if !safeRestoreArchivePath(header.Name) {
			return metrics, fmt.Errorf("invalid archive path: %q", header.Name)
		}
		if header.Mode&06000 != 0 {
			return metrics, fmt.Errorf("archive entry has setuid or setgid bits: %q", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 {
				return metrics, fmt.Errorf("directory entry has content: %q", header.Name)
			}
		case tar.TypeReg:
			if header.Size < 0 || metrics.expanded > int64(^uint64(0)>>1)-header.Size {
				return metrics, restoreLimitError("expanded archive size overflow")
			}
			metrics.expanded += header.Size
		default:
			return metrics, fmt.Errorf("unsupported archive entry type for %q", header.Name)
		}
	}
	return metrics, nil
}

func safeRestoreArchivePath(name string) bool {
	if name == "" || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || filepath.IsAbs(name) || !filepath.IsLocal(name) {
		return false
	}
	if len(name) >= 2 && ((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z')) && name[1] == ':' {
		return false
	}
	clean := path.Clean(name)
	return clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

// decryptBackup decrypts backup data using AES-256-GCM with Argon2id key derivation
// Per AI.md PART 21 specification
func decryptBackup(data []byte, password string) ([]byte, error) {
	return decryptBackupData(data, password)
}

// verifyBackupIntegrity verifies the backup archive against the checksum stored
// in its manifest, matching how Create computes it (content-only archive, no
// manifest.json). Returns an error on any mismatch or unreadable manifest.
func verifyBackupIntegrity(data []byte) error {
	// Extract the manifest to obtain the expected checksum.
	tempDir, err := tempdir.Create()
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	if err := extractTarGz(data, tempDir); err != nil {
		return fmt.Errorf("extract archive: %w", err)
	}

	manifest, err := loadManifest(tempDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	// Reconstruct the content-only archive (excluding manifest.json) and hash it,
	// matching how Create derives the stored checksum.
	contentBuf, err := rebuildContentArchive(data)
	if err != nil {
		return fmt.Errorf("rebuild content archive for checksum: %w", err)
	}
	records, err := fileRecordsFromArchive(contentBuf)
	if err != nil {
		return fmt.Errorf("read content records: %w", err)
	}
	calculatedChecksum := checksumFileRecords(records)
	if (manifest.Type != "incremental" && len(manifest.Files) == 0) || !sameFileRecords(manifest.Files, records) {
		return fmt.Errorf("manifest file records do not match archive contents")
	}

	if manifest.Checksum != calculatedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", manifest.Checksum, calculatedChecksum)
	}

	return nil
}

// extractBackup extracts tar.gz backup to directory
func extractBackup(data []byte, destDir string, limits restoreLimitValues) error {
	// Create gzip reader
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer func() { _ = gr.Close() }()

	// Create tar reader
	tr := tar.NewReader(gr)
	files := 0
	var expanded int64

	// Extract all files
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}

		if !safeRestoreArchivePath(header.Name) {
			return fmt.Errorf("invalid archive path: %q", header.Name)
		}
		files++
		if files > limits.maxFiles {
			return restoreLimitError("archive has more than %d entries", limits.maxFiles)
		}
		if len(header.Name) > limits.maxPathLength {
			return restoreLimitError("entry path is %d bytes; maximum is %d", len(header.Name), limits.maxPathLength)
		}
		// Construct destination path
		target := filepath.Join(destDir, header.Name)

		// Prevent path traversal
		if !strings.HasPrefix(target, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid file path: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0700); err != nil {
				return fmt.Errorf("create directory %s: %w", target, err)
			}

		case tar.TypeReg:
			if header.Size < 0 || expanded > limits.maxExpandedSize-header.Size {
				return restoreLimitError("expanded archive exceeds %d bytes", limits.maxExpandedSize)
			}
			// Create parent directory
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("create parent directory for %s: %w", target, err)
			}

			// Create file
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}
			// Copy content
			written, err := io.CopyN(f, tr, header.Size)
			if err == nil && written != header.Size {
				err = io.ErrUnexpectedEOF
			}
			if err != nil {
				_ = f.Close()
				return fmt.Errorf("write file %s: %w", target, err)
			}
			expanded += written
			if err := f.Chmod(0600); err != nil {
				_ = f.Close()
				return fmt.Errorf("set safe mode for %s: %w", target, err)
			}
			_ = f.Close()

		default:
			return fmt.Errorf("unsupported archive entry type for %q", header.Name)
		}
	}

	return nil
}

// loadManifest loads and parses manifest.json
func loadManifest(backupDir string) (*Manifest, error) {
	manifestPath := filepath.Join(backupDir, "manifest.json")

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	return &manifest, nil
}

// performRestore atomically restores files from backup
func performRestore(backupDir string, manifest *Manifest, opts *RestoreOptions) error {
	type action struct {
		source, target, stage, backup     string
		directory, hadOriginal, installed bool
	}
	var actions []action
	var createdParents []string
	cleanupStages := func(items []action, cause error) error {
		for _, item := range items {
			_ = os.RemoveAll(filepath.Dir(item.stage))
		}
		return cause
	}
	rollback := func(items []action, cause error) error {
		var rollbackErrors []error
		for i := len(items) - 1; i >= 0; i-- {
			item := items[i]
			if item.installed {
				if err := os.RemoveAll(item.target); err != nil {
					rollbackErrors = append(rollbackErrors, err)
				}
			}
			if item.hadOriginal {
				if err := os.Rename(item.backup, item.target); err != nil {
					rollbackErrors = append(rollbackErrors, err)
				}
			}
		}
		for _, item := range items {
			_ = os.RemoveAll(filepath.Dir(item.stage))
		}
		for i := len(createdParents) - 1; i >= 0; i-- {
			_ = os.Remove(createdParents[i])
		}
		return errors.Join(append([]error{cause}, rollbackErrors...)...)
	}
	add := func(source, target string, directory bool) error {
		if directory && !dirExists(source) || !directory && !fileExists(source) {
			return nil
		}
		parent := filepath.Dir(target)
		if target == opts.DataDir || strings.HasPrefix(target, filepath.Clean(opts.DataDir)+string(os.PathSeparator)) {
			parent = filepath.Dir(opts.DataDir)
		}
		if err := os.MkdirAll(parent, 0700); err != nil {
			return err
		}
		if info, err := os.Lstat(target); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to replace symlink %s", target)
		} else if err != nil && !os.IsNotExist(err) {
			return err
		}
		tmp, err := os.MkdirTemp(parent, ".restore-stage-*")
		if err != nil {
			return err
		}
		stage := filepath.Join(tmp, filepath.Base(target))
		if directory {
			if err := copyDir(source, stage); err != nil {
				_ = os.RemoveAll(tmp)
				return err
			}
		} else if filepath.Base(target) == "secrets.yml" {
			if err := restoreSecretsFileWithCurrentAndDatabase(source, stage, target, filepath.Join(opts.ConfigDir, "server.yml")); err != nil {
				_ = os.RemoveAll(tmp)
				return err
			}
		} else if filepath.Base(target) == "server.yml" {
			if err := restoreServerConfig(source, stage, backupDir, opts.ConfigDir); err != nil {
				_ = os.RemoveAll(tmp)
				return err
			}
		} else if err := copyFile(source, stage); err != nil {
			_ = os.RemoveAll(tmp)
			return err
		}
		actions = append(actions, action{source: source, target: target, stage: stage, backup: filepath.Join(tmp, ".previous"), directory: directory})
		return nil
	}
	entries := []struct {
		source, target string
		directory      bool
	}{
		{filepath.Join(backupDir, "server.yml"), filepath.Join(opts.ConfigDir, "server.yml"), false},
		{filepath.Join(backupDir, "secrets.yml"), filepath.Join(opts.ConfigDir, "secrets.yml"), false},
		{filepath.Join(backupDir, "yaml.d"), filepath.Join(opts.ConfigDir, "yaml.d"), true},
		{filepath.Join(backupDir, "assets"), filepath.Join(opts.ConfigDir, "assets"), true},
		{filepath.Join(backupDir, "server.db"), filepath.Join(opts.DataDir, "server.db"), false},
		{filepath.Join(backupDir, "users.db"), filepath.Join(opts.DataDir, "users.db"), false},
		{filepath.Join(backupDir, "template"), filepath.Join(opts.ConfigDir, "template"), true},
		{filepath.Join(backupDir, "theme"), filepath.Join(opts.ConfigDir, "theme"), true},
	}
	for _, entry := range entries {
		if err := add(entry.source, entry.target, entry.directory); err != nil {
			return cleanupStages(actions, err)
		}
	}
	sslSource := filepath.Join(backupDir, "ssl")
	externalTLS := filepath.Join(backupDir, "ssl-external")
	if dirExists(externalTLS) {
		prepared, err := tempdir.Create()
		if err != nil {
			return cleanupStages(actions, err)
		}
		if dirExists(sslSource) {
			if err := copyDir(sslSource, prepared); err != nil {
				_ = os.RemoveAll(prepared)
				return cleanupStages(actions, err)
			}
		}
		if err := copyDir(externalTLS, prepared); err != nil {
			_ = os.RemoveAll(prepared)
			return cleanupStages(actions, err)
		}
		sslSource = prepared
		defer func() { _ = os.RemoveAll(prepared) }()
	}
	if dirExists(sslSource) {
		if err := add(sslSource, filepath.Join(opts.ConfigDir, "ssl"), true); err != nil {
			return cleanupStages(actions, err)
		}
	}
	dataSource := filepath.Join(backupDir, "data")
	if dirExists(dataSource) {
		if info, err := os.Lstat(opts.DataDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return cleanupStages(actions, fmt.Errorf("refusing to replace symlink %s", opts.DataDir))
		} else if err != nil && !os.IsNotExist(err) {
			return cleanupStages(actions, err)
		}
		parent := filepath.Dir(opts.DataDir)
		tmp, err := os.MkdirTemp(parent, ".restore-stage-*")
		if err != nil {
			return cleanupStages(actions, err)
		}
		stage := filepath.Join(tmp, filepath.Base(opts.DataDir))
		if dirExists(opts.DataDir) {
			if err := copyDir(opts.DataDir, stage); err != nil {
				_ = os.RemoveAll(tmp)
				return cleanupStages(actions, err)
			}
		} else if err := os.Mkdir(stage, 0700); err != nil {
			_ = os.RemoveAll(tmp)
			return cleanupStages(actions, err)
		}
		if err := copyDir(dataSource, stage); err != nil {
			_ = os.RemoveAll(tmp)
			return cleanupStages(actions, err)
		}
		actions = append(actions, action{source: dataSource, target: opts.DataDir, stage: stage, backup: filepath.Join(tmp, ".previous"), directory: true})
	}
	for i := range actions {
		if actions[i].target == opts.DataDir && actions[i].directory {
			dataAction := actions[i]
			copy(actions[1:i+1], actions[0:i])
			actions[0] = dataAction
			break
		}
	}
	for i := range actions {
		item := &actions[i]
		parent := filepath.Dir(item.target)
		if _, err := os.Lstat(parent); os.IsNotExist(err) {
			if err := os.MkdirAll(parent, 0700); err != nil {
				return rollback(actions[:i], fmt.Errorf("create restore target directory %s: %w", parent, err))
			}
			createdParents = append(createdParents, parent)
		} else if err != nil {
			return rollback(actions[:i], fmt.Errorf("inspect restore target directory %s: %w", parent, err))
		}
		if _, err := os.Lstat(item.target); err == nil {
			if err := os.Rename(item.target, item.backup); err != nil {
				return rollback(actions[:i], fmt.Errorf("stage existing %s: %w", item.target, err))
			}
			item.hadOriginal = true
		} else if !os.IsNotExist(err) {
			return rollback(actions[:i], err)
		}
		if err := os.Rename(item.stage, item.target); err != nil {
			return rollback(actions[:i+1], fmt.Errorf("install restored %s: %w", item.target, err))
		}
		item.installed = true
	}
	if err := applyRestoredAppSecrets(backupDir, opts); err != nil {
		return rollback(actions, err)
	}
	for _, item := range actions {
		if item.hadOriginal {
			if err := os.RemoveAll(item.backup); err != nil {
				return fmt.Errorf("remove restore rollback data: %w", err)
			}
		}
		_ = os.RemoveAll(filepath.Dir(item.stage))
	}
	return nil
}

func restoreServerConfig(source, destination, backupDir, configDir string) error {
	externalDir := filepath.Join(backupDir, "ssl-external")
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parse restored server.yml: %w", err)
	}
	if root == nil {
		root = make(map[string]any)
	}
	server, _ := root["server"].(map[string]any)
	if server == nil {
		server = make(map[string]any)
		root["server"] = server
	}
	if currentData, err := os.ReadFile(filepath.Join(configDir, "server.yml")); err == nil {
		var current map[string]any
		if err := yaml.Unmarshal(currentData, &current); err != nil {
			return fmt.Errorf("parse destination server.yml: %w", err)
		}
		if currentServer, ok := current["server"].(map[string]any); ok {
			if currentDatabase, ok := currentServer["database"].(map[string]any); ok && remoteDatabaseConfigured(currentDatabase) {
				server["database"] = currentDatabase
			}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read destination server.yml: %w", err)
	}
	if dirExists(externalDir) {
		ssl, _ := server["ssl"].(map[string]any)
		if ssl == nil {
			ssl = make(map[string]any)
			server["ssl"] = ssl
		}
		for _, name := range []string{"cert.pem", "key.pem"} {
			if fileExists(filepath.Join(externalDir, name)) {
				key := strings.TrimSuffix(name, ".pem")
				ssl[key] = filepath.Join(configDir, "ssl", name)
			}
		}
	}
	data, err = yaml.Marshal(root)
	if err != nil {
		return err
	}
	if err := os.WriteFile(destination, data, 0600); err != nil {
		return err
	}
	return nil
}

func remoteDatabaseConfigured(database map[string]any) bool {
	driver, _ := database["driver"].(string)
	driver = strings.ToLower(strings.TrimSpace(driver))
	_, hasURL := database["url"]
	url, _ := database["url"].(string)
	return driver == "libsql" || driver == "turso" || hasURL && strings.TrimSpace(url) != ""
}

func restoreSecretsFileWithCurrentAndDatabase(backupPath, destinationPath, currentSecretsPath, currentConfigPath string) error {
	if err := restoreSecretsFileWithCurrent(backupPath, destinationPath, currentSecretsPath); err != nil {
		return err
	}
	configData, err := os.ReadFile(currentConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read destination server.yml: %w", err)
	}
	var currentConfig map[string]any
	if err := yaml.Unmarshal(configData, &currentConfig); err != nil {
		return fmt.Errorf("parse destination server.yml: %w", err)
	}
	currentServer, _ := currentConfig["server"].(map[string]any)
	currentDatabase, _ := currentServer["database"].(map[string]any)
	if !remoteDatabaseConfigured(currentDatabase) {
		return nil
	}
	currentData, err := os.ReadFile(currentSecretsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read destination secrets: %w", err)
	}
	var currentSecrets map[string]any
	if err := yaml.Unmarshal(currentData, &currentSecrets); err != nil {
		return fmt.Errorf("parse destination secrets: %w", err)
	}
	currentSecretServer, _ := currentSecrets["server"].(map[string]any)
	currentSecretDatabase, _ := currentSecretServer["database"].(map[string]any)
	if len(currentSecretDatabase) == 0 {
		return nil
	}
	restoredData, err := os.ReadFile(destinationPath)
	if err != nil {
		return err
	}
	var restored map[string]any
	if err := yaml.Unmarshal(restoredData, &restored); err != nil {
		return fmt.Errorf("parse restored secrets: %w", err)
	}
	if restored == nil {
		restored = make(map[string]any)
	}
	restoredServer, _ := restored["server"].(map[string]any)
	if restoredServer == nil {
		restoredServer = make(map[string]any)
		restored["server"] = restoredServer
	}
	restoredServer["database"] = currentSecretDatabase
	data, err := yaml.Marshal(restored)
	if err != nil {
		return err
	}
	if err := os.WriteFile(destinationPath, data, 0600); err != nil {
		return err
	}
	return os.Chmod(destinationPath, 0600)
}

func restoreSecretsFile(backupPath, destinationPath string) error {
	return restoreSecretsFileWithCurrent(backupPath, destinationPath, destinationPath)
}

func restoreSecretsFileWithCurrent(backupPath, destinationPath, currentPath string) error {
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	var restored map[string]any
	if err := yaml.Unmarshal(backupData, &restored); err != nil {
		return fmt.Errorf("parse backup secrets: %w", err)
	}
	if restored == nil {
		restored = make(map[string]any)
	}

	if destinationData, readErr := os.ReadFile(currentPath); readErr == nil {
		var current struct {
			Server struct {
				Token  string `yaml:"token"`
				Backup struct {
					EncryptionPassword string `yaml:"encryption_password"`
				} `yaml:"backup"`
			} `yaml:"server"`
		}
		if err := yaml.Unmarshal(destinationData, &current); err != nil {
			return fmt.Errorf("parse destination secrets: %w", err)
		}
		if current.Server.Token != "" {
			server, ok := restored["server"].(map[string]any)
			if !ok {
				server = make(map[string]any)
				restored["server"] = server
			}
			server["token"] = current.Server.Token
		}
		if current.Server.Backup.EncryptionPassword != "" {
			server, ok := restored["server"].(map[string]any)
			if !ok {
				server = make(map[string]any)
				restored["server"] = server
			}
			backup, ok := server["backup"].(map[string]any)
			if !ok {
				backup = make(map[string]any)
				server["backup"] = backup
			}
			backup["encryption_password"] = current.Server.Backup.EncryptionPassword
		}
	} else if !os.IsNotExist(readErr) {
		return fmt.Errorf("read destination secrets: %w", readErr)
	}

	data, err := yaml.Marshal(restored)
	if err != nil {
		return fmt.Errorf("encode restored secrets: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(destinationPath), 0700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := os.WriteFile(destinationPath, data, 0600); err != nil {
		return err
	}
	return os.Chmod(destinationPath, 0600)
}

// Helper functions

func copyFile(src, dst string) error {
	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("create destination directory: %w", err)
	}

	// Open source
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer func() { _ = srcFile.Close() }()

	// Create destination
	dstFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	defer func() { _ = dstFile.Close() }()

	// Copy content
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("copy content: %w", err)
	}

	// Copy permissions
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}

	if err := os.Chmod(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("set permissions: %w", err)
	}

	return nil
}

func copyDir(src, dst string) error {
	// Ensure destination exists
	if err := os.MkdirAll(dst, 0755); err != nil {
		return fmt.Errorf("create destination directory: %w", err)
	}

	// Walk source directory
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		return copyFile(path, dstPath)
	})
}
