package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
)

// RestoreOptions configures restore behavior
type RestoreOptions struct {
	BackupFile string
	// Password is required when restoring an encrypted backup
	Password   string
	ConfigDir  string
	DataDir    string
	// Force skips interactive confirmation prompts
	Force      bool
}

// Restore restores from backup per AI.md PART 21 specification
func Restore(opts *RestoreOptions) error {
	// Verify backup file exists
	if !fileExists(opts.BackupFile) {
		return fmt.Errorf("backup file not found: %s", opts.BackupFile)
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

	// Verify checksum
	if err := verifyBackupIntegrity(archiveData); err != nil {
		return fmt.Errorf("backup verification failed: %w", err)
	}

	// Extract to temporary directory
	tempDir, err := os.MkdirTemp("", "caswhois-restore-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	if err := extractBackup(archiveData, tempDir); err != nil {
		return fmt.Errorf("extract backup: %w", err)
	}

	// Verify manifest
	manifest, err := loadManifest(tempDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	// Perform atomic restore
	if err := performRestore(tempDir, manifest, opts); err != nil {
		return fmt.Errorf("perform restore: %w", err)
	}

	return nil
}

// decryptBackup decrypts backup data using AES-256-GCM with Argon2id key derivation
// Per AI.md PART 21 specification
func decryptBackup(data []byte, password string) ([]byte, error) {
	// Extract salt (first 32 bytes)
	if len(data) < 32 {
		return nil, fmt.Errorf("invalid encrypted backup: too short")
	}

	salt := data[:32]
	ciphertext := data[32:]

	// Derive key using Argon2id (same parameters as encryption)
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

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("invalid encrypted backup: ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w (invalid password?)", err)
	}

	return plaintext, nil
}

// verifyBackupIntegrity verifies the backup archive against the checksum stored
// in its manifest, matching how Create computes it (content-only archive, no
// manifest.json). Returns an error on any mismatch or unreadable manifest.
func verifyBackupIntegrity(data []byte) error {
	// Extract the manifest to obtain the expected checksum.
	tempDir, err := os.MkdirTemp("", "caswhois-verify-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

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
	checksum := sha256.Sum256(contentBuf)
	calculatedChecksum := "sha256:" + hex.EncodeToString(checksum[:])

	if manifest.Checksum != calculatedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", manifest.Checksum, calculatedChecksum)
	}

	return nil
}

// extractBackup extracts tar.gz backup to directory
func extractBackup(data []byte, destDir string) error {
	// Create gzip reader
	gr, err := gzip.NewReader(strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer gr.Close()

	// Create tar reader
	tr := tar.NewReader(gr)

	// Extract all files
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}

		// Construct destination path
		target := filepath.Join(destDir, header.Name)

		// Prevent path traversal
		if !strings.HasPrefix(target, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid file path: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("create directory %s: %w", target, err)
			}

		case tar.TypeReg:
			// Create parent directory
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("create parent directory for %s: %w", target, err)
			}

			// Create file
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}

			// Copy content
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("write file %s: %w", target, err)
			}
			f.Close()

		default:
			// Skip unknown types
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
	// Restore server.yml
	serverYML := filepath.Join(backupDir, "server.yml")
	if fileExists(serverYML) {
		destPath := filepath.Join(opts.ConfigDir, "server.yml")
		if err := copyFile(serverYML, destPath); err != nil {
			return fmt.Errorf("restore server.yml: %w", err)
		}
	}

	// Restore server.db
	serverDB := filepath.Join(backupDir, "server.db")
	if fileExists(serverDB) {
		destPath := filepath.Join(opts.DataDir, "server.db")
		if err := copyFile(serverDB, destPath); err != nil {
			return fmt.Errorf("restore server.db: %w", err)
		}
	}

	// Restore users.db if exists
	usersDB := filepath.Join(backupDir, "users.db")
	if fileExists(usersDB) {
		destPath := filepath.Join(opts.DataDir, "users.db")
		if err := copyFile(usersDB, destPath); err != nil {
			return fmt.Errorf("restore users.db: %w", err)
		}
	}

	// Restore templates if exist
	templatesDir := filepath.Join(backupDir, "template")
	if dirExists(templatesDir) {
		destPath := filepath.Join(opts.ConfigDir, "template")
		if err := copyDir(templatesDir, destPath); err != nil {
			return fmt.Errorf("restore templates: %w", err)
		}
	}

	// Restore themes if exist
	themesDir := filepath.Join(backupDir, "theme")
	if dirExists(themesDir) {
		destPath := filepath.Join(opts.ConfigDir, "theme")
		if err := copyDir(themesDir, destPath); err != nil {
			return fmt.Errorf("restore themes: %w", err)
		}
	}

	// Restore SSL if exist
	sslDir := filepath.Join(backupDir, "ssl")
	if dirExists(sslDir) {
		destPath := filepath.Join(opts.ConfigDir, "ssl")
		if err := copyDir(sslDir, destPath); err != nil {
			return fmt.Errorf("restore ssl: %w", err)
		}
	}

	// Restore data directory if exist
	dataDir := filepath.Join(backupDir, "data")
	if dirExists(dataDir) {
		if err := copyDir(dataDir, opts.DataDir); err != nil {
			return fmt.Errorf("restore data: %w", err)
		}
	}

	return nil
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
	defer srcFile.Close()

	// Create destination
	dstFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	defer dstFile.Close()

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
