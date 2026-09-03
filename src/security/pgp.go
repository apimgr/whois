package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	pgpcrypto "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	// PGPPublicKeyFile is the filename for the ASCII-armored public key
	PGPPublicKeyFile = "pgp.pub.asc"
	// PGPPrivateKeyFile is the filename for the encrypted ASCII-armored private key
	PGPPrivateKeyFile = "pgp.priv.asc.enc"
	// pgpSecurityDir is the subdirectory under configDir for pgp keys
	pgpSecurityDir = "security"
	// pgpKeyExpirySecs is 2 years in seconds
	pgpKeyExpirySecs = uint32(2 * 365 * 24 * 3600)
)

// pgpSecDir returns {configDir}/security
func pgpSecDir(configDir string) string {
	return filepath.Join(configDir, pgpSecurityDir)
}

// PGPKeypairExists returns true if both key files exist under configDir.
func PGPKeypairExists(configDir string) bool {
	dir := pgpSecDir(configDir)
	_, errPub := os.Stat(filepath.Join(dir, PGPPublicKeyFile))
	_, errPriv := os.Stat(filepath.Join(dir, PGPPrivateKeyFile))
	return errPub == nil && errPriv == nil
}

// GeneratePGPKeypair creates a new Ed25519+Curve25519 keypair.
// The public key is written to {configDir}/security/pgp.pub.asc.
// The private key is AES-256-GCM encrypted with a key derived from installationSecret
// and written to {configDir}/security/pgp.priv.asc.enc.
func GeneratePGPKeypair(configDir, appName, contactEmail, installationSecret string) error {
	if configDir == "" {
		return errors.New("configDir must not be empty")
	}
	if contactEmail == "" {
		contactEmail = "security@localhost"
	}
	identity := appName + " Security"

	cfg := &packet.Config{
		DefaultHash:            8,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		KeyLifetimeSecs:        pgpKeyExpirySecs,
	}

	entity, err := pgpcrypto.NewEntity(identity, "", contactEmail, cfg)
	if err != nil {
		return fmt.Errorf("generate pgp entity: %w", err)
	}

	dir := pgpSecDir(configDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create security dir: %w", err)
	}

	if err := writePublicKey(entity, filepath.Join(dir, PGPPublicKeyFile)); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	if err := writeEncryptedPrivateKey(entity, filepath.Join(dir, PGPPrivateKeyFile), installationSecret); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	return nil
}

// RotatePGPKeypair generates a new keypair, preserving the old one for 30 days.
// Old key files are renamed with a .old suffix and timestamp.
func RotatePGPKeypair(configDir, appName, contactEmail, installationSecret string) error {
	dir := pgpSecDir(configDir)

	// Archive old keys if they exist
	if PGPKeypairExists(configDir) {
		suffix := fmt.Sprintf(".old.%d", time.Now().Unix())
		for _, name := range []string{PGPPublicKeyFile, PGPPrivateKeyFile} {
			src := filepath.Join(dir, name)
			dst := src + suffix
			if err := os.Rename(src, dst); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("archive old key %s: %w", name, err)
			}
		}
	}

	return GeneratePGPKeypair(configDir, appName, contactEmail, installationSecret)
}

// PublishPGPKey HTTP-POSTs the ASCII-armored public key to each keyserver URL.
// Uses the keys.openpgp.org VKS v1 upload endpoint format.
func PublishPGPKey(configDir string, keyservers []string) error {
	pubPath := filepath.Join(pgpSecDir(configDir), PGPPublicKeyFile)
	pubKey, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}

	if len(keyservers) == 0 {
		keyservers = []string{"https://keys.openpgp.org/vks/v1/upload"}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	var errs []error
	for _, ks := range keyservers {
		resp, err := client.Post(ks, "application/pgp-keys", bytes.NewReader(pubKey))
		if err != nil {
			errs = append(errs, fmt.Errorf("POST %s: %w", ks, err))
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			errs = append(errs, fmt.Errorf("POST %s: HTTP %d", ks, resp.StatusCode))
		}
	}

	if len(errs) > 0 {
		var combined error
		for _, e := range errs {
			if combined == nil {
				combined = e
			} else {
				combined = fmt.Errorf("%w; %v", combined, e)
			}
		}
		return combined
	}
	return nil
}

// ExportPGPPublicKey writes the ASCII-armored public key to outPath (stdout if "-").
func ExportPGPPublicKey(configDir, outPath string) error {
	pubPath := filepath.Join(pgpSecDir(configDir), PGPPublicKeyFile)
	data, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}

	if outPath == "" || outPath == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}

	if err := os.WriteFile(outPath, data, 0644); err != nil {
		return fmt.Errorf("write public key to %s: %w", outPath, err)
	}
	return nil
}

// ExportPGPPrivateKey decrypts the private key and writes it to outPath.
// Requires installationSecret for decryption.
// outPath must be an explicit file path (not "-") to avoid accidental leaks.
func ExportPGPPrivateKey(configDir, outPath, installationSecret string) error {
	if outPath == "" || outPath == "-" {
		return errors.New("export private: output path must be an explicit file path, not stdout")
	}

	encPath := filepath.Join(pgpSecDir(configDir), PGPPrivateKeyFile)
	plaintext, err := decryptPrivateKey(encPath, installationSecret)
	if err != nil {
		return fmt.Errorf("decrypt private key: %w", err)
	}

	if err := os.WriteFile(outPath, plaintext, 0600); err != nil {
		return fmt.Errorf("write private key to %s: %w", outPath, err)
	}
	return nil
}

// ImportPGPPrivateKey reads an existing ASCII-armored private key from keyFile,
// re-encrypts it with installationSecret, and stores it under configDir.
// The matching public key is also extracted and stored.
func ImportPGPPrivateKey(configDir, keyFile, installationSecret string) error {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}

	el, err := pgpcrypto.ReadArmoredKeyRing(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("parse armored key ring: %w", err)
	}
	if len(el) == 0 {
		return errors.New("no keys found in key file")
	}

	entity := el[0]
	dir := pgpSecDir(configDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create security dir: %w", err)
	}

	if err := writePublicKey(entity, filepath.Join(dir, PGPPublicKeyFile)); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	if err := writeEncryptedPrivateKey(entity, filepath.Join(dir, PGPPrivateKeyFile), installationSecret); err != nil {
		return fmt.Errorf("write encrypted private key: %w", err)
	}

	return nil
}

// DeletePGPKeypair removes both key files under {configDir}/security/.
func DeletePGPKeypair(configDir string) error {
	dir := pgpSecDir(configDir)
	var errs []error
	for _, name := range []string{PGPPublicKeyFile, PGPPrivateKeyFile} {
		path := filepath.Join(dir, name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove %s: %w", name, err))
		}
	}
	if len(errs) > 0 {
		msgs := ""
		for _, e := range errs {
			msgs += e.Error() + "; "
		}
		return errors.New(msgs)
	}
	return nil
}

// PGPPublicKeyFingerprint returns the hex fingerprint of the stored public key, or "" if not present.
func PGPPublicKeyFingerprint(configDir string) string {
	pubPath := filepath.Join(pgpSecDir(configDir), PGPPublicKeyFile)
	data, err := os.ReadFile(pubPath)
	if err != nil {
		return ""
	}

	el, err := pgpcrypto.ReadArmoredKeyRing(bytes.NewReader(data))
	if err != nil || len(el) == 0 {
		return ""
	}

	fp := el[0].PrimaryKey.Fingerprint
	return hex.EncodeToString(fp[:])
}

// writePublicKey serializes the entity's public key as ASCII-armored PGP to path.
func writePublicKey(entity *pgpcrypto.Entity, path string) error {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		return fmt.Errorf("armor encode: %w", err)
	}
	if err := entity.Serialize(w); err != nil {
		w.Close()
		return fmt.Errorf("serialize public key: %w", err)
	}
	w.Close()

	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}

// writeEncryptedPrivateKey serializes the full entity (including private key)
// and encrypts it with AES-256-GCM using a key derived from installationSecret.
func writeEncryptedPrivateKey(entity *pgpcrypto.Entity, path, installationSecret string) error {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP PRIVATE KEY BLOCK", nil)
	if err != nil {
		return fmt.Errorf("armor encode: %w", err)
	}
	if err := entity.SerializePrivate(w, nil); err != nil {
		w.Close()
		return fmt.Errorf("serialize private key: %w", err)
	}
	w.Close()

	encrypted, err := aesEncrypt(buf.Bytes(), installationSecret)
	if err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}

	if err := os.WriteFile(path, encrypted, 0600); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}

// decryptPrivateKey reads and decrypts the encrypted private key file.
func decryptPrivateKey(path, installationSecret string) ([]byte, error) {
	encrypted, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return aesDecrypt(encrypted, installationSecret)
}

// aesEncrypt encrypts plaintext with AES-256-GCM.
// Key is derived from secret using HKDF-SHA3-256.
// Output format: 12-byte nonce || ciphertext.
func aesEncrypt(plaintext []byte, secret string) ([]byte, error) {
	key, err := deriveAESKey(secret)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// aesDecrypt decrypts AES-256-GCM ciphertext produced by aesEncrypt.
func aesDecrypt(ciphertext []byte, secret string) ([]byte, error) {
	key, err := deriveAESKey(secret)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w (wrong installation secret?)", err)
	}
	return plaintext, nil
}

// deriveAESKey derives a 32-byte AES key from the installation secret using HKDF-SHA3-256.
func deriveAESKey(secret string) ([]byte, error) {
	salt := []byte("caswhois-pgp-key-v1")
	info := []byte("pgp-private-key-encryption")
	h := hkdf.New(sha3.New256, []byte(secret), salt, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return key, nil
}
