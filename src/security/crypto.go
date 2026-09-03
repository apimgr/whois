package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2 parameters per AI.md PART 11
const (
	Argon2Time = 3
	// 64 MB memory cost for Argon2id
	Argon2Memory  = 64 * 1024
	Argon2Threads = 4
	Argon2KeyLen  = 32
	SaltLen       = 16
)

// HashPassword generates an Argon2id hash of the password
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}

	// Generate salt
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	// Generate hash using Argon2id
	hash := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	// Encode as: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, Argon2Memory, Argon2Time, Argon2Threads, b64Salt, b64Hash)

	return encoded, nil
}

// VerifyPassword checks if password matches the hash
func VerifyPassword(password, encodedHash string) (bool, error) {
	if password == "" {
		return false, errors.New("password cannot be empty")
	}
	if encodedHash == "" {
		return false, errors.New("hash cannot be empty")
	}

	// Parse the encoded hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid hash format")
	}

	if parts[1] != "argon2id" {
		return false, errors.New("unsupported hash algorithm")
	}

	// Parse parameters
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("parse version: %w", err)
	}

	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, fmt.Errorf("parse parameters: %w", err)
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}

	// Generate hash of provided password with same parameters
	comparisonHash := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(hash)))

	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(hash, comparisonHash) == 1 {
		return true, nil
	}

	return false, nil
}

// GenerateToken generates a random API token with prefix
func GenerateToken(prefix string) (string, error) {
	if prefix == "" {
		return "", errors.New("token prefix is required")
	}

	// Generate 32 bytes of random data (256 bits)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	// Encode as hex
	tokenStr := hex.EncodeToString(tokenBytes)

	// Format: prefix_<hex>
	// Examples: adm_abc123..., usr_def456..., org_ghi789...
	return fmt.Sprintf("%s_%s", prefix, tokenStr), nil
}

// HashToken hashes an API token using SHA-256 for storage
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// VerifyToken checks if a token matches the stored hash (constant-time)
func VerifyToken(token, storedHash string) bool {
	tokenHash := HashToken(token)
	return subtle.ConstantTimeCompare([]byte(tokenHash), []byte(storedHash)) == 1
}

// GenerateRandomString generates a random string of specified length
func GenerateRandomString(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("length must be positive")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// GenerateRandomBytes generates random bytes
func GenerateRandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("length must be positive")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}

	return bytes, nil
}
