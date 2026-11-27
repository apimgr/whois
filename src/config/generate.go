package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"gopkg.in/yaml.v3"
	"math/big"
	"os"
	"path/filepath"
)

const tokenAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// GenerateInstallationSecret generates a 64-char hex installation secret (AI.md PART 11).
// This is the root KDF input for PGP private-key encryption and derived material.
func GenerateInstallationSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate installation secret: %w", err)
	}
	result := make([]byte, 64)
	const hexChars = "0123456789abcdef"
	for i, byt := range b {
		result[i*2] = hexChars[byt>>4]
		result[i*2+1] = hexChars[byt&0xf]
	}
	return string(result), nil
}

// GenerateEncryptionKey returns a base64-encoded 32-byte AES-256-GCM key.
func GenerateEncryptionKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate encryption key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// GenerateWebhookSecret returns a base64-encoded per-webhook HMAC key.
func GenerateWebhookSecret() (string, error) {
	secret, err := GenerateEncryptionKey()
	if err != nil {
		return "", fmt.Errorf("generate webhook signing secret: %w", err)
	}
	return secret, nil
}

// GenerateToken generates the operator token: "adm_" + 32 base62 chars.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(tokenAlphabet))))
		if err != nil {
			return "", err
		}
		b[i] = tokenAlphabet[n.Int64()]
	}
	return "adm_" + string(b), nil
}

func GenerateDefaultConfig(configDir string) error {
	configPath := filepath.Join(configDir, "server.yml")

	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		return nil
	}

	// Ensure config directory exists
	if err := secureConfigDir(configDir); err != nil {
		return err
	}

	// Containers use the image's fixed internal HTTP port; bare-host installs
	// receive a free port from the documented high-port range.
	port := 80
	var err error
	if !isApplicationContainer() {
		port, err = randomPort()
		if err != nil {
			port = 64580
		}
	}

	// Reuse the operator credential if server.yml was removed independently.
	token, err := readOperatorToken(filepath.Join(configDir, "secrets.yml"))
	if err != nil {
		return err
	}
	newToken := token == ""
	if newToken {
		token, err = GenerateToken()
		if err != nil {
			return fmt.Errorf("failed to generate server token: %w", err)
		}
	}
	encryptionKey, err := readEncryptionKey(filepath.Join(configDir, "secrets.yml"))
	if err != nil {
		return err
	}
	if encryptionKey == "" {
		encryptionKey, err = GenerateEncryptionKey()
		if err != nil {
			return err
		}
	}

	// A fresh installation writes only this node's settings. Area files are
	// created by explicit workflows or by migration of an existing full file.
	serverConfig := Default()
	serverConfig.Port = port
	configData, err := marshalNodeConfig(serverConfig)
	if err != nil {
		return fmt.Errorf("marshal default node configuration: %w", err)
	}

	// Write the public configuration without credentials.
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	if err := os.Chmod(configPath, 0600); err != nil {
		return fmt.Errorf("secure config file: %w", err)
	}
	if err := writeServerSecrets(filepath.Join(configDir, "secrets.yml"), token, encryptionKey); err != nil {
		return fmt.Errorf("failed to write secrets file: %w", err)
	}
	if newToken {
		fmt.Printf("Generated operator token: %s\n", token)
	}

	return nil
}

func writeServerSecrets(path, token, encryptionKey string) error {
	secrets := map[string]any{}
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &secrets); err != nil {
			return fmt.Errorf("parse secrets file: %w", err)
		} else if secrets == nil {
			secrets = map[string]any{}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	server, _ := secrets["server"].(map[string]any)
	if server == nil {
		server = map[string]any{}
	}
	if token != "" {
		server["token"] = token
	}
	security, _ := server["security"].(map[string]any)
	if security == nil {
		security = map[string]any{}
	}
	if encryptionKey != "" {
		security["encryption_key"] = encryptionKey
		security["encryption_key_version"] = 1
	}
	server["security"] = security
	secrets["server"] = server
	data, err := yaml.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("marshal secrets file: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".secrets-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func readEncryptionKey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read secrets file: %w", err)
	}
	var secrets struct {
		Server struct {
			Security struct {
				EncryptionKey string `yaml:"encryption_key"`
			} `yaml:"security"`
		} `yaml:"server"`
	}
	if err := yaml.Unmarshal(data, &secrets); err != nil {
		return "", fmt.Errorf("parse secrets file: %w", err)
	}
	return secrets.Server.Security.EncryptionKey, nil
}

// randomPort generates a random port in the 64000-64999 range
func randomPort() (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()) + 64000, nil
}
