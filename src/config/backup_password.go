package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apimgr/whois/src/security"
	"gopkg.in/yaml.v3"
)

// LoadBackupPassword reads the backup passphrase from secrets.yml and migrates
// a legacy plaintext value to the encrypted representation in place.
func LoadBackupPassword(configDir string, cfg *ServerConfig) (string, error) {
	if configDir == "" || cfg == nil {
		return "", fmt.Errorf("config directory and server config are required")
	}
	path := filepath.Join(configDir, "secrets.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read backup password: %w", err)
	}
	var secrets map[string]any
	if err := yaml.Unmarshal(data, &secrets); err != nil {
		return "", fmt.Errorf("parse backup secrets: %w", err)
	}
	if secrets == nil {
		secrets = make(map[string]any)
	}
	server := ensureMap(secrets["server"])
	backup := ensureMap(server["backup"])
	value, _ := backup["encryption_password"].(string)
	if value == "" {
		return "", nil
	}
	key, err := base64.StdEncoding.DecodeString(cfg.Security.EncryptionKey)
	if err != nil || len(key) != 32 {
		return "", fmt.Errorf("backup encryption key is unavailable")
	}
	if strings.HasPrefix(value, "enc:v1:") {
		password, err := security.DecryptAESGCM(key, value)
		if err != nil {
			return "", fmt.Errorf("backup password cannot be decrypted: %w", err)
		}
		return password, nil
	}
	encrypted, err := security.EncryptAESGCM(key, value)
	if err != nil {
		return "", fmt.Errorf("encrypt backup password: %w", err)
	}
	backup["encryption_password"] = encrypted
	server["backup"] = backup
	secrets["server"] = server
	encoded, err := yaml.Marshal(secrets)
	if err != nil {
		return "", fmt.Errorf("encode backup secrets: %w", err)
	}
	if err := atomicPrivateWrite(path, encoded); err != nil {
		return "", fmt.Errorf("persist encrypted backup password: %w", err)
	}
	return value, nil
}
