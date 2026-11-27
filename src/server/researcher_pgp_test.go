package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apimgr/whois/src/security"
)

func TestResearcherPGPKeyValidationAndEncryption(t *testing.T) {
	configDir := t.TempDir()
	if err := security.GeneratePGPKeypair(configDir, "caswhois", "security@example.test", "test installation secret"); err != nil {
		t.Fatal(err)
	}
	publicKey, err := os.ReadFile(filepath.Join(configDir, "security", security.PGPPublicKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	validated, err := loadResearcherPGPKey(context.Background(), string(publicKey))
	if err != nil {
		t.Fatalf("validate public key: %v", err)
	}
	ciphertext, err := security.EncryptPGP(validated, []byte("report tracking details"))
	if err != nil {
		t.Fatalf("encrypt acknowledgment: %v", err)
	}
	if !strings.Contains(string(ciphertext), "-----BEGIN PGP MESSAGE-----") {
		t.Fatalf("unexpected encrypted message: %q", ciphertext[:min(len(ciphertext), 64)])
	}
	if _, err := loadResearcherPGPKey(context.Background(), "not a key"); err == nil {
		t.Fatal("invalid pasted key was accepted")
	}
	if _, err := loadResearcherPGPKey(context.Background(), "https://localhost/key.asc"); err == nil {
		t.Fatal("non-public key host was accepted")
	}
}
