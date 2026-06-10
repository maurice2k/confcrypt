package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/processor"
)

func TestPerformRekeyRotatesKeyAndReencryptsFiles(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)

	encryptedBefore, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}
	if len(cfg.Confcrypt.Store) != 1 {
		t.Fatalf("Expected 1 store entry before rekey, got %d", len(cfg.Confcrypt.Store))
	}
	oldSecret := cfg.Confcrypt.Store[0].Secret

	rekeyedFiles, err := performRekey(cfg, []age.Identity{identity})
	if err != nil {
		t.Fatalf("performRekey failed: %v", err)
	}
	if len(rekeyedFiles) != 1 || rekeyedFiles[0] != "test.yml" {
		t.Fatalf("Expected [test.yml] to be rekeyed, got %v", rekeyedFiles)
	}

	// The store must hold exactly one entry with a new wrapped key
	reloaded, err := config.Load(cfg.ConfigPath())
	if err != nil {
		t.Fatalf("Failed to reload config: %v", err)
	}
	if len(reloaded.Confcrypt.Store) != 1 {
		t.Fatalf("Expected 1 store entry after rekey, got %d", len(reloaded.Confcrypt.Store))
	}
	if reloaded.Confcrypt.Store[0].Secret == oldSecret {
		t.Error("Store entry unchanged after rekey - key was not rotated")
	}

	// The file must be re-encrypted (different ciphertext, no plaintext)
	encryptedAfter, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read rekeyed file: %v", err)
	}
	if string(encryptedAfter) == string(encryptedBefore) {
		t.Error("File content unchanged after rekey")
	}
	for _, secret := range []string{"secret123", "myapikey"} {
		if strings.Contains(string(encryptedAfter), secret) {
			t.Errorf("Plaintext %q present in rekeyed file", secret)
		}
	}

	// The rekeyed file must decrypt with the new store (incl. MAC check)
	proc, err := processor.NewProcessor(reloaded, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	if _, err := proc.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption after rekey: %v", err)
	}
	if err := proc.VerifyMAC(testFile, encryptedAfter); err != nil {
		t.Errorf("MAC verification failed after rekey: %v", err)
	}
	decrypted, _, err := proc.ProcessFile(testFile, false)
	if err != nil {
		t.Fatalf("Failed to decrypt after rekey: %v", err)
	}
	if !strings.Contains(string(decrypted), "password: secret123") {
		t.Errorf("Decrypted content wrong after rekey:\n%s", decrypted)
	}
}

func TestPerformRekeyWithoutEncryptedFilesRotatesKeyOnly(t *testing.T) {
	dir := t.TempDir()

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	cfg := createTestConfigWithSecrets(t, dir, identity)

	// Populate the store without encrypting any file
	proc, err := processor.NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption: %v", err)
	}
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}
	oldSecret := cfg.Confcrypt.Store[0].Secret

	// A plaintext file that matches the patterns but has nothing encrypted
	plainFile := filepath.Join(dir, "plain.yml")
	if err := os.WriteFile(plainFile, []byte("name: nothing-secret\n"), 0644); err != nil {
		t.Fatalf("Failed to write plain file: %v", err)
	}

	rekeyedFiles, err := performRekey(cfg, []age.Identity{identity})
	if err != nil {
		t.Fatalf("performRekey failed: %v", err)
	}
	if len(rekeyedFiles) != 0 {
		t.Errorf("Expected no rekeyed files, got %v", rekeyedFiles)
	}

	reloaded, err := config.Load(cfg.ConfigPath())
	if err != nil {
		t.Fatalf("Failed to reload config: %v", err)
	}
	if len(reloaded.Confcrypt.Store) != 1 {
		t.Fatalf("Expected 1 store entry, got %d", len(reloaded.Confcrypt.Store))
	}
	if reloaded.Confcrypt.Store[0].Secret == oldSecret {
		t.Error("Expected key rotation even without encrypted files")
	}

	// The plaintext file must be untouched
	content, err := os.ReadFile(plainFile)
	if err != nil {
		t.Fatalf("Failed to read plain file: %v", err)
	}
	if string(content) != "name: nothing-secret\n" {
		t.Errorf("Plain file modified by rekey: %s", content)
	}
}
