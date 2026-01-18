package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/maurice2k/confcrypt/internal/crypto"
)

func TestGetPublicKeyFromAgeFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate a test age key
	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate age keypair: %v", err)
	}

	// Write age key to file (with comment like real age keys)
	ageKeyPath := filepath.Join(tmpDir, "key.txt")
	keyContent := "# created: 2024-01-01\n# public key: " + identity.Recipient().String() + "\n" + identity.String()
	if err := os.WriteFile(ageKeyPath, []byte(keyContent), 0600); err != nil {
		t.Fatalf("Failed to write age key: %v", err)
	}

	t.Run("valid age key file", func(t *testing.T) {
		pubKey, keyType, err := getPublicKeyFromAgeFile(ageKeyPath)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if pubKey != identity.Recipient().String() {
			t.Errorf("Expected %s, got %s", identity.Recipient().String(), pubKey)
		}
		if keyType != crypto.KeyTypeAge {
			t.Errorf("Expected KeyTypeAge, got %v", keyType)
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, _, err := getPublicKeyFromAgeFile(filepath.Join(tmpDir, "nonexistent.txt"))
		if err == nil {
			t.Error("Expected error for non-existent file")
		}
	})

	t.Run("invalid content", func(t *testing.T) {
		invalidPath := filepath.Join(tmpDir, "invalid.txt")
		if err := os.WriteFile(invalidPath, []byte("not a valid key"), 0600); err != nil {
			t.Fatalf("Failed to write invalid key: %v", err)
		}
		_, _, err := getPublicKeyFromAgeFile(invalidPath)
		if err == nil {
			t.Error("Expected error for invalid key content")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		emptyPath := filepath.Join(tmpDir, "empty.txt")
		if err := os.WriteFile(emptyPath, []byte(""), 0600); err != nil {
			t.Fatalf("Failed to write empty file: %v", err)
		}
		_, _, err := getPublicKeyFromAgeFile(emptyPath)
		if err == nil {
			t.Error("Expected error for empty file")
		}
	})
}

func TestGetPublicKeyFromSSHFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Valid SSH ed25519 public key (real test key)
	validSSHKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHUjK0d/tDzPdMPUl8IkSmKvfaLV0tMqJhBU0xFRi+FJ test@example.com"

	t.Run("valid ssh key file", func(t *testing.T) {
		sshKeyPath := filepath.Join(tmpDir, "id_ed25519.pub")
		if err := os.WriteFile(sshKeyPath, []byte(validSSHKey), 0644); err != nil {
			t.Fatalf("Failed to write SSH key: %v", err)
		}

		pubKey, keyType, err := getPublicKeyFromSSHFile(sshKeyPath)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if pubKey != validSSHKey {
			t.Errorf("Expected %s, got %s", validSSHKey, pubKey)
		}
		if keyType != crypto.KeyTypeSSHEd25519 {
			t.Errorf("Expected KeyTypeSSHEd25519, got %v", keyType)
		}
	})

	t.Run("ssh key with whitespace", func(t *testing.T) {
		sshKeyPath := filepath.Join(tmpDir, "id_ed25519_whitespace.pub")
		if err := os.WriteFile(sshKeyPath, []byte("\n  "+validSSHKey+"  \n"), 0644); err != nil {
			t.Fatalf("Failed to write SSH key: %v", err)
		}

		pubKey, _, err := getPublicKeyFromSSHFile(sshKeyPath)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if pubKey != validSSHKey {
			t.Errorf("Expected trimmed key %s, got %s", validSSHKey, pubKey)
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, _, err := getPublicKeyFromSSHFile(filepath.Join(tmpDir, "nonexistent.pub"))
		if err == nil {
			t.Error("Expected error for non-existent file")
		}
	})

	t.Run("invalid ssh key", func(t *testing.T) {
		invalidPath := filepath.Join(tmpDir, "invalid.pub")
		if err := os.WriteFile(invalidPath, []byte("not a valid ssh key"), 0644); err != nil {
			t.Fatalf("Failed to write invalid key: %v", err)
		}
		_, _, err := getPublicKeyFromSSHFile(invalidPath)
		if err == nil {
			t.Error("Expected error for invalid SSH key")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		emptyPath := filepath.Join(tmpDir, "empty.pub")
		if err := os.WriteFile(emptyPath, []byte(""), 0644); err != nil {
			t.Fatalf("Failed to write empty file: %v", err)
		}
		_, _, err := getPublicKeyFromSSHFile(emptyPath)
		if err == nil {
			t.Error("Expected error for empty file")
		}
	})
}

func TestGetPublicKeyForInit_ExplicitFlags(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test age key
	ageIdentity, _ := crypto.GenerateAgeKeypair()
	ageKeyPath := filepath.Join(tmpDir, "age-key.txt")
	ageKeyContent := "# public key: " + ageIdentity.Recipient().String() + "\n" + ageIdentity.String()
	os.WriteFile(ageKeyPath, []byte(ageKeyContent), 0600)

	// Create test SSH key
	sshKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHUjK0d/tDzPdMPUl8IkSmKvfaLV0tMqJhBU0xFRi+FJ test@example.com"
	sshKeyPath := filepath.Join(tmpDir, "id_ed25519.pub")
	os.WriteFile(sshKeyPath, []byte(sshKey), 0644)

	// Save original flag values
	origAgeKeyFile := initAgeKeyFile
	origSSHKeyFile := initSSHKeyFile
	defer func() {
		initAgeKeyFile = origAgeKeyFile
		initSSHKeyFile = origSSHKeyFile
	}()

	t.Run("explicit age key flag", func(t *testing.T) {
		initAgeKeyFile = ageKeyPath
		initSSHKeyFile = ""

		pubKey, keyType, err := getPublicKeyForInit()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if pubKey != ageIdentity.Recipient().String() {
			t.Errorf("Expected age public key %s, got %s", ageIdentity.Recipient().String(), pubKey)
		}
		if keyType != crypto.KeyTypeAge {
			t.Errorf("Expected KeyTypeAge, got %v", keyType)
		}
	})

	t.Run("explicit ssh key flag", func(t *testing.T) {
		initAgeKeyFile = ""
		initSSHKeyFile = sshKeyPath

		pubKey, keyType, err := getPublicKeyForInit()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if pubKey != sshKey {
			t.Errorf("Expected SSH public key")
		}
		if keyType != crypto.KeyTypeSSHEd25519 {
			t.Errorf("Expected KeyTypeSSHEd25519, got %v", keyType)
		}
	})

	t.Run("age flag takes precedence over ssh flag", func(t *testing.T) {
		initAgeKeyFile = ageKeyPath
		initSSHKeyFile = sshKeyPath

		pubKey, keyType, err := getPublicKeyForInit()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		// Age flag should be checked first
		if pubKey != ageIdentity.Recipient().String() {
			t.Errorf("Age flag should take precedence")
		}
		if keyType != crypto.KeyTypeAge {
			t.Errorf("Expected KeyTypeAge, got %v", keyType)
		}
	})

	t.Run("invalid age key path returns error", func(t *testing.T) {
		initAgeKeyFile = filepath.Join(tmpDir, "nonexistent.txt")
		initSSHKeyFile = ""

		_, _, err := getPublicKeyForInit()
		if err == nil {
			t.Error("Expected error for non-existent age key")
		}
	})

	t.Run("invalid ssh key path returns error", func(t *testing.T) {
		initAgeKeyFile = ""
		initSSHKeyFile = filepath.Join(tmpDir, "nonexistent.pub")

		_, _, err := getPublicKeyForInit()
		if err == nil {
			t.Error("Expected error for non-existent ssh key")
		}
	})

	t.Run("invalid age key content returns error", func(t *testing.T) {
		invalidAgePath := filepath.Join(tmpDir, "invalid-age.txt")
		os.WriteFile(invalidAgePath, []byte("not a valid age key"), 0600)

		initAgeKeyFile = invalidAgePath
		initSSHKeyFile = ""

		_, _, err := getPublicKeyForInit()
		if err == nil {
			t.Error("Expected error for invalid age key content")
		}
	})

	t.Run("invalid ssh key content returns error", func(t *testing.T) {
		invalidSSHPath := filepath.Join(tmpDir, "invalid-ssh.pub")
		os.WriteFile(invalidSSHPath, []byte("not a valid ssh key"), 0644)

		initAgeKeyFile = ""
		initSSHKeyFile = invalidSSHPath

		_, _, err := getPublicKeyForInit()
		if err == nil {
			t.Error("Expected error for invalid ssh key content")
		}
	})

	t.Run("--age-key without value (auto) detects age keys only", func(t *testing.T) {
		// Set up env var for auto-detection
		t.Setenv("SOPS_AGE_KEY_FILE", ageKeyPath)

		initAgeKeyFile = autoDetectMarker // This is what Cobra sets when --age-key is used without value
		initSSHKeyFile = ""

		pubKey, keyType, err := getPublicKeyForInit()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if pubKey != ageIdentity.Recipient().String() {
			t.Errorf("Expected auto-detected age public key")
		}
		if keyType != crypto.KeyTypeAge {
			t.Errorf("Expected KeyTypeAge, got %v", keyType)
		}
	})

	t.Run("--ssh-key without value (auto) detects SSH keys only", func(t *testing.T) {
		// Create a temp SSH key that can be found
		sshDir := filepath.Join(tmpDir, ".ssh")
		os.MkdirAll(sshDir, 0700)
		tmpSSHKeyPath := filepath.Join(sshDir, "id_ed25519.pub")
		os.WriteFile(tmpSSHKeyPath, []byte(sshKey), 0644)

		// Clear env vars and override HOME to use our temp dir
		// Use t.Setenv for automatic cleanup and parallel test safety
		t.Setenv("SOPS_AGE_KEY_FILE", "")
		t.Setenv("CONFCRYPT_AGE_KEY_FILE", "")
		t.Setenv("CONFCRYPT_SSH_KEY_FILE", "")
		t.Setenv("HOME", tmpDir)

		initAgeKeyFile = ""
		initSSHKeyFile = autoDetectMarker // This is what Cobra sets when --ssh-key is used without value

		pubKey, keyType, err := getPublicKeyForInit()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if pubKey != sshKey {
			t.Errorf("Expected auto-detected SSH public key")
		}
		if keyType != crypto.KeyTypeSSHEd25519 {
			t.Errorf("Expected KeyTypeSSHEd25519, got %v", keyType)
		}
	})

	t.Run("--age-key auto ignores available SSH keys", func(t *testing.T) {
		// Set up SSH key that would normally be found
		sshDir := filepath.Join(tmpDir, ".ssh2")
		os.MkdirAll(sshDir, 0700)
		tmpSSHKeyPath := filepath.Join(sshDir, "id_ed25519.pub")
		os.WriteFile(tmpSSHKeyPath, []byte(sshKey), 0644)

		// Clear all env vars, set HOME to temp dir (so no age key is found)
		// Use t.Setenv for automatic cleanup and parallel test safety
		t.Setenv("SOPS_AGE_KEY_FILE", "")
		t.Setenv("CONFCRYPT_AGE_KEY_FILE", "")
		t.Setenv("HOME", tmpDir)

		initAgeKeyFile = autoDetectMarker
		initSSHKeyFile = ""

		// Should fail because no age key exists, even though SSH key does
		_, _, err := getPublicKeyForInit()
		if err == nil {
			t.Error("Expected error when --age-key auto finds no age key")
		}
	})

	t.Run("no flags falls back to full auto-detect", func(t *testing.T) {
		// Set up env var for auto-detection
		t.Setenv("SOPS_AGE_KEY_FILE", ageKeyPath)

		initAgeKeyFile = ""
		initSSHKeyFile = ""

		pubKey, keyType, err := getPublicKeyForInit()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if pubKey != ageIdentity.Recipient().String() {
			t.Errorf("Expected auto-detected age public key")
		}
		if keyType != crypto.KeyTypeAge {
			t.Errorf("Expected KeyTypeAge, got %v", keyType)
		}
	})
}

func TestGetPublicKeyForInit_EnvironmentVariables(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test age key
	ageIdentity, _ := crypto.GenerateAgeKeypair()
	ageKeyPath := filepath.Join(tmpDir, "age-key.txt")
	ageKeyContent := "# public key: " + ageIdentity.Recipient().String() + "\n" + ageIdentity.String()
	os.WriteFile(ageKeyPath, []byte(ageKeyContent), 0600)

	// Reset flags to ensure auto-detection
	origAgeKeyFile := initAgeKeyFile
	origSSHKeyFile := initSSHKeyFile
	defer func() {
		initAgeKeyFile = origAgeKeyFile
		initSSHKeyFile = origSSHKeyFile
	}()
	initAgeKeyFile = ""
	initSSHKeyFile = ""

	t.Run("SOPS_AGE_KEY_FILE env var", func(t *testing.T) {
		t.Setenv("SOPS_AGE_KEY_FILE", ageKeyPath)
		t.Setenv("CONFCRYPT_AGE_KEY_FILE", "")

		pubKey, keyType, err := getPublicKeyForInit()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if pubKey != ageIdentity.Recipient().String() {
			t.Errorf("Expected age public key from SOPS_AGE_KEY_FILE")
		}
		if keyType != crypto.KeyTypeAge {
			t.Errorf("Expected KeyTypeAge, got %v", keyType)
		}
	})

	t.Run("CONFCRYPT_AGE_KEY_FILE env var", func(t *testing.T) {
		t.Setenv("SOPS_AGE_KEY_FILE", "")
		t.Setenv("CONFCRYPT_AGE_KEY_FILE", ageKeyPath)

		pubKey, keyType, err := getPublicKeyForInit()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if pubKey != ageIdentity.Recipient().String() {
			t.Errorf("Expected age public key from CONFCRYPT_AGE_KEY_FILE")
		}
		if keyType != crypto.KeyTypeAge {
			t.Errorf("Expected KeyTypeAge, got %v", keyType)
		}
	})
}

func TestAutoDetectPublicKey(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test age key
	ageIdentity, _ := crypto.GenerateAgeKeypair()
	ageKeyPath := filepath.Join(tmpDir, "age-key.txt")
	ageKeyContent := "# public key: " + ageIdentity.Recipient().String() + "\n" + ageIdentity.String()
	os.WriteFile(ageKeyPath, []byte(ageKeyContent), 0600)

	t.Run("auto-detect from SOPS_AGE_KEY_FILE", func(t *testing.T) {
		t.Setenv("SOPS_AGE_KEY_FILE", ageKeyPath)

		pubKey, keyType, err := autoDetectPublicKey()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if pubKey != ageIdentity.Recipient().String() {
			t.Errorf("Expected age public key")
		}
		if keyType != crypto.KeyTypeAge {
			t.Errorf("Expected KeyTypeAge, got %v", keyType)
		}
	})
}
