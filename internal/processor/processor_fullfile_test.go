package processor

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/crypto"
	"github.com/maurice2k/confcrypt/internal/format"
)

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		override string
		want     FileFormat
	}{
		// Extension-based detection
		{name: "yaml file", filePath: "config.yml", want: FormatYAML},
		{name: "yaml file long ext", filePath: "config.yaml", want: FormatYAML},
		{name: "json file", filePath: "config.json", want: FormatJSON},
		{name: "env file", filePath: ".env", want: FormatEnv},
		{name: "env file with prefix", filePath: ".env.local", want: FormatEnv},
		{name: "env file with suffix", filePath: "database.env", want: FormatEnv},

		// Implicit full encryption patterns
		{name: "key file", filePath: "server.key", want: FormatFull},
		{name: "pem file", filePath: "cert.pem", want: FormatFull},
		{name: "p12 file", filePath: "cert.p12", want: FormatFull},
		{name: "pfx file", filePath: "cert.pfx", want: FormatFull},
		{name: "p8 file", filePath: "private.p8", want: FormatFull},
		{name: "keystore file", filePath: "app.keystore", want: FormatFull},
		{name: "jks file", filePath: "truststore.jks", want: FormatFull},
		{name: "ssh ed25519 key", filePath: "id_ed25519", want: FormatFull},
		{name: "ssh ed25519 key with suffix", filePath: "id_ed25519_work", want: FormatFull},
		{name: "ssh rsa key", filePath: "id_rsa", want: FormatFull},
		{name: "ssh rsa key with suffix", filePath: "id_rsa_backup", want: FormatFull},
		{name: "ssh ecdsa key", filePath: "id_ecdsa", want: FormatFull},
		{name: "ssh dsa key", filePath: "id_dsa", want: FormatFull},

		// Unknown extension defaults to YAML
		{name: "txt file", filePath: "readme.txt", want: FormatYAML},
		{name: "no extension", filePath: "Makefile", want: FormatYAML},

		// Override takes precedence
		{name: "override full on yaml", filePath: "config.yml", override: "full", want: FormatFull},
		{name: "override yaml on txt", filePath: "config.txt", override: "yaml", want: FormatYAML},
		{name: "override json on txt", filePath: "config.txt", override: "json", want: FormatJSON},
		{name: "override env on txt", filePath: "config.txt", override: "env", want: FormatEnv},
		{name: "override yaml on key", filePath: "server.key", override: "yaml", want: FormatYAML},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got FileFormat
			if tt.override != "" {
				got = DetectFormat(tt.filePath, tt.override)
			} else {
				got = DetectFormat(tt.filePath)
			}
			if got != tt.want {
				t.Errorf("DetectFormat(%q, %q) = %v, want %v", tt.filePath, tt.override, got, tt.want)
			}
		})
	}
}

func TestProcessFullFile(t *testing.T) {
	dir := t.TempDir()

	// Generate keypair
	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Create config
	cfg := createTestConfigWithIdentity(t, dir, identity)

	// Create a test file with binary content
	testFile := filepath.Join(dir, "secret.key")
	originalContent := []byte("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC...\n-----END PRIVATE KEY-----\n")
	if err := os.WriteFile(testFile, originalContent, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create processor
	proc, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption: %v", err)
	}

	// Encrypt the file
	encrypted, modified, err := proc.ProcessFile(testFile, true, "full")
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if !modified {
		t.Error("Expected file to be modified")
	}

	// Check encrypted format
	if !format.IsFullFileEncrypted(encrypted) {
		t.Error("Expected full file encrypted format")
	}

	// Write encrypted content
	if err := os.WriteFile(testFile, encrypted, 0644); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}

	// Save secrets
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}

	// Create new processor for decryption
	proc2, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	if _, err := proc2.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}

	// Decrypt the file
	decrypted, modified, err := proc2.ProcessFile(testFile, false, "full")
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if !modified {
		t.Error("Expected file to be modified during decryption")
	}

	// Compare
	if string(decrypted) != string(originalContent) {
		t.Errorf("Decrypted content doesn't match original.\nGot: %q\nWant: %q", decrypted, originalContent)
	}
}

func TestProcessFullFileIdempotent(t *testing.T) {
	dir := t.TempDir()

	// Generate keypair
	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Create config
	cfg := createTestConfigWithIdentity(t, dir, identity)

	// Create a test file
	testFile := filepath.Join(dir, "secret.key")
	originalContent := []byte("secret data")
	if err := os.WriteFile(testFile, originalContent, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create processor and encrypt
	proc, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption: %v", err)
	}

	// First encryption
	encrypted1, modified1, err := proc.ProcessFile(testFile, true, "full")
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if !modified1 {
		t.Error("Expected first encryption to modify")
	}

	// Write encrypted
	if err := os.WriteFile(testFile, encrypted1, 0644); err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	// Second encryption should not modify (already encrypted)
	encrypted2, modified2, err := proc.ProcessFile(testFile, true, "full")
	if err != nil {
		t.Fatalf("Failed on second encryption: %v", err)
	}
	if modified2 {
		t.Error("Expected second encryption to NOT modify (already encrypted)")
	}

	// Content should be unchanged
	if string(encrypted2) != string(encrypted1) {
		t.Error("Content changed during second encryption attempt")
	}
}

func TestHasEncryptedValuesFullFile(t *testing.T) {
	dir := t.TempDir()

	// Generate keypair
	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Create config
	cfg := createTestConfigWithIdentity(t, dir, identity)

	proc, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// Plain content
	plainContent := []byte("plain text content")
	if proc.HasEncryptedValues(plainContent, "test.key", "full") {
		t.Error("Expected HasEncryptedValues to return false for plain content")
	}

	// Encrypted content (mock)
	encryptedContent := []byte("$CONFCRYPT_ENCRYPTED;ENC[AES256_GCM,data:\ndGVzdA==,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:bytes]")
	if !proc.HasEncryptedValues(encryptedContent, "test.key", "full") {
		t.Error("Expected HasEncryptedValues to return true for encrypted content")
	}
}

func TestHasUnencryptedValuesFullFile(t *testing.T) {
	dir := t.TempDir()

	// Generate keypair
	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Create config
	cfg := createTestConfigWithIdentity(t, dir, identity)

	proc, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// Plain content - should report unencrypted
	plainContent := []byte("plain text content")
	if !proc.HasUnencryptedValues(plainContent, "test.key", "full") {
		t.Error("Expected HasUnencryptedValues to return true for plain content")
	}

	// Encrypted content - should not report unencrypted
	encryptedContent := []byte("$CONFCRYPT_ENCRYPTED;ENC[AES256_GCM,data:\ndGVzdA==,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:bytes]")
	if proc.HasUnencryptedValues(encryptedContent, "test.key", "full") {
		t.Error("Expected HasUnencryptedValues to return false for encrypted content")
	}
}

// Helper function to create test config
func createTestConfigWithIdentity(t *testing.T, dir string, identity *age.X25519Identity) *config.Config {
	t.Helper()

	// Get public key
	pubKey := identity.Recipient().String()

	configPath := filepath.Join(dir, ".confcrypt.yml")
	configContent := `recipients:
  - name: "Test"
    age: ` + pubKey + `
files:
  - "*.key"
  - "*.yml"
keys_include:
  - /password$/
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	return cfg
}
