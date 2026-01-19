package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"gopkg.in/yaml.v3"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/crypto"
	"github.com/maurice2k/confcrypt/internal/processor"
)

// Helper to create a test config with secrets
func createTestConfigWithSecrets(t *testing.T, dir string, identity *age.X25519Identity) *config.Config {
	cfg := &config.Config{
		Recipients: []config.RecipientConfig{
			{Name: "test", Age: identity.Recipient().String()},
		},
		Files: []string{"*.yml", "*.yaml"},
		KeysInclude: []interface{}{
			"/password$/",
			"api_key",
			"secret",
		},
	}

	configPath := filepath.Join(dir, ".confcrypt.yml")
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Reload to set internal paths
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	return loaded
}

func TestClearSecretsAfterFullDecryption(t *testing.T) {
	dir := t.TempDir()

	// Generate keypair
	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Create config
	cfg := createTestConfigWithSecrets(t, dir, identity)

	// Create test file with sensitive data
	testFile := filepath.Join(dir, "test.yml")
	testContent := `database:
  host: localhost
  password: secret123
api_key: myapikey
`
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create processor and encrypt
	proc, err := processor.NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption: %v", err)
	}

	output, _, err := proc.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Write encrypted file
	if err := os.WriteFile(testFile, output, 0644); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}

	// Save secrets
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}

	// Verify secrets exist
	if !cfg.HasSecrets() {
		t.Fatal("Expected secrets to exist after encryption")
	}

	// Now decrypt the file in-place
	proc2, err := processor.NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor for decryption: %v", err)
	}

	if _, err := proc2.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}

	decrypted, _, err := proc2.ProcessFile(testFile, false)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Write decrypted file (overwriting source)
	if err := os.WriteFile(testFile, decrypted, 0644); err != nil {
		t.Fatalf("Failed to write decrypted file: %v", err)
	}

	// Check if any encrypted values remain in all files
	allFiles, err := cfg.GetMatchingFiles()
	if err != nil {
		t.Fatalf("Failed to get matching files: %v", err)
	}

	hasAnyEncrypted := false
	for _, file := range allFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if proc2.HasEncryptedValues(content, file) {
			hasAnyEncrypted = true
			break
		}
	}

	// Simulate the ClearSecrets logic from decrypt command
	if !hasAnyEncrypted && cfg.HasSecrets() {
		cfg.ClearSecrets()
		if err := cfg.Save(); err != nil {
			t.Fatalf("Failed to save config: %v", err)
		}
	}

	// Verify secrets are cleared
	if cfg.HasSecrets() {
		t.Error("Expected secrets to be cleared after full decryption")
	}

	// Reload config and verify secrets are gone
	reloaded, err := config.Load(cfg.ConfigPath())
	if err != nil {
		t.Fatalf("Failed to reload config: %v", err)
	}

	if reloaded.HasSecrets() {
		t.Error("Expected secrets to be cleared in reloaded config")
	}
}

func TestSecretsPreservedWhenOutputPathDifferent(t *testing.T) {
	dir := t.TempDir()
	outputDir := filepath.Join(dir, "decrypted")

	// Generate keypair
	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Create config
	cfg := createTestConfigWithSecrets(t, dir, identity)

	// Create test file with sensitive data
	testFile := filepath.Join(dir, "test.yml")
	testContent := `database:
  host: localhost
  password: secret123
api_key: myapikey
`
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create processor and encrypt
	proc, err := processor.NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption: %v", err)
	}

	output, _, err := proc.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Write encrypted file
	if err := os.WriteFile(testFile, output, 0644); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}

	// Save secrets
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}

	// Verify secrets exist
	if !cfg.HasSecrets() {
		t.Fatal("Expected secrets to exist after encryption")
	}

	// Now decrypt the file to a DIFFERENT output path
	proc2, err := processor.NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor for decryption: %v", err)
	}

	if _, err := proc2.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}

	decrypted, _, err := proc2.ProcessFile(testFile, false)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Create output directory and write decrypted file there (NOT overwriting source)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatalf("Failed to create output directory: %v", err)
	}

	relPath, _ := filepath.Rel(cfg.ConfigDir(), testFile)
	outputFile := filepath.Join(outputDir, relPath)
	if err := os.WriteFile(outputFile, decrypted, 0644); err != nil {
		t.Fatalf("Failed to write decrypted file to output path: %v", err)
	}

	// Check if any encrypted values remain in SOURCE files (not output files)
	allFiles, err := cfg.GetMatchingFiles()
	if err != nil {
		t.Fatalf("Failed to get matching files: %v", err)
	}

	hasAnyEncrypted := false
	for _, file := range allFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if proc2.HasEncryptedValues(content, file) {
			hasAnyEncrypted = true
			break
		}
	}

	// Source files should still have encrypted values
	if !hasAnyEncrypted {
		t.Error("Expected source files to still have encrypted values")
	}

	// Simulate the ClearSecrets logic - should NOT clear because source files still encrypted
	if !hasAnyEncrypted && cfg.HasSecrets() {
		cfg.ClearSecrets()
		if err := cfg.Save(); err != nil {
			t.Fatalf("Failed to save config: %v", err)
		}
	}

	// Verify secrets are NOT cleared (because source files still encrypted)
	if !cfg.HasSecrets() {
		t.Error("Expected secrets to be preserved when output path is different from source")
	}

	// Verify the decrypted output file exists and has decrypted content
	outputContent, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	if strings.Contains(string(outputContent), "ENC[AES256_GCM,") {
		t.Error("Expected output file to be decrypted")
	}

	if !strings.Contains(string(outputContent), "secret123") {
		t.Error("Expected decrypted password in output file")
	}

	// Verify source file still has encrypted content
	sourceContent, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read source file: %v", err)
	}

	if !strings.Contains(string(sourceContent), "ENC[AES256_GCM,") {
		t.Error("Expected source file to still be encrypted")
	}
}

func TestClearSecretsWithOutputPathSameAsSource(t *testing.T) {
	dir := t.TempDir()

	// Generate keypair
	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Create config
	cfg := createTestConfigWithSecrets(t, dir, identity)

	// Create test file with sensitive data
	testFile := filepath.Join(dir, "test.yml")
	testContent := `database:
  host: localhost
  password: secret123
api_key: myapikey
`
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create processor and encrypt
	proc, err := processor.NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption: %v", err)
	}

	output, _, err := proc.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Write encrypted file
	if err := os.WriteFile(testFile, output, 0644); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}

	// Save secrets
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}

	// Verify secrets exist
	if !cfg.HasSecrets() {
		t.Fatal("Expected secrets to exist after encryption")
	}

	// Now decrypt with output-path="./" (same as source directory)
	proc2, err := processor.NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor for decryption: %v", err)
	}

	if _, err := proc2.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}

	decrypted, _, err := proc2.ProcessFile(testFile, false)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Simulate --output-path="./" which resolves to same directory
	outputPath := "./"
	outDir := outputPath
	if !filepath.IsAbs(outDir) {
		outDir = filepath.Join(cfg.ConfigDir(), outDir)
	}
	relPath, _ := filepath.Rel(cfg.ConfigDir(), testFile)
	outputFile := filepath.Join(outDir, relPath)

	// Write decrypted file (this should overwrite the source since paths resolve to same location)
	if err := os.WriteFile(outputFile, decrypted, 0644); err != nil {
		t.Fatalf("Failed to write decrypted file: %v", err)
	}

	// Check if any encrypted values remain in all files
	allFiles, err := cfg.GetMatchingFiles()
	if err != nil {
		t.Fatalf("Failed to get matching files: %v", err)
	}

	hasAnyEncrypted := false
	for _, file := range allFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if proc2.HasEncryptedValues(content, file) {
			hasAnyEncrypted = true
			break
		}
	}

	// Source files should now be decrypted (overwritten)
	if hasAnyEncrypted {
		t.Error("Expected source files to be decrypted when output-path='./'")
	}

	// Simulate the ClearSecrets logic - should clear because source files are now decrypted
	if !hasAnyEncrypted && cfg.HasSecrets() {
		cfg.ClearSecrets()
		if err := cfg.Save(); err != nil {
			t.Fatalf("Failed to save config: %v", err)
		}
	}

	// Verify secrets are cleared
	if cfg.HasSecrets() {
		t.Error("Expected secrets to be cleared when output-path='./' (same as source)")
	}
}
