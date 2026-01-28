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

// Helper to create a test config with rename rules
func createTestConfigWithRename(t *testing.T, dir string, identity *age.X25519Identity) *config.Config {
	cfg := &config.Config{
		Recipients: []config.RecipientConfig{
			{Name: "test", Age: identity.Recipient().String()},
		},
		Files: []string{"*.yml", "*.yaml", "*.enc.yml", "*.enc.yaml"},
		RenameFiles: &config.RenameFilesConfig{
			Encrypt: []string{`/(\.\w+)$/.enc$1/`},
			Decrypt: []string{`/\.enc(\.\w+)$/$1/`},
		},
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

func TestEncryptWithRename(t *testing.T) {
	dir := t.TempDir()

	// Generate keypair
	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Create config with rename rules
	cfg := createTestConfigWithRename(t, dir, identity)

	// Create test file with sensitive data
	testFile := filepath.Join(dir, "config.yml")
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

	output, modified, err := proc.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if !modified {
		t.Fatal("Expected file to be modified")
	}

	// Get renamed path
	renamedFile, err := cfg.GetEncryptRename(testFile)
	if err != nil {
		t.Fatalf("Failed to get encrypt rename: %v", err)
	}

	expectedRenamedFile := filepath.Join(dir, "config.enc.yml")
	if renamedFile != expectedRenamedFile {
		t.Errorf("GetEncryptRename() = %q, want %q", renamedFile, expectedRenamedFile)
	}

	// Write to renamed path
	if err := os.WriteFile(renamedFile, output, 0644); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}

	// Delete original file (simulating what encrypt command does)
	if renamedFile != testFile {
		if err := os.Remove(testFile); err != nil {
			t.Fatalf("Failed to remove original file: %v", err)
		}
	}

	// Verify original file no longer exists
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("Expected original file to be deleted")
	}

	// Verify renamed file exists
	if _, err := os.Stat(renamedFile); os.IsNotExist(err) {
		t.Error("Expected renamed file to exist")
	}

	// Verify renamed file has encrypted content
	renamedContent, err := os.ReadFile(renamedFile)
	if err != nil {
		t.Fatalf("Failed to read renamed file: %v", err)
	}

	if !strings.Contains(string(renamedContent), "ENC[AES256_GCM,") {
		t.Error("Expected renamed file to have encrypted content")
	}

	// Update MAC for the renamed file
	renamedRelPath, _ := filepath.Rel(cfg.ConfigDir(), renamedFile)
	if err := proc.UpdateMAC(renamedFile, output); err != nil {
		t.Fatalf("Failed to update MAC: %v", err)
	}

	// Verify MAC is stored with renamed path
	mac, ok := cfg.GetMAC(renamedRelPath)
	if !ok {
		t.Error("Expected MAC to be stored for renamed file")
	}
	if mac == "" {
		t.Error("Expected MAC to be non-empty")
	}

	// Save secrets
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}
}

func TestDecryptWithRenameInPlace(t *testing.T) {
	dir := t.TempDir()

	// Generate keypair
	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Create config with rename rules
	cfg := createTestConfigWithRename(t, dir, identity)

	// Create test file with sensitive data and encrypt it first
	originalFile := filepath.Join(dir, "config.yml")
	testContent := `database:
  host: localhost
  password: secret123
api_key: myapikey
`
	if err := os.WriteFile(originalFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Encrypt the file
	proc, err := processor.NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption: %v", err)
	}

	encrypted, _, err := proc.ProcessFile(originalFile, true)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Write to renamed path (config.enc.yml)
	encryptedFile := filepath.Join(dir, "config.enc.yml")
	if err := os.WriteFile(encryptedFile, encrypted, 0644); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}

	// Delete original file
	if err := os.Remove(originalFile); err != nil {
		t.Fatalf("Failed to remove original file: %v", err)
	}

	// Save secrets
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}

	// Now decrypt the encrypted file in-place with rename
	proc2, err := processor.NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor for decryption: %v", err)
	}

	if _, err := proc2.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}

	decrypted, _, err := proc2.ProcessFile(encryptedFile, false)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Get decrypted rename path
	decryptedFile, err := cfg.GetDecryptRename(encryptedFile)
	if err != nil {
		t.Fatalf("Failed to get decrypt rename: %v", err)
	}

	expectedDecryptedFile := filepath.Join(dir, "config.yml")
	if decryptedFile != expectedDecryptedFile {
		t.Errorf("GetDecryptRename() = %q, want %q", decryptedFile, expectedDecryptedFile)
	}

	// Write to renamed path
	if err := os.WriteFile(decryptedFile, decrypted, 0644); err != nil {
		t.Fatalf("Failed to write decrypted file: %v", err)
	}

	// Delete encrypted file (simulating what decrypt command does)
	if decryptedFile != encryptedFile {
		if err := os.Remove(encryptedFile); err != nil {
			t.Fatalf("Failed to remove encrypted file: %v", err)
		}
	}

	// Verify encrypted file no longer exists
	if _, err := os.Stat(encryptedFile); !os.IsNotExist(err) {
		t.Error("Expected encrypted file to be deleted")
	}

	// Verify decrypted file exists at original name
	if _, err := os.Stat(decryptedFile); os.IsNotExist(err) {
		t.Error("Expected decrypted file to exist")
	}

	// Verify decrypted content
	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if strings.Contains(string(decryptedContent), "ENC[AES256_GCM,") {
		t.Error("Expected decrypted file to not have encrypted content")
	}

	if !strings.Contains(string(decryptedContent), "secret123") {
		t.Error("Expected decrypted file to have original password")
	}

	if !strings.Contains(string(decryptedContent), "myapikey") {
		t.Error("Expected decrypted file to have original api_key")
	}
}

func TestDecryptWithRenameAndOutputPath(t *testing.T) {
	dir := t.TempDir()
	outputDir := filepath.Join(dir, "decrypted")

	// Generate keypair
	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Create config with rename rules
	cfg := createTestConfigWithRename(t, dir, identity)

	// Create test file with sensitive data and encrypt it first
	originalFile := filepath.Join(dir, "config.yml")
	testContent := `database:
  host: localhost
  password: secret123
api_key: myapikey
`
	if err := os.WriteFile(originalFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Encrypt the file
	proc, err := processor.NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption: %v", err)
	}

	encrypted, _, err := proc.ProcessFile(originalFile, true)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Write to renamed path (config.enc.yml)
	encryptedFile := filepath.Join(dir, "config.enc.yml")
	if err := os.WriteFile(encryptedFile, encrypted, 0644); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}

	// Delete original file
	if err := os.Remove(originalFile); err != nil {
		t.Fatalf("Failed to remove original file: %v", err)
	}

	// Save secrets
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}

	// Now decrypt with --output-path
	proc2, err := processor.NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor for decryption: %v", err)
	}

	if _, err := proc2.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}

	decrypted, _, err := proc2.ProcessFile(encryptedFile, false)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Simulate --output-path behavior:
	// 1. Compute output path with relative path preserved
	relPath, _ := filepath.Rel(cfg.ConfigDir(), encryptedFile)
	outputFile := filepath.Join(outputDir, relPath)

	// 2. Apply rename rules to output path
	renamedOutputFile, err := cfg.GetDecryptRename(outputFile)
	if err != nil {
		t.Fatalf("Failed to get decrypt rename: %v", err)
	}

	// Expected: decrypted/config.yml (not decrypted/config.enc.yml)
	expectedOutputFile := filepath.Join(outputDir, "config.yml")
	if renamedOutputFile != expectedOutputFile {
		t.Errorf("GetDecryptRename() = %q, want %q", renamedOutputFile, expectedOutputFile)
	}

	// Create output directory
	if err := os.MkdirAll(filepath.Dir(renamedOutputFile), 0755); err != nil {
		t.Fatalf("Failed to create output directory: %v", err)
	}

	// Write to renamed output path
	if err := os.WriteFile(renamedOutputFile, decrypted, 0644); err != nil {
		t.Fatalf("Failed to write decrypted file: %v", err)
	}

	// Verify source file still exists (not deleted when using --output-path)
	if _, err := os.Stat(encryptedFile); os.IsNotExist(err) {
		t.Error("Expected source encrypted file to still exist when using --output-path")
	}

	// Verify source file still has encrypted content
	sourceContent, err := os.ReadFile(encryptedFile)
	if err != nil {
		t.Fatalf("Failed to read source file: %v", err)
	}

	if !strings.Contains(string(sourceContent), "ENC[AES256_GCM,") {
		t.Error("Expected source file to still have encrypted content")
	}

	// Verify output file exists at renamed path
	if _, err := os.Stat(renamedOutputFile); os.IsNotExist(err) {
		t.Error("Expected renamed output file to exist")
	}

	// Verify output file has decrypted content
	outputContent, err := os.ReadFile(renamedOutputFile)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	if strings.Contains(string(outputContent), "ENC[AES256_GCM,") {
		t.Error("Expected output file to be decrypted")
	}

	if !strings.Contains(string(outputContent), "secret123") {
		t.Error("Expected output file to have decrypted password")
	}

	// Verify the unrenamed file does NOT exist in output directory
	unrenamedOutputFile := filepath.Join(outputDir, "config.enc.yml")
	if _, err := os.Stat(unrenamedOutputFile); !os.IsNotExist(err) {
		t.Error("Expected unrenamed output file (config.enc.yml) to NOT exist")
	}
}
