package processor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"gopkg.in/yaml.v3"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/crypto"
	"github.com/maurice2k/confcrypt/internal/format"
)

// Helper to create a test config
func createTestConfig(t *testing.T, dir string, recipients []config.RecipientConfig) *config.Config {
	cfg := &config.Config{
		Recipients: recipients,
		Files:      []string{"*.yml", "*.yaml", "*.json"},
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

func TestProcessorEncryptDecryptRoundtrip(t *testing.T) {
	// Create temp directory
	dir := t.TempDir()

	// Generate keypair
	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Create config
	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	// Create test file
	testFile := filepath.Join(dir, "test.yml")
	testContent := `database:
  host: localhost
  password: secret123
  port: 5432
api_key: myapikey
`
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
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

	output, modified, err := proc.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if !modified {
		t.Error("Expected file to be modified")
	}

	// Verify encrypted values
	if !strings.Contains(string(output), "ENC[AES256_GCM,") {
		t.Error("Expected encrypted values in output")
	}

	// Write encrypted file
	if err := os.WriteFile(testFile, output, 0644); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}

	// Save secrets
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}

	// Create new processor for decryption
	proc2, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor for decryption: %v", err)
	}

	if _, err := proc2.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}

	decrypted, modified, err := proc2.ProcessFile(testFile, false)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !modified {
		t.Error("Expected file to be modified during decryption")
	}

	// Verify decrypted values
	if strings.Contains(string(decrypted), "ENC[AES256_GCM,") {
		t.Error("Expected no encrypted values after decryption")
	}

	if !strings.Contains(string(decrypted), "secret123") {
		t.Error("Expected original password value")
	}

	if !strings.Contains(string(decrypted), "myapikey") {
		t.Error("Expected original api_key value")
	}
}

func TestProcessorIdempotentEncryption(t *testing.T) {
	dir := t.TempDir()

	identity, _ := crypto.GenerateAgeKeypair()
	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	testFile := filepath.Join(dir, "test.yml")
	testContent := `password: secret123`
	os.WriteFile(testFile, []byte(testContent), 0644)

	// First encryption
	proc, _ := NewProcessor(cfg, nil)
	proc.SetupEncryption()
	output1, _, _ := proc.ProcessFile(testFile, true)
	os.WriteFile(testFile, output1, 0644)
	proc.SaveEncryptedSecrets()

	// Reload config to get the saved secrets
	cfg, _ = config.Load(cfg.ConfigPath())

	// Second encryption with identity loader
	identityLoader := func() ([]age.Identity, error) {
		return []age.Identity{identity}, nil
	}
	proc2, _ := NewProcessor(cfg, identityLoader)
	proc2.SetupEncryption()
	output2, modified, _ := proc2.ProcessFile(testFile, true)

	// Should not be modified (already encrypted)
	if modified {
		t.Error("Expected no modification on second encryption")
	}

	// Output should be same as input
	if string(output2) != string(output1) {
		t.Error("Expected identical output on second encryption")
	}
}

func TestProcessorCheckMode(t *testing.T) {
	dir := t.TempDir()

	identity, _ := crypto.GenerateAgeKeypair()
	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	testFile := filepath.Join(dir, "test.yml")
	testContent := `password: secret123
api_key: mykey
`
	os.WriteFile(testFile, []byte(testContent), 0644)

	proc, _ := NewProcessor(cfg, nil)

	// Check should find unencrypted values
	unencrypted, err := proc.CheckFile(testFile)
	if err != nil {
		t.Fatalf("CheckFile failed: %v", err)
	}

	if len(unencrypted) != 2 {
		t.Errorf("Expected 2 unencrypted keys, got %d", len(unencrypted))
	}

	// Encrypt
	proc.SetupEncryption()
	output, _, _ := proc.ProcessFile(testFile, true)
	os.WriteFile(testFile, output, 0644)

	// Check again - should find nothing
	unencrypted, _ = proc.CheckFile(testFile)
	if len(unencrypted) != 0 {
		t.Errorf("Expected 0 unencrypted keys after encryption, got %d", len(unencrypted))
	}
}

func TestProcessorJSONSupport(t *testing.T) {
	dir := t.TempDir()

	identity, _ := crypto.GenerateAgeKeypair()
	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	testFile := filepath.Join(dir, "test.json")
	testContent := `{
  "database": {
    "password": "secret123"
  },
  "api_key": "mykey"
}`
	os.WriteFile(testFile, []byte(testContent), 0644)

	proc, _ := NewProcessor(cfg, nil)
	proc.SetupEncryption()

	output, modified, err := proc.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Failed to process JSON: %v", err)
	}

	if !modified {
		t.Error("Expected JSON file to be modified")
	}

	if !strings.Contains(string(output), "ENC[AES256_GCM,") {
		t.Error("Expected encrypted values in JSON output")
	}

	// Verify it's still valid JSON
	var data map[string]interface{}
	if err := yaml.Unmarshal(output, &data); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}
}

func TestProcessorPreservesUnmatchedKeys(t *testing.T) {
	dir := t.TempDir()

	identity, _ := crypto.GenerateAgeKeypair()
	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	testFile := filepath.Join(dir, "test.yml")
	testContent := `password: secret123
username: admin
host: localhost
port: 5432
`
	os.WriteFile(testFile, []byte(testContent), 0644)

	proc, _ := NewProcessor(cfg, nil)
	proc.SetupEncryption()

	output, _, _ := proc.ProcessFile(testFile, true)

	// password should be encrypted
	if !strings.Contains(string(output), "ENC[AES256_GCM,") {
		t.Error("Expected password to be encrypted")
	}

	// Other values should be preserved
	if !strings.Contains(string(output), "admin") {
		t.Error("Expected username to be preserved")
	}
	if !strings.Contains(string(output), "localhost") {
		t.Error("Expected host to be preserved")
	}
	if !strings.Contains(string(output), "5432") {
		t.Error("Expected port to be preserved")
	}
}

func TestProcessorMixedEncrypted(t *testing.T) {
	dir := t.TempDir()

	identity, _ := crypto.GenerateAgeKeypair()
	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	testFile := filepath.Join(dir, "test.yml")

	// First, encrypt one value
	testContent := `password: secret123`
	os.WriteFile(testFile, []byte(testContent), 0644)

	proc, _ := NewProcessor(cfg, nil)
	proc.SetupEncryption()
	output, _, _ := proc.ProcessFile(testFile, true)
	os.WriteFile(testFile, output, 0644)
	proc.SaveEncryptedSecrets()

	// Reload config
	cfg, _ = config.Load(cfg.ConfigPath())

	// Now add another unencrypted value
	content, _ := os.ReadFile(testFile)
	newContent := string(content) + "api_key: newkey\n"
	os.WriteFile(testFile, []byte(newContent), 0644)

	// Create processor with identity loader to decrypt existing key
	identityLoader := func() ([]age.Identity, error) {
		return []age.Identity{identity}, nil
	}
	proc2, _ := NewProcessor(cfg, identityLoader)
	proc2.SetupEncryption()

	output2, modified, err := proc2.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Failed to process mixed file: %v", err)
	}

	if !modified {
		t.Error("Expected file to be modified (new secret added)")
	}

	// Both should be encrypted now
	encCount := strings.Count(string(output2), "ENC[AES256_GCM,")
	if encCount != 2 {
		t.Errorf("Expected 2 encrypted values, got %d", encCount)
	}
}

func TestProcessorTypePreservation(t *testing.T) {
	dir := t.TempDir()

	identity, _ := crypto.GenerateAgeKeypair()
	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	// Add more key patterns
	cfg.KeysInclude = append(cfg.KeysInclude, "int_secret", "float_secret", "bool_secret", "null_secret")

	testFile := filepath.Join(dir, "test.json")
	testContent := `{
  "password": "stringvalue",
  "int_secret": 42,
  "float_secret": 3.14,
  "bool_secret": true,
  "null_secret": null
}`
	os.WriteFile(testFile, []byte(testContent), 0644)

	proc, _ := NewProcessor(cfg, nil)
	proc.SetupEncryption()

	encrypted, _, _ := proc.ProcessFile(testFile, true)
	os.WriteFile(testFile, encrypted, 0644)
	proc.SaveEncryptedSecrets()

	// Decrypt
	proc2, _ := NewProcessor(cfg, nil)
	proc2.SetupDecryption([]age.Identity{identity}) //nolint:errcheck

	decrypted, _, err := proc2.ProcessFile(testFile, false)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify types are preserved
	var data map[string]interface{}
	if err := yaml.Unmarshal(decrypted, &data); err != nil {
		t.Fatalf("Failed to parse decrypted output: %v", err)
	}

	// Check types
	if _, ok := data["password"].(string); !ok {
		t.Error("password should be string")
	}
	// YAML unmarshals as int, JSON as float64 - check both
	switch v := data["int_secret"].(type) {
	case int:
		if v != 42 {
			t.Errorf("int_secret should be 42, got %v", v)
		}
	case int64:
		if v != 42 {
			t.Errorf("int_secret should be 42, got %v", v)
		}
	case float64:
		if v != 42 {
			t.Errorf("int_secret should be 42, got %v", v)
		}
	default:
		t.Errorf("int_secret has unexpected type %T(%v)", data["int_secret"], data["int_secret"])
	}
	if v, ok := data["float_secret"].(float64); !ok || v != 3.14 {
		t.Errorf("float_secret should be float64(3.14), got %T(%v)", data["float_secret"], data["float_secret"])
	}
	if v, ok := data["bool_secret"].(bool); !ok || v != true {
		t.Errorf("bool_secret should be bool(true), got %T(%v)", data["bool_secret"], data["bool_secret"])
	}
	if data["null_secret"] != nil {
		t.Errorf("null_secret should be nil, got %T(%v)", data["null_secret"], data["null_secret"])
	}
}

func TestMultipleRecipients(t *testing.T) {
	dir := t.TempDir()

	// Generate 2 keypairs
	identity1, _ := crypto.GenerateAgeKeypair()
	identity2, _ := crypto.GenerateAgeKeypair()

	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "user1", Age: identity1.Recipient().String()},
		{Name: "user2", Age: identity2.Recipient().String()},
	})

	testFile := filepath.Join(dir, "test.yml")
	testContent := `password: secret123`
	os.WriteFile(testFile, []byte(testContent), 0644)

	// Encrypt
	proc, _ := NewProcessor(cfg, nil)
	proc.SetupEncryption()
	output, _, _ := proc.ProcessFile(testFile, true)
	os.WriteFile(testFile, output, 0644)
	proc.SaveEncryptedSecrets()

	// Reload config
	cfg, _ = config.Load(cfg.ConfigPath())

	// Both recipients should be able to decrypt
	for i, identity := range []*age.X25519Identity{identity1, identity2} {
		proc, _ := NewProcessor(cfg, nil)
		_, err := proc.SetupDecryption([]age.Identity{identity})
		if err != nil {
			t.Errorf("Recipient %d failed to setup decryption: %v", i+1, err)
			continue
		}

		decrypted, _, err := proc.ProcessFile(testFile, false)
		if err != nil {
			t.Errorf("Recipient %d failed to decrypt: %v", i+1, err)
			continue
		}

		if !strings.Contains(string(decrypted), "secret123") {
			t.Errorf("Recipient %d got wrong decrypted value", i+1)
		}
	}
}

func TestAddRecipient(t *testing.T) {
	dir := t.TempDir()

	// Start with 2 recipients
	identity1, _ := crypto.GenerateAgeKeypair()
	identity2, _ := crypto.GenerateAgeKeypair()

	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "user1", Age: identity1.Recipient().String()},
		{Name: "user2", Age: identity2.Recipient().String()},
	})

	testFile := filepath.Join(dir, "test.yml")
	testContent := `password: secret123`
	os.WriteFile(testFile, []byte(testContent), 0644)

	// Encrypt with first 2 recipients
	proc, _ := NewProcessor(cfg, nil)
	proc.SetupEncryption()
	output, _, _ := proc.ProcessFile(testFile, true)
	os.WriteFile(testFile, output, 0644)
	proc.SaveEncryptedSecrets()

	// Reload config
	cfg, _ = config.Load(cfg.ConfigPath())

	// Add a third recipient
	identity3, _ := crypto.GenerateAgeKeypair()
	cfg.Recipients = append(cfg.Recipients, config.RecipientConfig{
		Name: "user3",
		Age:  identity3.Recipient().String(),
	})

	// Re-encrypt for all recipients (using identity1 to decrypt existing key)
	identityLoader := func() ([]age.Identity, error) {
		return []age.Identity{identity1}, nil
	}
	proc2, _ := NewProcessor(cfg, identityLoader)
	proc2.SetupEncryption()
	proc2.SaveEncryptedSecrets()

	// Reload config again
	cfg, _ = config.Load(cfg.ConfigPath())

	// All 3 recipients should be able to decrypt
	for i, identity := range []*age.X25519Identity{identity1, identity2, identity3} {
		proc, _ := NewProcessor(cfg, nil)
		_, err := proc.SetupDecryption([]age.Identity{identity})
		if err != nil {
			t.Errorf("Recipient %d failed to setup decryption after adding recipient: %v", i+1, err)
			continue
		}

		decrypted, _, err := proc.ProcessFile(testFile, false)
		if err != nil {
			t.Errorf("Recipient %d failed to decrypt after adding recipient: %v", i+1, err)
			continue
		}

		if !strings.Contains(string(decrypted), "secret123") {
			t.Errorf("Recipient %d got wrong decrypted value after adding recipient", i+1)
		}
	}
}

func TestRecipientAddRemove(t *testing.T) {
	dir := t.TempDir()

	// Start with 2 recipients
	identity1, _ := crypto.GenerateAgeKeypair()
	identity2, _ := crypto.GenerateAgeKeypair()

	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "user1", Age: identity1.Recipient().String()},
		{Name: "user2", Age: identity2.Recipient().String()},
	})

	testFile := filepath.Join(dir, "test.yml")
	testContent := `password: secret123`
	os.WriteFile(testFile, []byte(testContent), 0644)

	// Encrypt
	proc, _ := NewProcessor(cfg, nil)
	proc.SetupEncryption()
	output, _, _ := proc.ProcessFile(testFile, true)
	os.WriteFile(testFile, output, 0644)
	proc.SaveEncryptedSecrets()

	// Reload config
	cfg, _ = config.Load(cfg.ConfigPath())

	// Add a third recipient
	identity3, _ := crypto.GenerateAgeKeypair()
	cfg.Recipients = append(cfg.Recipients, config.RecipientConfig{
		Name: "user3",
		Age:  identity3.Recipient().String(),
	})

	// Re-encrypt for all recipients
	identityLoader := func() ([]age.Identity, error) {
		return []age.Identity{identity1}, nil
	}
	proc2, _ := NewProcessor(cfg, identityLoader)
	proc2.SetupEncryption()
	proc2.SaveEncryptedSecrets()

	// Reload config
	cfg, _ = config.Load(cfg.ConfigPath())

	// Remove recipient 2
	newRecipients := []config.RecipientConfig{}
	for _, r := range cfg.Recipients {
		if r.Age != identity2.Recipient().String() {
			newRecipients = append(newRecipients, r)
		}
	}
	cfg.Recipients = newRecipients

	// Re-encrypt for remaining recipients
	proc3, _ := NewProcessor(cfg, identityLoader)
	proc3.SetupEncryption()
	proc3.SaveEncryptedSecrets()

	// Reload config
	cfg, _ = config.Load(cfg.ConfigPath())

	// Recipients 1 and 3 should be able to decrypt
	for i, identity := range []*age.X25519Identity{identity1, identity3} {
		proc, _ := NewProcessor(cfg, nil)
		_, err := proc.SetupDecryption([]age.Identity{identity})
		if err != nil {
			t.Errorf("Remaining recipient %d failed to setup decryption: %v", i+1, err)
			continue
		}

		decrypted, _, err := proc.ProcessFile(testFile, false)
		if err != nil {
			t.Errorf("Remaining recipient %d failed to decrypt: %v", i+1, err)
			continue
		}

		if !strings.Contains(string(decrypted), "secret123") {
			t.Errorf("Remaining recipient %d got wrong decrypted value", i+1)
		}
	}

	// Recipient 2 should NOT be able to decrypt
	proc4, _ := NewProcessor(cfg, nil)
	_, err := proc4.SetupDecryption([]age.Identity{identity2})
	if err == nil {
		t.Error("Removed recipient should not be able to setup decryption")
	}
}

func TestMACComputation(t *testing.T) {
	dir := t.TempDir()

	identity, _ := crypto.GenerateAgeKeypair()
	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	testFile := filepath.Join(dir, "test.yml")
	testContent := `password: secret123`
	os.WriteFile(testFile, []byte(testContent), 0644)

	proc, _ := NewProcessor(cfg, nil)
	proc.SetupEncryption()

	output, _, _ := proc.ProcessFile(testFile, true)
	os.WriteFile(testFile, output, 0644)

	// Compute MAC
	mac, err := proc.ComputeMAC(output, FormatYAML)
	if err != nil {
		t.Fatalf("ComputeMAC failed: %v", err)
	}

	if len(mac) != 32 { // SHA256 produces 32 bytes
		t.Errorf("Expected 32 byte MAC, got %d", len(mac))
	}

	// Encrypt MAC
	encryptedMAC, err := proc.EncryptMAC(mac)
	if err != nil {
		t.Fatalf("EncryptMAC failed: %v", err)
	}

	if !format.IsEncrypted(encryptedMAC) {
		t.Error("Encrypted MAC should be in ENC format")
	}
}

func TestHasEncryptedValues(t *testing.T) {
	dir := t.TempDir()

	identity, _ := crypto.GenerateAgeKeypair()
	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	proc, _ := NewProcessor(cfg, nil)

	// Test with unencrypted content
	unencrypted := []byte(`password: secret123`)
	testFile := filepath.Join(dir, "test.yml")

	if proc.HasEncryptedValues(unencrypted, testFile) {
		t.Error("Should not detect encrypted values in plain content")
	}

	// Encrypt and test again
	proc.SetupEncryption()
	os.WriteFile(testFile, unencrypted, 0644)
	encrypted, _, _ := proc.ProcessFile(testFile, true)

	if !proc.HasEncryptedValues(encrypted, testFile) {
		t.Error("Should detect encrypted values in encrypted content")
	}
}

func TestStoreNotChangedWhenAddingNewValues(t *testing.T) {
	dir := t.TempDir()

	identity, _ := crypto.GenerateAgeKeypair()
	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	// Create initial file with one secret
	testFile := filepath.Join(dir, "test.yml")
	initialContent := `password: secret123`
	os.WriteFile(testFile, []byte(initialContent), 0644)

	// First encryption
	proc, _ := NewProcessor(cfg, nil)
	proc.SetupEncryption()
	output1, _, _ := proc.ProcessFile(testFile, true)
	os.WriteFile(testFile, output1, 0644)
	proc.SaveEncryptedSecrets()

	// Reload config and capture the store
	cfg, _ = config.Load(cfg.ConfigPath())
	originalStore := make([]config.SecretEntry, len(cfg.Confcrypt.Store))
	copy(originalStore, cfg.Confcrypt.Store)

	// Add a new unencrypted value to the file
	content, _ := os.ReadFile(testFile)
	newContent := string(content) + "\napi_key: newkey123\n"
	os.WriteFile(testFile, []byte(newContent), 0644)

	// Second encryption - should NOT change the store
	identityLoader := func() ([]age.Identity, error) {
		return []age.Identity{identity}, nil
	}
	proc2, _ := NewProcessor(cfg, identityLoader)
	proc2.SetupEncryption()
	output2, modified, _ := proc2.ProcessFile(testFile, true)

	if !modified {
		t.Error("Expected file to be modified (new secret added)")
	}

	os.WriteFile(testFile, output2, 0644)

	// Simulate what main.go does: if hadSecrets, just save config, don't call SaveEncryptedSecrets
	// Since cfg.HasSecrets() was true before SetupEncryption, we should just save config
	cfg.Save()

	// Reload and verify store hasn't changed
	cfg, _ = config.Load(cfg.ConfigPath())

	if len(cfg.Confcrypt.Store) != len(originalStore) {
		t.Errorf("Store length changed: was %d, now %d", len(originalStore), len(cfg.Confcrypt.Store))
	}

	for i, entry := range cfg.Confcrypt.Store {
		if entry.Recipient != originalStore[i].Recipient {
			t.Errorf("Store recipient changed at index %d", i)
		}
		if entry.Secret != originalStore[i].Secret {
			t.Errorf("Store secret changed at index %d - store should not be re-encrypted when adding new values", i)
		}
	}

	// Verify both values are now encrypted in the file
	finalContent, _ := os.ReadFile(testFile)
	encCount := strings.Count(string(finalContent), "ENC[AES256_GCM,")
	if encCount != 2 {
		t.Errorf("Expected 2 encrypted values, got %d", encCount)
	}

	// Verify we can still decrypt with the same key
	proc3, _ := NewProcessor(cfg, identityLoader)
	proc3.SetupDecryption([]age.Identity{identity}) //nolint:errcheck
	decrypted, _, err := proc3.ProcessFile(testFile, false)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !strings.Contains(string(decrypted), "secret123") {
		t.Error("Original password not found after decryption")
	}
	if !strings.Contains(string(decrypted), "newkey123") {
		t.Error("New api_key not found after decryption")
	}
}
