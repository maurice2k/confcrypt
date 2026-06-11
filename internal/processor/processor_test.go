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

func TestAddMissingStoreRecipients(t *testing.T) {
	dir := t.TempDir()

	alice, _ := crypto.GenerateAgeKeypair()
	bob, _ := crypto.GenerateAgeKeypair()

	// Initial store has only Alice
	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "Alice", Age: alice.Recipient().String()},
	})
	proc, _ := NewProcessor(cfg, nil)
	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("setup encryption: %v", err)
	}
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("save secrets: %v", err)
	}

	// Reload and simulate a hand-edit that adds Bob to the recipients list
	cfg, _ = config.Load(cfg.ConfigPath())
	cfg.Recipients = append(cfg.Recipients, config.RecipientConfig{Name: "Bob", Age: bob.Recipient().String()})

	identityLoader := func() ([]age.Identity, error) {
		return []age.Identity{alice}, nil
	}
	proc2, _ := NewProcessor(cfg, identityLoader)

	added, err := proc2.AddMissingStoreRecipients()
	if err != nil {
		t.Fatalf("AddMissingStoreRecipients: %v", err)
	}
	if len(added) != 1 || added[0] != bob.Recipient().String() {
		t.Fatalf("expected Bob added, got %v", added)
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Bob (the new recipient) must now be able to decrypt the AES key,
	// proving the same key was reused.
	cfg, _ = config.Load(cfg.ConfigPath())
	if len(cfg.Confcrypt.Store) != 2 {
		t.Fatalf("expected 2 store entries, got %d", len(cfg.Confcrypt.Store))
	}
	procBob, _ := NewProcessor(cfg, nil)
	if _, err := procBob.SetupDecryption([]age.Identity{bob}); err != nil {
		t.Fatalf("Bob could not decrypt key after being added: %v", err)
	}

	// Calling again with no new recipients is a no-op.
	proc3, _ := NewProcessor(cfg, identityLoader)
	added2, err := proc3.AddMissingStoreRecipients()
	if err != nil {
		t.Fatalf("AddMissingStoreRecipients (2nd): %v", err)
	}
	if len(added2) != 0 {
		t.Fatalf("expected no additions on second run, got %v", added2)
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

func TestProcessorLazySetupLoadsExistingKeyOnlyWhenEncrypting(t *testing.T) {
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
	proc.SaveEncryptedSecrets()

	cfg, _ = config.Load(cfg.ConfigPath())

	loadCalls := 0
	identityLoader := func() ([]age.Identity, error) {
		loadCalls++
		return []age.Identity{identity}, nil
	}
	proc2, _ := NewProcessor(cfg, identityLoader)

	output, modified, err := proc2.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Processing already encrypted file failed: %v", err)
	}
	if modified {
		t.Error("Expected already encrypted file to remain unmodified")
	}
	if loadCalls != 0 {
		t.Fatalf("Identity loader called for no-op encryption: %d", loadCalls)
	}

	contentWithNewSecret := string(output) + "\napi_key: newkey\n"
	os.WriteFile(testFile, []byte(contentWithNewSecret), 0644)

	output, modified, err = proc2.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Lazy encryption of new value failed: %v", err)
	}
	if !modified {
		t.Error("Expected new api_key to be encrypted")
	}
	if loadCalls != 1 {
		t.Fatalf("Identity loader calls = %d, want 1", loadCalls)
	}
	if encCount := strings.Count(string(output), "ENC[AES256_GCM,"); encCount != 2 {
		t.Fatalf("Encrypted value count = %d, want 2", encCount)
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

func TestHasUnencryptedValuesDetectsNonStringYAMLScalars(t *testing.T) {
	dir := t.TempDir()

	identity, _ := crypto.GenerateAgeKeypair()
	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})
	cfg.KeysInclude = append(cfg.KeysInclude, "pin", "enabled")

	proc, _ := NewProcessor(cfg, nil)
	content := []byte("pin: 1234\nenabled: true\n")

	if !proc.HasUnencryptedValues(content, filepath.Join(dir, "test.yml")) {
		t.Fatal("Expected numeric/bool YAML scalars to be detected as needing encryption")
	}

	results, err := proc.CheckContent(content, FormatYAML)
	if err != nil {
		t.Fatalf("CheckContent failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("CheckContent returned %d results, want 2", len(results))
	}
}

// TestCheckContentSiblingPathsNotAliased guards against the path append-aliasing
// regression where sibling MatchResults all reported the same key name/path
// because they shared a backing array.
func TestCheckContentSiblingPathsNotAliased(t *testing.T) {
	identity, _ := crypto.GenerateAgeKeypair()
	cfg := createTestConfig(t, t.TempDir(), []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})
	cfg.KeysInclude = append(cfg.KeysInclude, "alpha", "beta", "gamma")

	proc, _ := NewProcessor(cfg, nil)

	check := func(t *testing.T, content []byte, ff FileFormat) {
		results, err := proc.CheckContent(content, ff)
		if err != nil {
			t.Fatalf("CheckContent failed: %v", err)
		}
		if len(results) != 3 {
			t.Fatalf("got %d results, want 3", len(results))
		}
		seen := map[string]bool{}
		for _, r := range results {
			joined := strings.Join(r.Path, ".")
			if seen[joined] {
				t.Fatalf("duplicate (aliased) path %q across siblings: %+v", joined, results)
			}
			seen[joined] = true
			if last := r.Path[len(r.Path)-1]; last != r.KeyName {
				t.Fatalf("path tail %q != KeyName %q (aliasing): %+v", last, r.KeyName, results)
			}
		}
	}

	t.Run("yaml", func(t *testing.T) {
		check(t, []byte("alpha: one\nbeta: two\ngamma: three\n"), FormatYAML)
	})
	t.Run("json", func(t *testing.T) {
		check(t, []byte(`{"alpha":"one","beta":"two","gamma":"three"}`), FormatJSON)
	})
}

func TestProcessorLazyEncryptionEncryptsNonStringYAMLScalar(t *testing.T) {
	dir := t.TempDir()

	identity, _ := crypto.GenerateAgeKeypair()
	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})
	cfg.KeysInclude = append(cfg.KeysInclude, "pin")

	testFile := filepath.Join(dir, "test.yml")
	os.WriteFile(testFile, []byte("pin: 1234\nname: service\n"), 0644)

	proc, _ := NewProcessor(cfg, nil)
	encrypted, modified, err := proc.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Lazy encryption failed: %v", err)
	}
	if !modified {
		t.Fatal("Expected numeric YAML scalar to be encrypted")
	}
	if !strings.Contains(string(encrypted), "pin: ENC[AES256_GCM,") {
		t.Fatalf("Expected pin to be encrypted, got:\n%s", string(encrypted))
	}
	if strings.Contains(string(encrypted), "pin: 1234") {
		t.Fatalf("Numeric secret remained in plaintext:\n%s", string(encrypted))
	}

	os.WriteFile(testFile, encrypted, 0644)
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save lazy-generated store: %v", err)
	}

	proc2, _ := NewProcessor(cfg, nil)
	if _, err := proc2.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}
	decrypted, _, err := proc2.ProcessFile(testFile, false)
	if err != nil {
		t.Fatalf("Failed to decrypt lazily encrypted value: %v", err)
	}
	if !strings.Contains(string(decrypted), "pin: 1234") {
		t.Fatalf("Expected numeric value to round-trip, got:\n%s", string(decrypted))
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

func TestYAMLCommentPreservation(t *testing.T) {
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

	// Create test file with comments
	testFile := filepath.Join(dir, "test.yml")
	testContent := `# This is a header comment
database:
  # Database host configuration
  host: localhost  # inline comment
  # The password below should be encrypted
  password: secret123
  port: 5432

# API configuration section
api:
  key: myapikey  # This should also be encrypted
  # Timeout in seconds
  timeout: 30
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

	// Encrypt
	encrypted, modified, err := proc.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if !modified {
		t.Error("Expected file to be modified")
	}

	encryptedStr := string(encrypted)

	// Verify comments are preserved after encryption
	commentsToCheck := []string{
		"# This is a header comment",
		"# Database host configuration",
		"# inline comment",
		"# The password below should be encrypted",
		"# API configuration section",
		"# This should also be encrypted",
		"# Timeout in seconds",
	}

	for _, comment := range commentsToCheck {
		if !strings.Contains(encryptedStr, comment) {
			t.Errorf("Comment not preserved after encryption: %q", comment)
		}
	}

	// Verify encrypted values
	if !strings.Contains(encryptedStr, "ENC[AES256_GCM,") {
		t.Error("Expected encrypted values in output")
	}

	// Write encrypted file for decryption test
	if err := os.WriteFile(testFile, encrypted, 0644); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}

	// Save secrets
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}

	// Setup decryption
	if _, err := proc.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}

	// Decrypt
	decrypted, modified, err := proc.ProcessFile(testFile, false)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !modified {
		t.Error("Expected file to be modified during decryption")
	}

	decryptedStr := string(decrypted)

	// Verify comments are preserved after decryption
	for _, comment := range commentsToCheck {
		if !strings.Contains(decryptedStr, comment) {
			t.Errorf("Comment not preserved after decryption: %q", comment)
		}
	}

	// Verify original values are restored
	if !strings.Contains(decryptedStr, "password: secret123") {
		t.Error("Original password not restored after decryption")
	}
	if !strings.Contains(decryptedStr, "key: myapikey") {
		t.Error("Original api_key not restored after decryption")
	}
}

func TestYAMLBlankLinePreservation(t *testing.T) {
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

	// Create test file with blank lines
	testFile := filepath.Join(dir, "test.yml")
	testContent := `database:
  host: localhost
  password: secret123

api:
  key: myapikey

  timeout: 30
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

	// Encrypt
	encrypted, modified, err := proc.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if !modified {
		t.Error("Expected file to be modified")
	}

	encryptedStr := string(encrypted)

	// Check that blank lines are preserved after encryption
	// There should be a blank line between "password: ..." and "api:"
	// And between "key: ..." and "timeout:"
	lines := strings.Split(encryptedStr, "\n")
	foundBlankBeforeApi := false
	foundBlankBeforeTimeout := false

	for i, line := range lines {
		if strings.HasPrefix(line, "api:") && i > 0 && strings.TrimSpace(lines[i-1]) == "" {
			foundBlankBeforeApi = true
		}
		if strings.HasPrefix(strings.TrimSpace(line), "timeout:") && i > 0 && strings.TrimSpace(lines[i-1]) == "" {
			foundBlankBeforeTimeout = true
		}
	}

	if !foundBlankBeforeApi {
		t.Error("Blank line before 'api:' not preserved after encryption")
	}
	if !foundBlankBeforeTimeout {
		t.Error("Blank line before 'timeout:' not preserved after encryption")
	}

	// Write encrypted file for decryption test
	if err := os.WriteFile(testFile, encrypted, 0644); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}

	// Save secrets
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}

	// Setup decryption
	if _, err := proc.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}

	// Decrypt
	decrypted, modified, err := proc.ProcessFile(testFile, false)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !modified {
		t.Error("Expected file to be modified during decryption")
	}

	decryptedStr := string(decrypted)

	// Check blank lines are preserved after decryption
	lines = strings.Split(decryptedStr, "\n")
	foundBlankBeforeApi = false
	foundBlankBeforeTimeout = false

	for i, line := range lines {
		if strings.HasPrefix(line, "api:") && i > 0 && strings.TrimSpace(lines[i-1]) == "" {
			foundBlankBeforeApi = true
		}
		if strings.HasPrefix(strings.TrimSpace(line), "timeout:") && i > 0 && strings.TrimSpace(lines[i-1]) == "" {
			foundBlankBeforeTimeout = true
		}
	}

	if !foundBlankBeforeApi {
		t.Error("Blank line before 'api:' not preserved after decryption")
	}
	if !foundBlankBeforeTimeout {
		t.Error("Blank line before 'timeout:' not preserved after decryption")
	}
}

func TestYAMLIndentedCommentsDoNotAddBlankLinesBetweenTopLevelKeys(t *testing.T) {
	dir := t.TempDir()

	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	testFile := filepath.Join(dir, "test.yml")
	testContent := `secret: supersecret

example_mapping:
  first: [one]
  second: [two] # inline note
  third: [three] # another inline note
  # Additional notes for this mapping.
  # These should stay attached to the mapping.

next_section:
  - item # inline note
`
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	proc, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption: %v", err)
	}

	encrypted, modified, err := proc.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if !modified {
		t.Fatal("Expected file to be modified")
	}

	if got := blankLinesBeforeKey(string(encrypted), "next_section:"); got != 1 {
		t.Fatalf("Expected exactly 1 blank line before next top-level key after encryption, got %d:\n%s", got, encrypted)
	}

	if err := os.WriteFile(testFile, encrypted, 0644); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}
	if _, err := proc.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}

	decrypted, modified, err := proc.ProcessFile(testFile, false)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if !modified {
		t.Fatal("Expected file to be modified during decryption")
	}

	if got := blankLinesBeforeKey(string(decrypted), "next_section:"); got != 1 {
		t.Fatalf("Expected exactly 1 blank line before next top-level key after decryption, got %d:\n%s", got, decrypted)
	}
}

func TestYAMLFlowSequenceBlankLinesBeforeNextItemAreStable(t *testing.T) {
	dir := t.TempDir()

	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	testFile := filepath.Join(dir, "test.yml")
	testContent := `secret: supersecret

base_settings: &baseSettings
  enabled: true
  mode: default

entries:
  - name: first
    !!merge <<: *baseSettings
    values: ["alpha", # first value
      "beta", # second value

      "gamma", # third value
    ]




  - name: second
    !!merge <<: *baseSettings
    value: delta
`
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	const expectedBlankLines = 4
	if got := blankLinesBeforeLine(testContent, "  - name: second"); got != expectedBlankLines {
		t.Fatalf("Test fixture should have %d blank lines before second entry, got %d", expectedBlankLines, got)
	}

	proc, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption: %v", err)
	}

	encrypted, modified, err := proc.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if !modified {
		t.Fatal("Expected file to be modified")
	}

	if got := blankLinesBeforeLine(string(encrypted), "  - name: second"); got != expectedBlankLines {
		t.Fatalf("Expected %d blank lines before second entry after encryption, got %d:\n%s", expectedBlankLines, got, encrypted)
	}

	if err := os.WriteFile(testFile, encrypted, 0644); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}
	if _, err := proc.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}

	decrypted, modified, err := proc.ProcessFile(testFile, false)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if !modified {
		t.Fatal("Expected file to be modified during decryption")
	}

	if got := blankLinesBeforeLine(string(decrypted), "  - name: second"); got != expectedBlankLines {
		t.Fatalf("Expected %d blank lines before second entry after decryption, got %d:\n%s", expectedBlankLines, got, decrypted)
	}
}

func TestYAMLLiteralBlockDoesNotAddBlankLineBeforeNextKey(t *testing.T) {
	dir := t.TempDir()

	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	testFile := filepath.Join(dir, "test.yml")
	testContent := `primary_password: |
  example-value

secondary_password: another-value
`
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	if got := blankLinesBeforeLine(testContent, "secondary_password: another-value"); got != 1 {
		t.Fatalf("Test fixture should have 1 blank line before secondary password, got %d", got)
	}

	proc, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption: %v", err)
	}

	encrypted, modified, err := proc.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if !modified {
		t.Fatal("Expected file to be modified")
	}

	if got := blankLinesBeforeLinePrefix(string(encrypted), "secondary_password:"); got != 1 {
		t.Fatalf("Expected exactly 1 blank line before secondary password after encryption, got %d:\n%s", got, encrypted)
	}

	if err := os.WriteFile(testFile, encrypted, 0644); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}
	if _, err := proc.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}

	decrypted, modified, err := proc.ProcessFile(testFile, false)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if !modified {
		t.Fatal("Expected file to be modified during decryption")
	}

	if got := blankLinesBeforeLine(string(decrypted), "secondary_password: another-value"); got != 1 {
		t.Fatalf("Expected exactly 1 blank line before secondary password after decryption, got %d:\n%s", got, decrypted)
	}
}

func TestYAMLMergeKeyDoesNotGainExplicitTag(t *testing.T) {
	dir := t.TempDir()

	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	testFile := filepath.Join(dir, "test.yml")
	testContent := `secret: supersecret

base_settings: &baseSettings
  enabled: true

entries:
  - name: example
    <<: *baseSettings
`
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	proc, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption: %v", err)
	}

	encrypted, modified, err := proc.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if !modified {
		t.Fatal("Expected file to be modified")
	}

	encryptedStr := string(encrypted)
	if strings.Contains(encryptedStr, "!!merge <<:") {
		t.Fatalf("Expected merge key to remain plain after encryption:\n%s", encryptedStr)
	}
	if !strings.Contains(encryptedStr, "<<: *baseSettings") {
		t.Fatalf("Expected plain merge key after encryption:\n%s", encryptedStr)
	}

	if err := os.WriteFile(testFile, encrypted, 0644); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}
	if _, err := proc.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}

	decrypted, modified, err := proc.ProcessFile(testFile, false)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if !modified {
		t.Fatal("Expected file to be modified during decryption")
	}

	decryptedStr := string(decrypted)
	if strings.Contains(decryptedStr, "!!merge <<:") {
		t.Fatalf("Expected merge key to remain plain after decryption:\n%s", decryptedStr)
	}
	if !strings.Contains(decryptedStr, "<<: *baseSettings") {
		t.Fatalf("Expected plain merge key after decryption:\n%s", decryptedStr)
	}
}

func TestYAMLExplicitMergeKeyTagIsRemoved(t *testing.T) {
	dir := t.TempDir()

	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	testFile := filepath.Join(dir, "test.yml")
	testContent := `secret: supersecret

base_settings: &baseSettings
  enabled: true

entries:
  - name: example
    !!merge <<: *baseSettings
`
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	proc, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption: %v", err)
	}

	encrypted, modified, err := proc.ProcessFile(testFile, true)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if !modified {
		t.Fatal("Expected file to be modified")
	}

	encryptedStr := string(encrypted)
	if strings.Contains(encryptedStr, "!!merge <<:") || strings.Contains(encryptedStr, "!!str <<:") {
		t.Fatalf("Expected explicit merge key tag to be removed after encryption:\n%s", encryptedStr)
	}
	if !strings.Contains(encryptedStr, "<<: *baseSettings") {
		t.Fatalf("Expected plain merge key after encryption:\n%s", encryptedStr)
	}
}

func blankLinesBeforeKey(content, key string) int {
	return blankLinesBeforeLine(content, key)
}

func blankLinesBeforeLine(content, target string) int {
	return blankLinesBeforeLineMatch(content, func(line string) bool {
		return line == target
	})
}

func blankLinesBeforeLinePrefix(content, prefix string) int {
	return blankLinesBeforeLineMatch(content, func(line string) bool {
		return strings.HasPrefix(line, prefix)
	})
}

func blankLinesBeforeLineMatch(content string, match func(string) bool) int {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if match(line) {
			count := 0
			for j := i - 1; j >= 0 && strings.TrimSpace(lines[j]) == ""; j-- {
				count++
			}
			return count
		}
	}
	return -1
}

func TestProcessorEnvFileEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()

	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Create config with .env file pattern and keys to encrypt
	cfg := &config.Config{
		Recipients: []config.RecipientConfig{
			{Name: "test", Age: identity.Recipient().String()},
		},
		Files: []string{"*.env", ".env*"},
		KeysInclude: []interface{}{
			"/.*_PASSWORD$/",
			"/.*_SECRET$/",
			"API_KEY",
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

	cfg, err = config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Create test .env file
	testFile := filepath.Join(dir, ".env")
	testContent := `# Database configuration
DB_HOST=localhost
DB_PORT=5432
DB_PASSWORD=supersecret123

# API configuration
API_KEY=myapikey456
API_URL=https://api.example.com

# App config
APP_SECRET=topsecret789
DEBUG=true
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

	outputStr := string(output)

	// Verify encrypted values
	if !strings.Contains(outputStr, "ENC[AES256_GCM,") {
		t.Error("Expected encrypted values in output")
	}

	// Verify non-secret values are NOT encrypted
	if !strings.Contains(outputStr, "DB_HOST=localhost") {
		t.Error("DB_HOST should not be encrypted")
	}
	if !strings.Contains(outputStr, "DB_PORT=5432") {
		t.Error("DB_PORT should not be encrypted")
	}
	if !strings.Contains(outputStr, "DEBUG=true") {
		t.Error("DEBUG should not be encrypted")
	}

	// Verify comments are preserved
	if !strings.Contains(outputStr, "# Database configuration") {
		t.Error("Comments should be preserved")
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

	decryptedStr := string(decrypted)

	// Verify decrypted values
	if strings.Contains(decryptedStr, "ENC[AES256_GCM,") {
		t.Error("Expected no encrypted values after decryption")
	}

	// Values may be quoted or unquoted after decryption
	if !strings.Contains(decryptedStr, "supersecret123") {
		t.Error("Expected original DB_PASSWORD value")
	}
	if !strings.Contains(decryptedStr, "myapikey456") {
		t.Error("Expected original API_KEY value")
	}
	if !strings.Contains(decryptedStr, "topsecret789") {
		t.Error("Expected original APP_SECRET value")
	}

	// Verify structure preserved
	if !strings.Contains(decryptedStr, "# Database configuration") {
		t.Error("Comments should be preserved after decryption")
	}
}

func TestProcessorEnvFileCheck(t *testing.T) {
	dir := t.TempDir()

	identity, _ := crypto.GenerateAgeKeypair()

	cfg := &config.Config{
		Recipients: []config.RecipientConfig{
			{Name: "test", Age: identity.Recipient().String()},
		},
		Files: []string{"*.env"},
		KeysInclude: []interface{}{
			"DB_PASSWORD",
			"API_KEY",
		},
	}

	configPath := filepath.Join(dir, ".confcrypt.yml")
	data, _ := yaml.Marshal(cfg)
	os.WriteFile(configPath, data, 0644)
	cfg, _ = config.Load(configPath)

	testFile := filepath.Join(dir, "app.env")
	testContent := `DB_HOST=localhost
DB_PASSWORD=secret
API_KEY=mykey
DEBUG=true`
	os.WriteFile(testFile, []byte(testContent), 0644)

	proc, _ := NewProcessor(cfg, nil)

	// Check should find unencrypted values
	results, err := proc.CheckFile(testFile)
	if err != nil {
		t.Fatalf("CheckFile() error = %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 unencrypted keys, got %d", len(results))
	}

	foundPassword := false
	foundApiKey := false
	for _, r := range results {
		if r.KeyName == "DB_PASSWORD" {
			foundPassword = true
		}
		if r.KeyName == "API_KEY" {
			foundApiKey = true
		}
	}

	if !foundPassword {
		t.Error("Expected to find DB_PASSWORD as unencrypted")
	}
	if !foundApiKey {
		t.Error("Expected to find API_KEY as unencrypted")
	}
}

func TestProcessorEnvQuotePreservation(t *testing.T) {
	dir := t.TempDir()

	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	cfg := &config.Config{
		Recipients: []config.RecipientConfig{
			{Name: "test", Age: identity.Recipient().String()},
		},
		Files: []string{"*.env"},
		KeysInclude: []interface{}{
			"UNQUOTED_SECRET",
			"QUOTED_SECRET",
		},
	}

	configPath := filepath.Join(dir, ".confcrypt.yml")
	data, _ := yaml.Marshal(cfg)
	os.WriteFile(configPath, data, 0644)
	cfg, _ = config.Load(configPath)

	// Create test file with mixed quoting
	testFile := filepath.Join(dir, ".env")
	testContent := `# Test quote preservation
UNQUOTED_SECRET=mysecret
QUOTED_SECRET="anothersecret"
NORMAL_VAR=value
`
	os.WriteFile(testFile, []byte(testContent), 0644)

	// Encrypt
	proc, _ := NewProcessor(cfg, nil)
	proc.SetupEncryption()
	encrypted, _, _ := proc.ProcessFile(testFile, true)
	encryptedStr := string(encrypted)

	// Both ENC values are unquoted (the quotes are inside the encrypted payload for quoted values)
	if !strings.Contains(encryptedStr, `UNQUOTED_SECRET=ENC[AES256_GCM,`) {
		t.Errorf("Encrypted UNQUOTED_SECRET should have ENC value, got:\n%s", encryptedStr)
	}
	if !strings.Contains(encryptedStr, `QUOTED_SECRET=ENC[AES256_GCM,`) {
		t.Errorf("Encrypted QUOTED_SECRET should have ENC value, got:\n%s", encryptedStr)
	}

	// Write encrypted file and save secrets
	os.WriteFile(testFile, encrypted, 0644)
	proc.SaveEncryptedSecrets()

	// Decrypt
	proc2, _ := NewProcessor(cfg, nil)
	proc2.SetupDecryption([]age.Identity{identity})
	decrypted, _, _ := proc2.ProcessFile(testFile, false)
	decryptedStr := string(decrypted)

	// Verify original quote styles are restored (raw bytes preserved)
	if !strings.Contains(decryptedStr, "UNQUOTED_SECRET=mysecret") {
		t.Errorf("Decrypted UNQUOTED_SECRET should be unquoted, got:\n%s", decryptedStr)
	}
	if !strings.Contains(decryptedStr, `QUOTED_SECRET="anothersecret"`) {
		t.Errorf("Decrypted QUOTED_SECRET should be quoted, got:\n%s", decryptedStr)
	}
}

func TestMatchFile(t *testing.T) {
	dir := t.TempDir()

	// Generate a real key pair for encryption
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	proc, err := NewProcessor(cfg, func() ([]age.Identity, error) {
		return []age.Identity{identity}, nil
	})
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// Write a YAML file with mixed encrypted/unencrypted keys
	yamlContent := `database:
  host: localhost
  password: supersecret
api:
  endpoint: https://api.example.com
  api_key: sk_live_12345
`
	yamlFile := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(yamlFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	// MatchFile should return all matching keys (unencrypted)
	results, err := proc.MatchFile(yamlFile)
	if err != nil {
		t.Fatalf("MatchFile error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("Expected 2 matching keys, got %d: %+v", len(results), results)
	}

	foundKeys := map[string]bool{}
	for _, r := range results {
		name := strings.Join(r.Path, ".")
		foundKeys[name] = true
		if r.Encrypted {
			t.Errorf("Key %q should not be encrypted yet", name)
		}
	}
	if !foundKeys["database.password"] {
		t.Error("Expected database.password in results")
	}
	if !foundKeys["api.api_key"] {
		t.Error("Expected api.api_key in results")
	}

	// Now encrypt the file
	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("SetupEncryption error: %v", err)
	}
	output, _, err := proc.ProcessFile(yamlFile, true)
	if err != nil {
		t.Fatalf("ProcessFile error: %v", err)
	}
	if err := os.WriteFile(yamlFile, output, 0644); err != nil {
		t.Fatal(err)
	}

	// MatchFile should still return all matching keys, now marked encrypted
	results, err = proc.MatchFile(yamlFile)
	if err != nil {
		t.Fatalf("MatchFile error after encrypt: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("Expected 2 matching keys after encrypt, got %d", len(results))
	}
	for _, r := range results {
		if !r.Encrypted {
			t.Errorf("Key %q should be encrypted", strings.Join(r.Path, "."))
		}
	}
}

func TestMatchFile_RelativePaths(t *testing.T) {
	dir := t.TempDir()

	// Create subdirectories
	sub1 := filepath.Join(dir, "sub1")
	sub2 := filepath.Join(dir, "sub1", "sub2")
	if err := os.MkdirAll(sub2, 0755); err != nil {
		t.Fatal(err)
	}

	// Create test files at various depths
	files := map[string]string{
		filepath.Join(dir, "root.yml"):    "password: secret1\n",
		filepath.Join(sub1, "nested.yml"): "password: secret2\n",
		filepath.Join(sub2, "deep.json"):  `{"password": "secret3"}`,
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"},
	})

	matched, err := cfg.GetMatchingFilesWithFormat()
	if err != nil {
		t.Fatalf("GetMatchingFilesWithFormat error: %v", err)
	}

	// Verify all matched paths are absolute and produce correct relative paths
	relPaths := map[string]bool{}
	for _, m := range matched {
		if !filepath.IsAbs(m.Path) {
			t.Errorf("Expected absolute path, got %q", m.Path)
		}
		rel, err := filepath.Rel(cfg.ConfigDir(), m.Path)
		if err != nil {
			t.Fatalf("filepath.Rel error: %v", err)
		}
		if strings.HasPrefix(rel, "..") {
			t.Errorf("Relative path %q escapes config dir", rel)
		}
		relPaths[rel] = true
	}

	expected := []string{"root.yml", filepath.Join("sub1", "nested.yml"), filepath.Join("sub1", "sub2", "deep.json")}
	for _, e := range expected {
		if !relPaths[e] {
			t.Errorf("Expected %q in matched files, got: %v", e, relPaths)
		}
	}
}
