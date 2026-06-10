package processor

import (
	"encoding/json"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestYAMLSequenceUnderMatchedKeyIsEncrypted(t *testing.T) {
	proc, identity, cfg := newMultiDocProcessor(t)

	original := `api_key:
  - key-one
  - key-two
other:
  - plain-item
`
	encrypted, modified, err := proc.ProcessContent([]byte(original), "test.yml", true, FormatYAML)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if !modified {
		t.Fatal("Expected sequence items under matched key to be encrypted")
	}
	for _, secret := range []string{"key-one", "key-two"} {
		if strings.Contains(string(encrypted), secret) {
			t.Errorf("Plaintext %q left in encrypted output:\n%s", secret, encrypted)
		}
	}
	if !strings.Contains(string(encrypted), "plain-item") {
		t.Error("Item under non-matched key should stay plaintext")
	}

	// MAC must cover the sequence items
	mac, err := proc.ComputeMAC(encrypted, FormatYAML)
	if err != nil {
		t.Fatalf("ComputeMAC failed: %v", err)
	}
	if len(mac) == 0 {
		t.Fatal("Expected non-empty MAC")
	}

	// Round-trip
	proc2, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	if _, err := proc2.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}
	decrypted, modified, err := proc2.ProcessContent(encrypted, "test.yml", false, FormatYAML)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if !modified {
		t.Fatal("Expected decryption to modify content")
	}
	for _, want := range []string{"key-one", "key-two", "plain-item"} {
		if !strings.Contains(string(decrypted), want) {
			t.Errorf("Decrypted output missing %q:\n%s", want, decrypted)
		}
	}
}

func TestYAMLSequenceUnderMatchedKeyReportedByCheck(t *testing.T) {
	proc, _, _ := newMultiDocProcessor(t)

	content := `api_key: ["key-one", "key-two"]
password: hunter2
`
	results, err := proc.CheckContent([]byte(content), FormatYAML)
	if err != nil {
		t.Fatalf("CheckContent failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("Expected 3 unencrypted values (2 items + password), got %d: %+v", len(results), results)
	}

	paths := make(map[string]bool)
	for _, r := range results {
		paths[strings.Join(r.Path, ".")] = true
	}
	for _, want := range []string{"api_key[0]", "api_key[1]", "password"} {
		if !paths[want] {
			t.Errorf("Expected path %q in check results, got %v", want, paths)
		}
	}
}

func TestYAMLAliasUnderMatchedKeyIsEncrypted(t *testing.T) {
	proc, identity, cfg := newMultiDocProcessor(t)

	original := `shared: &ref supersecret
password: *ref
`
	encrypted, modified, err := proc.ProcessContent([]byte(original), "test.yml", true, FormatYAML)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if !modified {
		t.Fatal("Expected alias target under matched key to be encrypted")
	}
	if strings.Contains(string(encrypted), "supersecret") {
		t.Errorf("Plaintext left in encrypted output:\n%s", encrypted)
	}
	// Anchor/alias structure must be preserved
	if !strings.Contains(string(encrypted), "&ref") || !strings.Contains(string(encrypted), "*ref") {
		t.Errorf("Anchor/alias structure lost:\n%s", encrypted)
	}

	// check must be silent now (everything encrypted)
	results, err := proc.CheckContent(encrypted, FormatYAML)
	if err != nil {
		t.Fatalf("CheckContent failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Expected no unencrypted values after encryption, got %+v", results)
	}

	// Round-trip
	proc2, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	if _, err := proc2.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}
	decrypted, _, err := proc2.ProcessContent(encrypted, "test.yml", false, FormatYAML)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if !strings.Contains(string(decrypted), "supersecret") {
		t.Errorf("Decryption did not restore alias target:\n%s", decrypted)
	}
}

func TestYAMLAliasUnderMatchedKeyReportedByCheck(t *testing.T) {
	proc, _, _ := newMultiDocProcessor(t)

	content := `shared: &ref supersecret
password: *ref
`
	results, err := proc.CheckContent([]byte(content), FormatYAML)
	if err != nil {
		t.Fatalf("CheckContent failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 unencrypted value (alias target), got %d: %+v", len(results), results)
	}
	if results[0].KeyName != "password" {
		t.Errorf("Expected finding under key 'password', got %q", results[0].KeyName)
	}
}

func TestJSONSequenceUnderMatchedKeyIsEncrypted(t *testing.T) {
	proc, identity, cfg := newMultiDocProcessor(t)

	original := `{
  "api_key": ["key-one", "key-two"],
  "other": ["plain-item"]
}`
	encrypted, modified, err := proc.ProcessContent([]byte(original), "test.json", true, FormatJSON)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if !modified {
		t.Fatal("Expected array items under matched key to be encrypted")
	}
	for _, secret := range []string{"key-one", "key-two"} {
		if strings.Contains(string(encrypted), secret) {
			t.Errorf("Plaintext %q left in encrypted output:\n%s", secret, encrypted)
		}
	}
	if !strings.Contains(string(encrypted), "plain-item") {
		t.Error("Item under non-matched key should stay plaintext")
	}

	// check on JSON must report the items beforehand
	results, err := proc.CheckContent([]byte(original), FormatJSON)
	if err != nil {
		t.Fatalf("CheckContent failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("Expected 2 unencrypted values, got %d: %+v", len(results), results)
	}

	// Round-trip
	proc2, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	if _, err := proc2.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}
	decrypted, _, err := proc2.ProcessContent(encrypted, "test.json", false, FormatJSON)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(decrypted, &result); err != nil {
		t.Fatalf("Decrypted output is not valid JSON: %v", err)
	}
	arr, _ := result["api_key"].([]interface{})
	if len(arr) != 2 || arr[0] != "key-one" || arr[1] != "key-two" {
		t.Errorf("Decrypted array wrong: %v", result["api_key"])
	}
}

func TestJSONLargeIntegersPreserved(t *testing.T) {
	proc, identity, cfg := newMultiDocProcessor(t)

	original := `{
  "password": 12345678901234567890,
  "snowflake_id": 98765432109876543210,
  "normal": 42
}`
	encrypted, modified, err := proc.ProcessContent([]byte(original), "test.json", true, FormatJSON)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if !modified {
		t.Fatal("Expected password to be encrypted")
	}

	// The untouched large integer must survive the re-marshal verbatim
	if !strings.Contains(string(encrypted), "98765432109876543210") {
		t.Errorf("Untouched large integer corrupted:\n%s", encrypted)
	}
	if strings.Contains(string(encrypted), "12345678901234567890") {
		t.Errorf("Matched large integer not encrypted:\n%s", encrypted)
	}

	// Round-trip restores the encrypted large integer exactly
	proc2, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	if _, err := proc2.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}
	decrypted, _, err := proc2.ProcessContent(encrypted, "test.json", false, FormatJSON)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	for _, want := range []string{"12345678901234567890", "98765432109876543210", "42"} {
		if !strings.Contains(string(decrypted), want) {
			t.Errorf("Decrypted output missing %q:\n%s", want, decrypted)
		}
	}
}

func TestMatchResultPathsNotAliased(t *testing.T) {
	proc, _, _ := newMultiDocProcessor(t)

	content := `a:
  b:
    password: one
    secret: two
    api_key: three
`
	results, err := proc.CheckContent([]byte(content), FormatYAML)
	if err != nil {
		t.Fatalf("CheckContent failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(results))
	}

	seen := make(map[string]bool)
	for _, r := range results {
		seen[strings.Join(r.Path, ".")] = true
	}
	for _, want := range []string{"a.b.password", "a.b.secret", "a.b.api_key"} {
		if !seen[want] {
			t.Errorf("Expected path %q, got %v - sibling paths overwrote each other", want, seen)
		}
	}
}

func TestEncryptedSequenceItemsCoveredByEncryptedValueDetection(t *testing.T) {
	proc, _, _ := newMultiDocProcessor(t)

	encrypted, _, err := proc.ProcessContent([]byte("api_key: [item-one]\n"), "test.yml", true, FormatYAML)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	hasEnc, err := proc.HasEncryptedValuesStrict(encrypted, "test.yml")
	if err != nil {
		t.Fatalf("HasEncryptedValuesStrict failed: %v", err)
	}
	if !hasEnc {
		t.Error("Encrypted sequence items not detected by HasEncryptedValuesStrict")
	}
}
