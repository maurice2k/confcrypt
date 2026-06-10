package processor

import (
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/crypto"
	"github.com/maurice2k/confcrypt/internal/format"
)

const multiDocYAML = `# first document
name: first
password: secret-one
---
# second document
name: second
password: secret-two
other: data
`

func newMultiDocProcessor(t *testing.T) (*Processor, *age.X25519Identity, *config.Config) {
	t.Helper()

	dir := t.TempDir()
	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	proc, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption: %v", err)
	}
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("Failed to save secrets: %v", err)
	}

	return proc, identity, cfg
}

func decodeAllDocs(t *testing.T, content []byte) []map[string]interface{} {
	t.Helper()

	values, err := decodeYAMLValues(content)
	if err != nil {
		t.Fatalf("Failed to decode YAML docs: %v", err)
	}
	docs := make([]map[string]interface{}, 0, len(values))
	for _, v := range values {
		m, ok := v.(map[string]interface{})
		if !ok {
			t.Fatalf("Expected mapping document, got %T", v)
		}
		docs = append(docs, m)
	}
	return docs
}

func TestProcessorMultiDocumentYAMLEncrypt(t *testing.T) {
	proc, identity, cfg := newMultiDocProcessor(t)

	encrypted, modified, err := proc.ProcessContent([]byte(multiDocYAML), "test.yml", true, FormatYAML)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if !modified {
		t.Fatal("Expected content to be modified")
	}

	docs := decodeAllDocs(t, encrypted)
	if len(docs) != 2 {
		t.Fatalf("Expected 2 documents after encryption, got %d:\n%s", len(docs), encrypted)
	}

	for i, doc := range docs {
		pw, _ := doc["password"].(string)
		if !format.IsEncrypted(pw) {
			t.Errorf("Document %d: password not encrypted: %q", i, pw)
		}
	}
	if docs[0]["name"] != "first" || docs[1]["name"] != "second" {
		t.Errorf("Document content lost: %v / %v", docs[0]["name"], docs[1]["name"])
	}
	if docs[1]["other"] != "data" {
		t.Errorf("Second document lost unrelated key: %v", docs[1]["other"])
	}

	// Plaintext must not survive anywhere in the encrypted output
	for _, secret := range []string{"secret-one", "secret-two"} {
		if strings.Contains(string(encrypted), secret) {
			t.Errorf("Plaintext %q leaked into encrypted output", secret)
		}
	}

	// Decrypt round-trip restores both documents
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

	docs = decodeAllDocs(t, decrypted)
	if len(docs) != 2 {
		t.Fatalf("Expected 2 documents after decryption, got %d", len(docs))
	}
	if docs[0]["password"] != "secret-one" || docs[1]["password"] != "secret-two" {
		t.Errorf("Decrypted passwords wrong: %v / %v", docs[0]["password"], docs[1]["password"])
	}
}

func TestProcessorMultiDocumentYAMLCheckAndMAC(t *testing.T) {
	proc, _, _ := newMultiDocProcessor(t)

	// CheckContent must report unencrypted values in ALL documents
	results, err := proc.CheckContent([]byte(multiDocYAML), FormatYAML)
	if err != nil {
		t.Fatalf("CheckContent failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("Expected 2 unencrypted values across documents, got %d: %+v", len(results), results)
	}

	encrypted, _, err := proc.ProcessContent([]byte(multiDocYAML), "test.yml", true, FormatYAML)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// HasEncryptedValuesStrict must see values in the second document too
	secondDocOnly := encrypted[:0:0]
	parts := strings.SplitN(string(encrypted), "---", 2)
	if len(parts) == 2 {
		secondDocOnly = []byte(parts[1])
	}
	hasEnc, err := proc.HasEncryptedValuesStrict(secondDocOnly, "test.yml")
	if err != nil {
		t.Fatalf("HasEncryptedValuesStrict failed: %v", err)
	}
	if !hasEnc {
		t.Error("Expected encrypted values to be detected in second document")
	}

	// The MAC must cover encrypted values from both documents: tampering
	// with the second document's ciphertext must change the MAC
	mac1, err := proc.ComputeMAC(encrypted, FormatYAML)
	if err != nil {
		t.Fatalf("ComputeMAC failed: %v", err)
	}

	// Re-encrypt the original: fresh IVs change the second document's
	// ciphertext, so the MAC must differ if it covers that document
	encrypted2, _, err := proc.ProcessContent([]byte(multiDocYAML), "test.yml", true, FormatYAML)
	if err != nil {
		t.Fatalf("Failed to re-encrypt: %v", err)
	}
	// Keep doc 1 from the first encryption, doc 2 from the second
	parts1 := strings.SplitN(string(encrypted), "\n---\n", 2)
	parts2 := strings.SplitN(string(encrypted2), "\n---\n", 2)
	if len(parts1) != 2 || len(parts2) != 2 {
		t.Fatalf("Expected two documents in encrypted outputs")
	}
	mixed := []byte(parts1[0] + "\n---\n" + parts2[1])

	mac2, err := proc.ComputeMAC(mixed, FormatYAML)
	if err != nil {
		t.Fatalf("ComputeMAC on mixed content failed: %v", err)
	}
	if string(mac1) == string(mac2) {
		t.Error("MAC unchanged when second document's ciphertext changed - MAC does not cover all documents")
	}
}

func TestProcessorAltKeyTrialDecryption(t *testing.T) {
	dir := t.TempDir()
	identity, err := crypto.GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})

	// Encrypt file A with key A and persist the store
	procA, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	if err := procA.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption: %v", err)
	}
	encryptedA, _, err := procA.ProcessContent([]byte("password: alpha\n"), "a.yml", true, FormatYAML)
	if err != nil {
		t.Fatalf("Failed to encrypt with key A: %v", err)
	}
	secretsA, err := procA.EncryptStoreEntries()
	if err != nil {
		t.Fatalf("Failed to build store entries for key A: %v", err)
	}

	// Simulate an interrupted rekey: generate key B, encrypt file B with it,
	// and leave the store in the transitional state holding both keys
	cfg.SetSecrets(secretsA)
	storeA := cfg.Confcrypt.Store
	cfg.Confcrypt.Store = nil

	procB, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	if err := procB.SetupEncryption(); err != nil {
		t.Fatalf("Failed to setup encryption with key B: %v", err)
	}
	encryptedB, _, err := procB.ProcessContent([]byte("password: beta\n"), "b.yml", true, FormatYAML)
	if err != nil {
		t.Fatalf("Failed to encrypt with key B: %v", err)
	}
	secretsB, err := procB.EncryptStoreEntries()
	if err != nil {
		t.Fatalf("Failed to build store entries for key B: %v", err)
	}

	cfg.Confcrypt.Store = storeA
	cfg.AddSecrets(secretsB)
	if len(cfg.Confcrypt.Store) != 2 {
		t.Fatalf("Expected transitional store with 2 entries, got %d", len(cfg.Confcrypt.Store))
	}

	// A fresh processor must decrypt files encrypted with EITHER key
	procC, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	if _, err := procC.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("Failed to setup decryption: %v", err)
	}

	decryptedA, _, err := procC.ProcessContent(encryptedA, "a.yml", false, FormatYAML)
	if err != nil {
		t.Fatalf("Failed to decrypt file encrypted with key A: %v", err)
	}
	if !strings.Contains(string(decryptedA), "password: alpha") {
		t.Errorf("Wrong plaintext for key A file: %s", decryptedA)
	}

	decryptedB, _, err := procC.ProcessContent(encryptedB, "b.yml", false, FormatYAML)
	if err != nil {
		t.Fatalf("Failed to decrypt file encrypted with key B (alt key): %v", err)
	}
	if !strings.Contains(string(decryptedB), "password: beta") {
		t.Errorf("Wrong plaintext for key B file: %s", decryptedB)
	}
}

func TestProcessorSingleDocumentYAMLUnchangedLayout(t *testing.T) {
	proc, identity, cfg := newMultiDocProcessor(t)

	original := `# header comment
database:
  host: localhost

  # the password
  password: secret123
`
	encrypted, _, err := proc.ProcessContent([]byte(original), "test.yml", true, FormatYAML)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	for _, comment := range []string{"# header comment", "# the password"} {
		if !strings.Contains(string(encrypted), comment) {
			t.Errorf("Comment %q lost during multi-doc-aware encryption", comment)
		}
	}

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
	// Blank lines may carry indentation whitespace after a round-trip
	// (pre-existing encoder behavior), so compare lines ignoring trailing spaces
	normalize := func(s string) string {
		lines := strings.Split(s, "\n")
		for i, l := range lines {
			lines[i] = strings.TrimRight(l, " ")
		}
		return strings.Join(lines, "\n")
	}
	if normalize(string(decrypted)) != normalize(original) {
		t.Errorf("Single-document round-trip changed layout:\n--- original ---\n%s\n--- decrypted ---\n%s", original, decrypted)
	}
}
