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

// fakeEditor writes a shell script that applies a sed expression to the file
// it is given, and returns the editor command string.
func fakeEditor(t *testing.T, sedExpr string) string {
	t.Helper()
	script := filepath.Join(t.TempDir(), "editor.sh")
	body := "#!/bin/sh\nsed -i.bak -e '" + sedExpr + "' \"$1\" && rm -f \"$1.bak\"\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatalf("write editor script: %v", err)
	}
	return script
}

func identityLoaderFor(identity age.Identity) processor.IdentityLoader {
	return func() ([]age.Identity, error) { return []age.Identity{identity}, nil }
}

func decryptFile(t *testing.T, cfg *config.Config, identity age.Identity, file string) string {
	t.Helper()
	reloaded, err := config.Load(cfg.ConfigPath())
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	proc, err := processor.NewProcessor(reloaded, nil)
	if err != nil {
		t.Fatalf("processor: %v", err)
	}
	if _, err := proc.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("setup decryption: %v", err)
	}
	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := proc.VerifyMAC(file, content); err != nil {
		t.Fatalf("MAC verification failed: %v", err)
	}
	out, _, err := proc.ProcessFile(file, false)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return string(out)
}

func TestEditChangesOneValueAndKeepsOtherCiphertext(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	before, _ := os.ReadFile(testFile)

	res, err := performEdit(cfg, testFile, identityLoaderFor(identity), fakeEditor(t, "s/myapikey/rotated-key/"), false)
	if err != nil {
		t.Fatalf("performEdit: %v", err)
	}
	if !res.changed || res.outputPath != testFile {
		t.Fatalf("unexpected result: %+v", res)
	}

	after, _ := os.ReadFile(testFile)
	if strings.Contains(string(after), "rotated-key") || strings.Contains(string(after), "secret123") {
		t.Fatalf("plaintext leaked into file:\n%s", after)
	}

	beforeLines := strings.Split(string(before), "\n")
	afterLines := strings.Split(string(after), "\n")
	if len(beforeLines) != len(afterLines) {
		t.Fatalf("line count changed:\n%s\n---\n%s", before, after)
	}
	for i := range beforeLines {
		isAPIKey := strings.HasPrefix(beforeLines[i], "api_key:")
		if isAPIKey && beforeLines[i] == afterLines[i] {
			t.Errorf("edited value kept old ciphertext: %s", afterLines[i])
		}
		if !isAPIKey && beforeLines[i] != afterLines[i] {
			t.Errorf("untouched line changed:\n  %s\n  %s", beforeLines[i], afterLines[i])
		}
	}

	decrypted := decryptFile(t, cfg, identity, testFile)
	if !strings.Contains(decrypted, "api_key: rotated-key") || !strings.Contains(decrypted, "password: secret123") {
		t.Errorf("unexpected decrypted content:\n%s", decrypted)
	}
}

func TestEditWithoutChangesWritesNothing(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	before, _ := os.ReadFile(testFile)
	cfgBefore, _ := os.ReadFile(cfg.ConfigPath())

	res, err := performEdit(cfg, testFile, identityLoaderFor(identity), fakeEditor(t, "s/nothing-here/never/"), false)
	if err != nil {
		t.Fatalf("performEdit: %v", err)
	}
	if res.changed {
		t.Fatal("expected no change")
	}
	after, _ := os.ReadFile(testFile)
	cfgAfter, _ := os.ReadFile(cfg.ConfigPath())
	if string(before) != string(after) {
		t.Error("file was rewritten although nothing changed")
	}
	if string(cfgBefore) != string(cfgAfter) {
		t.Error("config was rewritten although nothing changed")
	}
}

func TestEditRefusesTamperedFileWithoutForce(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	content, _ := os.ReadFile(testFile)

	// The fixture stores no MAC; record one so tampering is detectable
	macProc, err := processor.NewProcessor(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := macProc.SetupEncryptionWithIdentities([]age.Identity{identity}); err != nil {
		t.Fatal(err)
	}
	if err := macProc.UpdateMAC(testFile, content); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	// Tamper by dropping an encrypted value (the MAC covers the set of
	// encrypted values, not plaintext fields)
	var kept []string
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "api_key:") {
			continue
		}
		kept = append(kept, line)
	}
	tampered := strings.Join(kept, "\n")
	if err := os.WriteFile(testFile, []byte(tampered), 0644); err != nil {
		t.Fatal(err)
	}

	_, err = performEdit(cfg, testFile, identityLoaderFor(identity), fakeEditor(t, "s/x/y/"), false)
	if err == nil || !strings.Contains(err.Error(), "MAC") {
		t.Fatalf("expected MAC error, got %v", err)
	}

	res, err := performEdit(cfg, testFile, identityLoaderFor(identity), fakeEditor(t, "s/secret123/forced/"), true)
	if err != nil {
		t.Fatalf("performEdit with --force: %v", err)
	}
	if !res.changed {
		t.Fatal("expected change with --force")
	}
	decrypted := decryptFile(t, cfg, identity, testFile)
	if !strings.Contains(decrypted, "password: forced") {
		t.Errorf("unexpected decrypted content:\n%s", decrypted)
	}
}

func TestEditEditorFailureLeavesFileUntouched(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	before, _ := os.ReadFile(testFile)

	_, err := performEdit(cfg, testFile, identityLoaderFor(identity), "false", false)
	if err == nil || !strings.Contains(err.Error(), "editor") {
		t.Fatalf("expected editor error, got %v", err)
	}
	after, _ := os.ReadFile(testFile)
	if string(before) != string(after) {
		t.Error("file changed after editor failure")
	}
}

func TestEditPlaintextFileWithoutStoreCreatesKey(t *testing.T) {
	dir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()
	cfg := createTestConfigWithSecrets(t, dir, identity)
	testFile := filepath.Join(dir, "fresh.yml")
	if err := os.WriteFile(testFile, []byte("name: app\npassword: placeholder\n"), 0644); err != nil {
		t.Fatal(err)
	}

	res, err := performEdit(cfg, testFile, identityLoaderFor(identity), fakeEditor(t, "s/placeholder/real-secret/"), false)
	if err != nil {
		t.Fatalf("performEdit: %v", err)
	}
	if !res.changed {
		t.Fatal("expected change")
	}

	reloaded, err := config.Load(cfg.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.HasSecrets() {
		t.Fatal("expected key store to be created")
	}
	after, _ := os.ReadFile(testFile)
	if strings.Contains(string(after), "real-secret") || !strings.Contains(string(after), "ENC[") {
		t.Fatalf("expected encrypted output:\n%s", after)
	}
	decrypted := decryptFile(t, cfg, identity, testFile)
	if !strings.Contains(decrypted, "password: real-secret") {
		t.Errorf("unexpected decrypted content:\n%s", decrypted)
	}
}

func TestEditAppliesEncryptRenameForPlaintextFile(t *testing.T) {
	dir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()
	cfg := createTestConfigWithRename(t, dir, identity)
	testFile := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(testFile, []byte("password: placeholder\n"), 0644); err != nil {
		t.Fatal(err)
	}

	res, err := performEdit(cfg, testFile, identityLoaderFor(identity), fakeEditor(t, "s/placeholder/real/"), false)
	if err != nil {
		t.Fatalf("performEdit: %v", err)
	}
	want := filepath.Join(dir, "config.enc.yml")
	if res.outputPath != want {
		t.Fatalf("expected rename to %s, got %s", want, res.outputPath)
	}
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("original plaintext file should have been removed")
	}

	// Editing the already-encrypted file keeps its name
	res2, err := performEdit(cfg, want, identityLoaderFor(identity), fakeEditor(t, "s/real/newer/"), false)
	if err != nil {
		t.Fatalf("second performEdit: %v", err)
	}
	if res2.outputPath != want {
		t.Fatalf("encrypted file must keep its name, got %s", res2.outputPath)
	}
	if !strings.Contains(decryptFile(t, cfg, identity, want), "password: newer") {
		t.Error("second edit not applied")
	}
}

func TestEditRejectsFileOutsidePatterns(t *testing.T) {
	cfg, identity, _ := createEncryptedYAMLFixture(t)
	other := filepath.Join(cfg.ConfigDir(), "notes.txt")
	if err := os.WriteFile(other, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := performEdit(cfg, other, identityLoaderFor(identity), fakeEditor(t, "s/x/y/"), false)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected pattern error, got %v", err)
	}
}
