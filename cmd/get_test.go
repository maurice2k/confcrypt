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

// noIdentity is an identity loader that fails the test when called.
func noIdentity(t *testing.T) processor.IdentityLoader {
	return func() ([]age.Identity, error) {
		t.Fatal("identity loader must not be called for plaintext values")
		return nil, nil
	}
}

// encryptFixtureFile encrypts file in place with the config's key, storing
// the key and the MAC.
func encryptFixtureFile(t *testing.T, cfg *config.Config, file string) {
	t.Helper()
	proc, err := processor.NewProcessor(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.SetupEncryption(); err != nil {
		t.Fatal(err)
	}
	out, _, err := proc.ProcessFile(file, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, out, 0644); err != nil {
		t.Fatal(err)
	}
	if err := proc.UpdateMAC(file, out); err != nil {
		t.Fatal(err)
	}
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatal(err)
	}
}

func mustGet(t *testing.T, cfg *config.Config, file string, loader processor.IdentityLoader, opts getOptions, paths ...string) string {
	t.Helper()
	out, err := performGet(cfg, file, paths, opts, loader)
	if err != nil {
		t.Fatalf("performGet(%v): %v", paths, err)
	}
	return string(out)
}

func TestGetPlaintextValueNeedsNoIdentity(t *testing.T) {
	cfg, _, testFile := createEncryptedYAMLFixture(t)
	if got := mustGet(t, cfg, testFile, noIdentity(t), getOptions{}, "database.host"); got != "localhost\n" {
		t.Errorf("got %q", got)
	}
}

func TestGetEncryptedScalarAndSubtree(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	loader := identityLoaderFor(identity)

	if got := mustGet(t, cfg, testFile, loader, getOptions{}, "database.password"); got != "secret123\n" {
		t.Errorf("scalar: got %q", got)
	}
	if got := mustGet(t, cfg, testFile, loader, getOptions{}, "database"); got != "host: localhost\npassword: secret123\n" {
		t.Errorf("subtree YAML: got %q", got)
	}
	if got := mustGet(t, cfg, testFile, loader, getOptions{JSON: true}, "database"); got != "{\n  \"host\": \"localhost\",\n  \"password\": \"secret123\"\n}\n" {
		t.Errorf("subtree JSON: got %q", got)
	}
	if got := mustGet(t, cfg, testFile, loader, getOptions{JSON: true}, "database.password"); got != "\"secret123\"\n" {
		t.Errorf("scalar JSON: got %q", got)
	}
	// The file on disk stays encrypted
	after, _ := os.ReadFile(testFile)
	if strings.Contains(string(after), "secret123") {
		t.Error("get must not modify the file")
	}
}

func TestGetMultiplePaths(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	loader := identityLoaderFor(identity)
	if got := mustGet(t, cfg, testFile, loader, getOptions{}, "database.host", "api_key"); got != "localhost\nmyapikey\n" {
		t.Errorf("lines: got %q", got)
	}
	want := "{\n  \"database.host\": \"localhost\",\n  \"database\": {\n    \"host\": \"localhost\",\n    \"password\": \"secret123\"\n  }\n}\n"
	if got := mustGet(t, cfg, testFile, loader, getOptions{JSON: true}, "database.host", "database"); got != want {
		t.Errorf("json object:\n got: %q\nwant: %q", got, want)
	}
}

func TestGetJSONFileWithListIndexAndTypes(t *testing.T) {
	dir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()
	cfg := createTestConfigWithFiles(t, dir, identity, "*.json")
	file := filepath.Join(dir, "c.json")
	if err := os.WriteFile(file, []byte("{\n  \"secret\": [\"a\", \"b\"],\n  \"n\": 5,\n  \"obj\": {\"password\": 42, \"ok\": true}\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	encryptFixtureFile(t, cfg, file)
	loader := identityLoaderFor(identity)

	if got := mustGet(t, cfg, file, loader, getOptions{}, "secret[1]"); got != "b\n" {
		t.Errorf("list index: got %q", got)
	}
	if got := mustGet(t, cfg, file, noIdentity(t), getOptions{JSON: true}, "n"); got != "5\n" {
		t.Errorf("number json: got %q", got)
	}
	if got := mustGet(t, cfg, file, loader, getOptions{}, "secret"); got != "[\n  \"a\",\n  \"b\"\n]\n" {
		t.Errorf("list subtree in file format: got %q", got)
	}
	if got := mustGet(t, cfg, file, loader, getOptions{YAML: true}, "obj"); got != "password: 42\nok: true\n" {
		t.Errorf("--yaml on JSON file: got %q", got)
	}
	if got := mustGet(t, cfg, file, loader, getOptions{}, "obj.password"); got != "42\n" {
		t.Errorf("typed scalar: got %q", got)
	}
}

func TestGetEnvFile(t *testing.T) {
	dir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()
	cfg := createTestConfigWithFiles(t, dir, identity, ".env")
	file := filepath.Join(dir, ".env")
	if err := os.WriteFile(file, []byte("API_KEY=\"quoted\"\nPLAIN=x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	encryptFixtureFile(t, cfg, file)
	if got := mustGet(t, cfg, file, identityLoaderFor(identity), getOptions{}, "API_KEY"); got != "\"quoted\"\n" {
		t.Errorf("env value keeps its quotes: got %q", got)
	}
	if got := mustGet(t, cfg, file, noIdentity(t), getOptions{}, "PLAIN"); got != "x\n" {
		t.Errorf("plain env value: got %q", got)
	}
}

func TestGetErrors(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	loader := identityLoaderFor(identity)

	for _, tc := range []struct{ path, want string }{
		{"database.nope", `key "nope" not found in database`},
		{"database[0]", "is not a list"},
		{"database.host.x", "is not a mapping"},
		{"a..b", "empty key"},
	} {
		_, err := performGet(cfg, testFile, []string{tc.path}, getOptions{}, loader)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want error containing %q", tc.path, err, tc.want)
		}
	}

	if _, err := performGet(cfg, testFile, []string{"database"}, getOptions{Doc: 1}, loader); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("doc index: got %v", err)
	}
	other := filepath.Join(cfg.ConfigDir(), "notes.txt")
	_ = os.WriteFile(other, []byte("x"), 0644)
	if _, err := performGet(cfg, other, []string{"a"}, getOptions{}, loader); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("pattern: got %v", err)
	}
}

func TestGetRefusesTamperedFileWithoutForce(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	content, _ := os.ReadFile(testFile)
	macProc, _ := processor.NewProcessor(cfg, nil)
	_ = macProc.SetupEncryptionWithIdentities([]age.Identity{identity})
	_ = macProc.UpdateMAC(testFile, content)
	_ = cfg.Save()

	// Drop the api_key line so the stored MAC no longer matches
	var kept []string
	for _, line := range strings.Split(string(content), "\n") {
		if !strings.HasPrefix(line, "api_key:") {
			kept = append(kept, line)
		}
	}
	_ = os.WriteFile(testFile, []byte(strings.Join(kept, "\n")), 0644)

	loader := identityLoaderFor(identity)
	if _, err := performGet(cfg, testFile, []string{"database.password"}, getOptions{}, loader); err == nil || !strings.Contains(err.Error(), "MAC") {
		t.Errorf("expected MAC error, got %v", err)
	}
	if got := mustGet(t, cfg, testFile, loader, getOptions{Force: true}, "database.password"); got != "secret123\n" {
		t.Errorf("--force: got %q", got)
	}
	// Plaintext reads never check the MAC
	if got := mustGet(t, cfg, testFile, noIdentity(t), getOptions{}, "database.host"); got != "localhost\n" {
		t.Errorf("plaintext on tampered file: got %q", got)
	}
}

func TestGetMultiDocumentYAML(t *testing.T) {
	dir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()
	cfg := createTestConfigWithFiles(t, dir, identity, "*.yml")
	file := filepath.Join(dir, "multi.yml")
	if err := os.WriteFile(file, []byte("name: first\npassword: one\n---\nname: second\npassword: two\n"), 0644); err != nil {
		t.Fatal(err)
	}
	encryptFixtureFile(t, cfg, file)
	loader := identityLoaderFor(identity)
	if got := mustGet(t, cfg, file, noIdentity(t), getOptions{Doc: 1}, "name"); got != "second\n" {
		t.Errorf("doc 1 name: got %q", got)
	}
	if got := mustGet(t, cfg, file, loader, getOptions{Doc: 1}, "password"); got != "two\n" {
		t.Errorf("doc 1 password: got %q", got)
	}
	if got := mustGet(t, cfg, file, loader, getOptions{}, "password"); got != "one\n" {
		t.Errorf("doc 0 password: got %q", got)
	}
}

func TestGetQuotedKeyAndAlias(t *testing.T) {
	dir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()
	cfg := createTestConfigWithFiles(t, dir, identity, "*.yml")
	file := filepath.Join(dir, "a.yml")
	if err := os.WriteFile(file, []byte("base: &b\n  password: shared\ncopy: *b\n\"dotted.key\":\n  api_key: k\n"), 0644); err != nil {
		t.Fatal(err)
	}
	encryptFixtureFile(t, cfg, file)
	loader := identityLoaderFor(identity)
	if got := mustGet(t, cfg, file, loader, getOptions{}, "copy.password"); got != "shared\n" {
		t.Errorf("alias: got %q", got)
	}
	if got := mustGet(t, cfg, file, loader, getOptions{}, `"dotted.key".api_key`); got != "k\n" {
		t.Errorf("quoted key: got %q", got)
	}
}
