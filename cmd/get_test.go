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

func TestGetRootPrintsDecryptedFileVerbatim(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	loader := identityLoaderFor(identity)
	want := "database:\n  host: localhost\n  password: secret123\napi_key: myapikey\n"
	if got := mustGet(t, cfg, testFile, loader, getOptions{Doc: -1}, "."); got != want {
		t.Errorf("root: got %q", got)
	}
	// Mixed with other paths, the root still prints the whole file
	if got := mustGet(t, cfg, testFile, loader, getOptions{Doc: -1}, "api_key", "."); got != "myapikey\n"+want {
		t.Errorf("root with others: got %q", got)
	}
	// --json re-renders the tree instead
	if got := mustGet(t, cfg, testFile, loader, getOptions{Doc: -1, JSON: true}, "."); !strings.HasPrefix(got, "{\n  \"database\": {") {
		t.Errorf("root json: got %q", got)
	}

	// JSONC keeps comments and layout byte for byte
	dir := t.TempDir()
	cfg2 := createTestConfigWithFiles(t, dir, identity, "*.jsonc")
	file := filepath.Join(dir, "s.jsonc")
	src := "// settings\n{\n\t\"password\": \"p\", // c\n\t\"n\": 1,\n}\n"
	_ = os.WriteFile(file, []byte(src), 0644)
	encryptFixtureFile(t, cfg2, file)
	if got := mustGet(t, cfg2, file, loader, getOptions{Doc: -1}, "."); got != src {
		t.Errorf("jsonc root:\n got: %q\nwant: %q", got, src)
	}
	// A plaintext file prints as-is without loading a key
	plain := filepath.Join(dir, "plain.jsonc")
	_ = os.WriteFile(plain, []byte("{\"n\": 1}"), 0644)
	if got := mustGet(t, cfg2, plain, noIdentity(t), getOptions{Doc: -1}, "."); got != "{\"n\": 1}\n" {
		t.Errorf("plain root: got %q", got)
	}

	// env files: whole file, and single variables
	cfg3 := createTestConfigWithFiles(t, dir, identity, ".env")
	env := filepath.Join(dir, ".env")
	envSrc := "# db\nexport DB_PASSWORD=one\nPLAIN=x\n"
	_ = os.WriteFile(env, []byte(envSrc), 0644)
	encryptFixtureFile(t, cfg3, env)
	if got := mustGet(t, cfg3, env, loader, getOptions{Doc: -1}, "."); got != envSrc {
		t.Errorf("env root:\n got: %q\nwant: %q", got, envSrc)
	}
	if got := mustGet(t, cfg3, env, loader, getOptions{Doc: -1}, "DB_PASSWORD", "PLAIN"); got != "one\nx\n" {
		t.Errorf("env values: got %q", got)
	}
}

func TestGetFullFile(t *testing.T) {
	dir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()
	cfg := createTestConfigWithFiles(t, dir, identity, "*.pem")
	file := filepath.Join(dir, "k.pem")
	src := "-----BEGIN KEY-----\nabc\n-----END KEY-----\n"
	_ = os.WriteFile(file, []byte(src), 0600)

	// Plaintext full file: printed as-is, no key needed
	if got := mustGet(t, cfg, file, noIdentity(t), getOptions{Doc: -1}, "."); got != src {
		t.Errorf("plain pem: got %q", got)
	}

	encryptFixtureFile(t, cfg, file)
	loader := identityLoaderFor(identity)
	if got := mustGet(t, cfg, file, loader, getOptions{Doc: -1}, "."); got != src {
		t.Errorf("encrypted pem: got %q", got)
	}
	if _, err := performGet(cfg, file, []string{"some.path"}, getOptions{Doc: -1}, loader); err == nil || !strings.Contains(err.Error(), "has no paths") {
		t.Errorf("path on full file: got %v", err)
	}

	// Tampered full file is refused without --force
	enc, _ := os.ReadFile(file)
	tampered := strings.Replace(string(enc), "tag:", "tag:A", 1)
	_ = os.WriteFile(file, []byte(tampered), 0600)
	if _, err := performGet(cfg, file, []string{"."}, getOptions{Doc: -1}, loader); err == nil || !strings.Contains(err.Error(), "MAC") {
		t.Errorf("tampered pem: got %v", err)
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
	// Root without --doc prints the whole decrypted stream; with --doc only that document
	whole := "name: first\npassword: one\n---\nname: second\npassword: two\n"
	if got := mustGet(t, cfg, file, loader, getOptions{Doc: -1}, "."); got != whole {
		t.Errorf("whole stream: got %q", got)
	}
	if got := mustGet(t, cfg, file, loader, getOptions{Doc: 1}, "."); got != "name: second\npassword: two\n" {
		t.Errorf("doc 1 root: got %q", got)
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
