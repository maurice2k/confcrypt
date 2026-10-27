package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/format"
	"github.com/maurice2k/confcrypt/internal/processor"
)

func mustSet(t *testing.T, cfg *config.Config, file, path, value string, opts setOptions, loader processor.IdentityLoader) *setResult {
	t.Helper()
	res, err := performSet(cfg, file, path, value, opts, loader)
	if err != nil {
		t.Fatalf("performSet(%s): %v", path, err)
	}
	return res
}

// onlyLineChanged asserts that exactly the lines containing marker differ.
func onlyLineChanged(t *testing.T, before, after, marker string) {
	t.Helper()
	bl, al := strings.Split(before, "\n"), strings.Split(after, "\n")
	if len(bl) != len(al) {
		t.Fatalf("line count differs:\n%s\n---\n%s", before, after)
	}
	for i := range bl {
		if strings.Contains(bl[i], marker) != (bl[i] != al[i]) {
			t.Errorf("line %d: unexpected %s:\n  %s\n  %s", i, map[bool]string{true: "change", false: "no change"}[bl[i] != al[i]], bl[i], al[i])
		}
	}
}

func TestSetExistingSecretChangesOneLine(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	before, _ := os.ReadFile(testFile)

	res := mustSet(t, cfg, testFile, "database.password", "n3w", setOptions{}, identityLoaderFor(identity))
	if !res.changed || !res.encrypted || res.outputPath != testFile {
		t.Fatalf("unexpected result: %+v", res)
	}
	after, _ := os.ReadFile(testFile)
	onlyLineChanged(t, string(before), string(after), "password")
	if strings.Contains(string(after), "n3w") {
		t.Fatal("plaintext leaked")
	}
	if got := decryptFile(t, cfg, identity, testFile); !strings.Contains(got, "password: n3w") || !strings.Contains(got, "api_key: myapikey") {
		t.Errorf("unexpected decrypted content:\n%s", got)
	}

	// Same value again: nothing changes
	after2 := mustSet(t, cfg, testFile, "database.password", "n3w", setOptions{}, identityLoaderFor(identity))
	content2, _ := os.ReadFile(testFile)
	if after2.changed || string(content2) != string(after) {
		t.Error("setting the same value must not change the file")
	}
}

func TestSetPlaintextKeyNeedsNoIdentity(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	cfgBefore, _ := os.ReadFile(cfg.ConfigPath())
	res := mustSet(t, cfg, testFile, "database.host", "db.internal", setOptions{}, noIdentity(t))
	if !res.changed || res.encrypted {
		t.Fatalf("unexpected result: %+v", res)
	}
	after, _ := os.ReadFile(testFile)
	if !strings.Contains(string(after), "host: db.internal") {
		t.Errorf("value not set:\n%s", after)
	}
	cfgAfter, _ := os.ReadFile(cfg.ConfigPath())
	if string(cfgBefore) != string(cfgAfter) {
		t.Error("config (MAC) must not change when no ciphertext changed")
	}
	// Secrets still decrypt and the MAC still verifies
	if got := decryptFile(t, cfg, identity, testFile); !strings.Contains(got, "password: secret123") {
		t.Errorf("unexpected decrypted content:\n%s", got)
	}
}

func TestSetCreatesNestedKeysAndTypes(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	loader := identityLoaderFor(identity)
	mustSet(t, cfg, testFile, "cache.redis.port", "6379", setOptions{Type: format.TypeInt}, noIdentity(t))
	mustSet(t, cfg, testFile, "cache.redis.enabled", "true", setOptions{Type: format.TypeBool}, noIdentity(t))
	mustSet(t, cfg, testFile, "cache.redis.ttl", "1.5", setOptions{Type: format.TypeFloat}, noIdentity(t))
	mustSet(t, cfg, testFile, "cache.redis.nothing", "", setOptions{Type: format.TypeNull}, noIdentity(t))
	mustSet(t, cfg, testFile, "cache.redis.password", "rp", setOptions{}, loader)
	mustSet(t, cfg, testFile, "cache.redis.version", "0777", setOptions{}, noIdentity(t))

	got := decryptFile(t, cfg, identity, testFile)
	want := "cache:\n  redis:\n    port: 6379\n    enabled: true\n    ttl: 1.5\n    nothing: null\n    password: rp\n    version: \"0777\"\n"
	if !strings.Contains(got, want) {
		t.Errorf("unexpected decrypted content:\n%s\nwant to contain:\n%s", got, want)
	}
	raw, _ := os.ReadFile(testFile)
	if strings.Contains(string(raw), "password: rp") {
		t.Error("nested secret was not encrypted")
	}

	for _, tc := range []struct {
		value string
		typ   format.ValueType
	}{{"abc", format.TypeInt}, {"1.2.3", format.TypeFloat}, {"yes", format.TypeBool}, {"x", format.TypeNull}} {
		if _, err := performSet(cfg, testFile, "cache.x", tc.value, setOptions{Type: tc.typ}, noIdentity(t)); err == nil {
			t.Errorf("expected type error for %q as %s", tc.value, tc.typ)
		}
	}
}

func TestSetListItemsAndAppend(t *testing.T) {
	dir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()
	cfg := createTestConfigWithFiles(t, dir, identity, "*.yml")
	file := filepath.Join(dir, "l.yml")
	_ = os.WriteFile(file, []byte("hosts:\n  - a\n  - b\nsecret:\n  - s1\n"), 0644)
	encryptFixtureFile(t, cfg, file)
	loader := identityLoaderFor(identity)

	mustSet(t, cfg, file, "hosts[1]", "B", setOptions{}, noIdentity(t))
	mustSet(t, cfg, file, "hosts[+]", "c", setOptions{}, noIdentity(t))
	res := mustSet(t, cfg, file, "secret[+]", "s2", setOptions{}, loader)
	if !res.encrypted {
		t.Error("item appended under a matched key must be encrypted")
	}
	mustSet(t, cfg, file, "servers[+].name", "srv", setOptions{}, noIdentity(t))
	mustSet(t, cfg, file, "servers[0].password", "pw", setOptions{}, loader)

	got := decryptFile(t, cfg, identity, file)
	want := "hosts:\n  - a\n  - B\n  - c\nsecret:\n  - s1\n  - s2\nservers:\n  - name: srv\n    password: pw\n"
	if got != want {
		t.Errorf("unexpected decrypted content:\n got: %q\nwant: %q", got, want)
	}
	raw, _ := os.ReadFile(file)
	if strings.Count(string(raw), "ENC[") != 3 {
		t.Errorf("expected 3 encrypted values:\n%s", raw)
	}

	if _, err := performSet(cfg, file, "hosts[9]", "x", setOptions{}, noIdentity(t)); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("index out of range: got %v", err)
	}
	if _, err := performSet(cfg, file, "hosts.key", "x", setOptions{}, noIdentity(t)); err == nil || !strings.Contains(err.Error(), "not a mapping") {
		t.Errorf("key on list: got %v", err)
	}
	if _, err := performSet(cfg, file, "hosts[0].key", "x", setOptions{}, noIdentity(t)); err == nil || !strings.Contains(err.Error(), "not a mapping") {
		t.Errorf("key on scalar: got %v", err)
	}
}

func TestSetDelete(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	loader := identityLoaderFor(identity)
	content, _ := os.ReadFile(testFile)
	macProc, _ := processor.NewProcessor(cfg, nil)
	_ = macProc.SetupEncryptionWithIdentities([]age.Identity{identity})
	_ = macProc.UpdateMAC(testFile, content)
	_ = cfg.Save()

	// Deleting a plaintext key needs no identity and leaves the MAC alone
	res := mustSet(t, cfg, testFile, "database.host", "", setOptions{Delete: true}, noIdentity(t))
	if !res.changed {
		t.Fatal("expected change")
	}
	// Deleting an encrypted key updates the MAC (and verifies it first)
	mustSet(t, cfg, testFile, "api_key", "", setOptions{Delete: true}, loader)
	got := decryptFile(t, cfg, identity, testFile)
	if got != "database:\n  password: secret123\n" {
		t.Errorf("unexpected content after deletes: %q", got)
	}

	if _, err := performSet(cfg, testFile, "nope", "", setOptions{Delete: true}, noIdentity(t)); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("delete missing: got %v", err)
	}

	// Deleting the last encrypted value drops the MAC
	mustSet(t, cfg, testFile, "database.password", "", setOptions{Delete: true}, loader)
	reloaded, _ := config.Load(cfg.ConfigPath())
	if _, ok := reloaded.GetMAC("test.yml"); ok {
		t.Error("MAC should be removed when no encrypted values remain")
	}

	// List items
	dir := t.TempDir()
	cfg2 := createTestConfigWithFiles(t, dir, identity, "*.yml")
	file := filepath.Join(dir, "l.yml")
	_ = os.WriteFile(file, []byte("hosts: [a, b, c]\n"), 0644)
	mustSet(t, cfg2, file, "hosts[1]", "", setOptions{Delete: true}, noIdentity(t))
	raw, _ := os.ReadFile(file)
	if string(raw) != "hosts: [a, c]\n" {
		t.Errorf("delete list item: got %q", raw)
	}
}

func TestSetJSONCKeepsCommentsAndLayout(t *testing.T) {
	dir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()
	cfg := createTestConfigWithFiles(t, dir, identity, "*.jsonc")
	file := filepath.Join(dir, "s.jsonc")
	src := "// settings\n{\n\t\"db\": {\n\t\t\"password\": \"old\", // rotate\n\t\t\"port\": 5432,\n\t},\n\t\"list\": [1, 2],\n}\n"
	_ = os.WriteFile(file, []byte(src), 0644)
	encryptFixtureFile(t, cfg, file)
	before, _ := os.ReadFile(file)
	loader := identityLoaderFor(identity)

	mustSet(t, cfg, file, "db.password", "new", setOptions{}, loader)
	after, _ := os.ReadFile(file)
	onlyLineChanged(t, string(before), string(after), "password")

	mustSet(t, cfg, file, "db.port", "6543", setOptions{Type: format.TypeInt}, noIdentity(t))
	mustSet(t, cfg, file, "list[+]", "3", setOptions{Type: format.TypeInt}, noIdentity(t))
	mustSet(t, cfg, file, "db.name", "app", setOptions{}, noIdentity(t))
	got := decryptFile(t, cfg, identity, file)
	want := "// settings\n{\n\t\"db\": {\n\t\t\"password\": \"new\", // rotate\n\t\t\"port\": 6543,\n\t\t\"name\": \"app\",\n\t},\n\t\"list\": [1, 2, 3],\n}\n"
	if got != want {
		t.Errorf("unexpected content:\n got: %q\nwant: %q", got, want)
	}
}

func TestSetEnvFile(t *testing.T) {
	dir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()
	cfg := createTestConfigWithFiles(t, dir, identity, ".env")
	file := filepath.Join(dir, ".env")
	_ = os.WriteFile(file, []byte("# db\nDB_PASSWORD=old\nPLAIN=x\n"), 0644)
	encryptFixtureFile(t, cfg, file)
	loader := identityLoaderFor(identity)

	mustSet(t, cfg, file, "DB_PASSWORD", "\"quoted new\"", setOptions{}, loader)
	mustSet(t, cfg, file, "PLAIN", "y", setOptions{}, noIdentity(t))
	mustSet(t, cfg, file, "OTHER_PASSWORD", "k", setOptions{}, loader)
	got := decryptFile(t, cfg, identity, file)
	if got != "# db\nDB_PASSWORD=\"quoted new\"\nPLAIN=y\nOTHER_PASSWORD=k\n" {
		t.Errorf("unexpected env content: %q", got)
	}
	raw, _ := os.ReadFile(file)
	if strings.Count(string(raw), "ENC[") != 2 {
		t.Errorf("expected 2 encrypted vars:\n%s", raw)
	}
	if _, err := performSet(cfg, file, "A.B", "x", setOptions{}, noIdentity(t)); err == nil || !strings.Contains(err.Error(), "flat") {
		t.Errorf("nested env key: got %v", err)
	}
}

func TestSetDryRunWritesNothing(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	before, _ := os.ReadFile(testFile)
	cfgBefore, _ := os.ReadFile(cfg.ConfigPath())
	res := mustSet(t, cfg, testFile, "database.host", "dry", setOptions{DryRun: true}, identityLoaderFor(identity))
	if !res.changed || !strings.Contains(string(res.output), "host: dry") {
		t.Errorf("dry run output: %q", res.output)
	}
	after, _ := os.ReadFile(testFile)
	cfgAfter, _ := os.ReadFile(cfg.ConfigPath())
	if string(before) != string(after) || string(cfgBefore) != string(cfgAfter) {
		t.Error("dry run must not write")
	}
}

func TestSetFirstSecretCreatesStoreAndRenames(t *testing.T) {
	dir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()
	cfg := createTestConfigWithRename(t, dir, identity)
	file := filepath.Join(dir, "config.yml")
	_ = os.WriteFile(file, []byte("name: app\n"), 0644)

	res := mustSet(t, cfg, file, "password", "first", setOptions{}, identityLoaderFor(identity))
	want := filepath.Join(dir, "config.enc.yml")
	if res.outputPath != want {
		t.Fatalf("expected rename to %s, got %s", want, res.outputPath)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Error("plaintext original should be gone")
	}
	reloaded, _ := config.Load(cfg.ConfigPath())
	if !reloaded.HasSecrets() {
		t.Error("key store should be created")
	}
	if got := decryptFile(t, cfg, identity, want); got != "name: app\npassword: first\n" {
		t.Errorf("unexpected content: %q", got)
	}
}

func TestSetFullFile(t *testing.T) {
	dir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()
	cfg := createTestConfigWithFiles(t, dir, identity, "*.pem")
	file := filepath.Join(dir, "k.pem")
	_ = os.WriteFile(file, []byte("old\n"), 0600)
	loader := identityLoaderFor(identity)

	res := mustSet(t, cfg, file, ".", "new cert\n", setOptions{}, loader)
	if !res.changed || !res.encrypted {
		t.Fatalf("unexpected result: %+v", res)
	}
	raw, _ := os.ReadFile(file)
	if !strings.HasPrefix(string(raw), "$CONFCRYPT_ENCRYPTED;") {
		t.Fatalf("expected full-file ciphertext: %q", raw)
	}
	if got := decryptFile(t, cfg, identity, file); got != "new cert\n" {
		t.Errorf("unexpected content: %q", got)
	}
	if again := mustSet(t, cfg, file, ".", "new cert\n", setOptions{}, loader); again.changed {
		t.Error("same content must be a no-op")
	}
	if _, err := performSet(cfg, file, "x", "v", setOptions{}, loader); err == nil || !strings.Contains(err.Error(), "no paths") {
		t.Errorf("path on full file: got %v", err)
	}
	if _, err := performSet(cfg, file, ".", "", setOptions{Delete: true}, loader); err == nil {
		t.Error("delete on full file must fail")
	}
}

func TestSetRefusesTamperedFileWithoutForce(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	content, _ := os.ReadFile(testFile)
	macProc, _ := processor.NewProcessor(cfg, nil)
	_ = macProc.SetupEncryptionWithIdentities([]age.Identity{identity})
	_ = macProc.UpdateMAC(testFile, content)
	_ = cfg.Save()
	var kept []string
	for _, line := range strings.Split(string(content), "\n") {
		if !strings.HasPrefix(line, "api_key:") {
			kept = append(kept, line)
		}
	}
	_ = os.WriteFile(testFile, []byte(strings.Join(kept, "\n")), 0644)
	loader := identityLoaderFor(identity)

	if _, err := performSet(cfg, testFile, "database.password", "x", setOptions{}, loader); err == nil || !strings.Contains(err.Error(), "MAC") {
		t.Errorf("expected MAC error, got %v", err)
	}
	// Plaintext changes don't need the key and therefore don't verify
	mustSet(t, cfg, testFile, "database.host", "h", setOptions{}, noIdentity(t))
	mustSet(t, cfg, testFile, "database.password", "x", setOptions{Force: true}, loader)
	if got := decryptFile(t, cfg, identity, testFile); !strings.Contains(got, "password: x") {
		t.Errorf("--force set not applied: %q", got)
	}
}

func TestSetRootPathRejectedForStructuredFiles(t *testing.T) {
	cfg, _, testFile := createEncryptedYAMLFixture(t)
	if _, err := performSet(cfg, testFile, ".", "x", setOptions{}, noIdentity(t)); err == nil || !strings.Contains(err.Error(), "edit") {
		t.Errorf("root path: got %v", err)
	}
}

func TestParseValueType(t *testing.T) {
	for in, want := range map[string]format.ValueType{"": format.TypeString, "STR": format.TypeString, "int": format.TypeInt, "Float": format.TypeFloat, "bool": format.TypeBool, "null": format.TypeNull} {
		got, err := parseValueType(in)
		if err != nil || got != want {
			t.Errorf("parseValueType(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := parseValueType("bytes"); err == nil {
		t.Error("expected error for unknown type")
	}
}
