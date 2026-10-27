package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"gopkg.in/yaml.v3"

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

// createTestConfigWithFiles writes a .confcrypt.yml with the given file
// patterns and the fixture key rules.
func createTestConfigWithFiles(t *testing.T, dir string, identity *age.X25519Identity, files ...string) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Recipients:  []config.RecipientConfig{{Name: "test", Age: identity.Recipient().String()}},
		Files:       files,
		KeysInclude: []interface{}{"/password$/", "api_key", "secret"},
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, ".confcrypt.yml")
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func TestEditFullFileFormat(t *testing.T) {
	dir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()
	cfg := createTestConfigWithFiles(t, dir, identity, "*.pem")
	file := filepath.Join(dir, "server.pem")
	if err := os.WriteFile(file, []byte("-----BEGIN KEY-----\nold\n-----END KEY-----\n"), 0600); err != nil {
		t.Fatal(err)
	}

	res, err := performEdit(cfg, file, identityLoaderFor(identity), fakeEditor(t, "s/old/new/"), false)
	if err != nil {
		t.Fatalf("performEdit: %v", err)
	}
	if !res.changed {
		t.Fatal("expected change")
	}
	after, _ := os.ReadFile(file)
	if !strings.HasPrefix(string(after), "$CONFCRYPT_ENCRYPTED;") || strings.Contains(string(after), "new") {
		t.Fatalf("expected full-file ciphertext:\n%s", after)
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0600 {
		t.Errorf("mode changed to %o", fi.Mode().Perm())
	}

	// Second edit decrypts the full file, applies the change, re-encrypts
	res, err = performEdit(cfg, file, identityLoaderFor(identity), fakeEditor(t, "s/new/newer/"), false)
	if err != nil || !res.changed {
		t.Fatalf("second performEdit: changed=%v err=%v", res != nil && res.changed, err)
	}
	if !strings.Contains(decryptFile(t, cfg, identity, file), "newer") {
		t.Error("second edit not applied")
	}
}

func TestEditEnvFile(t *testing.T) {
	dir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()
	cfg := createTestConfigWithFiles(t, dir, identity, ".env")
	file := filepath.Join(dir, ".env")
	if err := os.WriteFile(file, []byte("# db\nDB_PASSWORD=one\nAPI_KEY=two\nPLAIN=3\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := performEdit(cfg, file, identityLoaderFor(identity), fakeEditor(t, "s/one/ONE/"), false); err != nil {
		t.Fatalf("first edit: %v", err)
	}
	before, _ := os.ReadFile(file)
	if _, err := performEdit(cfg, file, identityLoaderFor(identity), fakeEditor(t, "s/two/TWO/"), false); err != nil {
		t.Fatalf("second edit: %v", err)
	}
	after, _ := os.ReadFile(file)
	bl, al := strings.Split(string(before), "\n"), strings.Split(string(after), "\n")
	for i := range bl {
		if strings.HasPrefix(bl[i], "API_KEY") != (bl[i] != al[i]) {
			t.Errorf("line %d unexpectedly %s:\n  %s\n  %s", i, map[bool]string{true: "changed", false: "unchanged"}[bl[i] != al[i]], bl[i], al[i])
		}
	}
	decrypted := decryptFile(t, cfg, identity, file)
	if decrypted != "# db\nDB_PASSWORD=ONE\nAPI_KEY=TWO\nPLAIN=3\n" {
		t.Errorf("unexpected decrypted content: %q", decrypted)
	}
}

func TestEditRemovingAllSecretsDropsMAC(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	content, _ := os.ReadFile(testFile)
	macProc, _ := processor.NewProcessor(cfg, nil)
	_ = macProc.SetupEncryptionWithIdentities([]age.Identity{identity})
	_ = macProc.UpdateMAC(testFile, content)
	_ = cfg.Save()
	if _, ok := cfg.GetMAC("test.yml"); !ok {
		t.Fatal("fixture should have a MAC")
	}

	// The editor deletes both secret lines
	res, err := performEdit(cfg, testFile, identityLoaderFor(identity), fakeEditor(t, "/password/d;/api_key/d"), false)
	if err != nil {
		t.Fatalf("performEdit: %v", err)
	}
	if !res.changed {
		t.Fatal("expected change")
	}
	after, _ := os.ReadFile(testFile)
	if strings.Contains(string(after), "ENC[") || !strings.Contains(string(after), "host: localhost") {
		t.Fatalf("unexpected content:\n%s", after)
	}
	reloaded, _ := config.Load(cfg.ConfigPath())
	if _, ok := reloaded.GetMAC("test.yml"); ok {
		t.Error("MAC should be removed when no encrypted values remain")
	}
	if !reloaded.HasSecrets() {
		t.Error("key store must be kept")
	}
}

func TestEditTempFileIsPrivateAndRemoved(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	record := filepath.Join(t.TempDir(), "record.txt")
	script := filepath.Join(t.TempDir(), "editor.sh")
	body := "#!/bin/sh\n{ echo \"$1\"; ls -ld \"$1\" \"$(dirname \"$1\")\"; cat \"$1\"; } > " + record + "\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}

	if _, err := performEdit(cfg, testFile, identityLoaderFor(identity), script, false); err != nil {
		t.Fatalf("performEdit: %v", err)
	}
	recorded, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitN(string(recorded), "\n", 4)
	tmpPath := lines[0]
	if filepath.Base(tmpPath) != "test.yml" {
		t.Errorf("temp file should keep the file name, got %s", tmpPath)
	}
	modes := lines[1] + "\n" + lines[2]
	if !strings.Contains(modes, "\n-rw-------") && !strings.HasPrefix(modes, "-rw-------") || !strings.Contains(modes, "drwx------") {
		t.Errorf("temp file and directory must be private:\n%s", modes)
	}
	if !strings.Contains(lines[3], "password: secret123") {
		t.Errorf("editor did not see decrypted content:\n%s", lines[3])
	}
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("temp file still exists after edit")
	}
	if _, err := os.Stat(filepath.Dir(tmpPath)); !os.IsNotExist(err) {
		t.Error("temp directory still exists after edit")
	}
}

func TestEditPassesEditorArgumentsAndFileLast(t *testing.T) {
	cfg, identity, testFile := createEncryptedYAMLFixture(t)
	script := filepath.Join(t.TempDir(), "editor.sh")
	// Expects "--wait" first, the file last; fails otherwise
	body := "#!/bin/sh\n[ \"$1\" = \"--wait\" ] || exit 3\nshift\nsed -i.bak 's/myapikey/viaargs/' \"$1\" && rm -f \"$1.bak\"\n"
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	res, err := performEdit(cfg, testFile, identityLoaderFor(identity), script+" --wait", false)
	if err != nil {
		t.Fatalf("performEdit: %v", err)
	}
	if !res.changed || !strings.Contains(decryptFile(t, cfg, identity, testFile), "api_key: viaargs") {
		t.Error("edit via editor with arguments not applied")
	}
}

func TestResolveEditorPrecedence(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")
	if got := resolveEditor(""); got != "vi" {
		t.Errorf("default: got %q", got)
	}
	t.Setenv("EDITOR", "nano")
	if got := resolveEditor(""); got != "nano" {
		t.Errorf("EDITOR: got %q", got)
	}
	t.Setenv("VISUAL", "code --wait")
	if got := resolveEditor(""); got != "code --wait" {
		t.Errorf("VISUAL over EDITOR: got %q", got)
	}
	if got := resolveEditor("vim"); got != "vim" {
		t.Errorf("flag over env: got %q", got)
	}
	if got := resolveEditor("   "); got != "code --wait" {
		t.Errorf("blank flag ignored: got %q", got)
	}
}
