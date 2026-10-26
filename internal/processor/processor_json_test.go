package processor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/crypto"
	"github.com/maurice2k/confcrypt/internal/format"
)

func newJSONProcessor(t *testing.T) (*Processor, *age.X25519Identity, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	identity, _ := crypto.GenerateAgeKeypair()
	cfg := createTestConfig(t, dir, []config.RecipientConfig{
		{Name: "test", Age: identity.Recipient().String()},
	})
	cfg.KeysInclude = append(cfg.KeysInclude, "int_secret", "float_secret", "bool_secret", "null_secret", "list_secret")
	proc, err := NewProcessor(cfg, nil)
	if err != nil {
		t.Fatalf("NewProcessor: %v", err)
	}
	if err := proc.SetupEncryption(); err != nil {
		t.Fatalf("SetupEncryption: %v", err)
	}
	if err := proc.SaveEncryptedSecrets(); err != nil {
		t.Fatalf("SaveEncryptedSecrets: %v", err)
	}
	return proc, identity, cfg
}

const formattedJSON = `{
	"zeta": "first by order, not alphabet",
	"database": {
		"host": "localhost",
		"password": "s3cret",
		"port": 5432,
		"options": [ "a", "b" ]
	},
	"api_key": "key<with>&html",
	"int_secret": 12345678901234567890,
	"float_secret": 1.50,
	"bool_secret": true,
	"null_secret": null,
	"list_secret": ["x", 1, false, ["nested"]],
	"escaped": "caf\u00e9 \/ slash",
	"alpha": {}
}
`

func TestJSONEncryptPreservesLayoutAndDecryptRestoresBytes(t *testing.T) {
	proc, identity, cfg := newJSONProcessor(t)

	encrypted, modified, err := proc.ProcessContent([]byte(formattedJSON), "config.json", true, FormatJSON)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !modified {
		t.Fatal("expected modification")
	}
	enc := string(encrypted)

	// Untouched parts are byte-identical: order, tabs, spacing, escapes
	for _, want := range []string{
		"{\n\t\"zeta\": \"first by order, not alphabet\",\n\t\"database\": {\n\t\t\"host\": \"localhost\",",
		"\"options\": [ \"a\", \"b\" ]",
		"\"escaped\": \"caf\\u00e9 \\/ slash\"",
		"\"alpha\": {}\n}\n",
	} {
		if !strings.Contains(enc, want) {
			t.Errorf("encrypted output lost original formatting, missing %q:\n%s", want, enc)
		}
	}
	if strings.Index(enc, `"zeta"`) > strings.Index(enc, `"database"`) || strings.Index(enc, `"alpha"`) < strings.Index(enc, `"list_secret"`) {
		t.Errorf("key order changed:\n%s", enc)
	}
	for _, plaintext := range []string{"s3cret", "key<with>", "12345678901234567890", "1.50", `"x"`, `"nested"`} {
		if strings.Contains(enc, plaintext) {
			t.Errorf("plaintext %q leaked:\n%s", plaintext, enc)
		}
	}
	for _, typed := range []string{"type:int]", "type:float]", "type:bool]", "type:null]"} {
		if !strings.Contains(enc, typed) {
			t.Errorf("expected a value of %s in:\n%s", typed, enc)
		}
	}
	if strings.Contains(enc, `\u003c`) {
		t.Errorf("HTML characters must not be escaped:\n%s", enc)
	}

	// Decrypting gives back the exact original bytes
	proc2, _ := NewProcessor(cfg, nil)
	if _, err := proc2.SetupDecryption([]age.Identity{identity}); err != nil {
		t.Fatalf("SetupDecryption: %v", err)
	}
	decrypted, _, err := proc2.ProcessContent(encrypted, "config.json", false, FormatJSON)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decrypted) != formattedJSON {
		t.Errorf("decrypt did not restore the original bytes:\n got: %q\nwant: %q", decrypted, formattedJSON)
	}

	// Check, match and MAC agree with the encryption walk
	if res, _ := proc.CheckContent(encrypted, FormatJSON); len(res) != 0 {
		t.Errorf("check reports unencrypted values after encrypt: %+v", res)
	}
	res, _ := proc.CheckContent([]byte(formattedJSON), FormatJSON)
	var paths []string
	for _, r := range res {
		paths = append(paths, strings.Join(r.Path, "."))
	}
	want := "database.password api_key int_secret float_secret bool_secret null_secret list_secret[0] list_secret[1] list_secret[2] list_secret[3][0]"
	if got := strings.Join(paths, " "); got != want {
		t.Errorf("check paths in document order:\n got: %s\nwant: %s", got, want)
	}
	if !proc.HasEncryptedValues(encrypted, "config.json") || proc.HasEncryptedValues([]byte(formattedJSON), "config.json") {
		t.Error("HasEncryptedValues wrong")
	}
	mac1, _ := proc.ComputeMAC(encrypted, FormatJSON)
	mac2, _ := proc.ComputeMAC([]byte(strings.ReplaceAll(enc, "\t", "    ")), FormatJSON)
	if string(mac1) != string(mac2) {
		t.Error("MAC must not depend on formatting")
	}
}

func TestJSONCCommentsSurviveEncryptAndDecrypt(t *testing.T) {
	proc, identity, cfg := newJSONProcessor(t)

	src := "// app settings\n{\n  // credentials\n  \"password\": \"s3cret\", // rotate monthly\n  /* keep */ \"host\": \"db\",\n  \"list_secret\": [\n    \"a\", // first\n    \"b\",\n  ],\n}\n"
	encrypted, _, err := proc.ProcessContent([]byte(src), "settings.jsonc", true, FormatJSON)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	enc := string(encrypted)
	for _, comment := range []string{"// app settings", "// credentials", "// rotate monthly", "/* keep */", "// first", "\",\n  ],\n}"} {
		if !strings.Contains(enc, comment) {
			t.Errorf("comment or trailing comma lost: %q in\n%s", comment, enc)
		}
	}
	if strings.Contains(enc, "s3cret") || strings.Contains(enc, `"a"`) {
		t.Errorf("plaintext leaked:\n%s", enc)
	}

	proc2, _ := NewProcessor(cfg, nil)
	_, _ = proc2.SetupDecryption([]age.Identity{identity})
	decrypted, _, err := proc2.ProcessContent(encrypted, "settings.jsonc", false, FormatJSON)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decrypted) != src {
		t.Errorf("decrypt did not restore the original bytes:\n got: %q\nwant: %q", decrypted, src)
	}

	if DetectFormat("x.jsonc") != FormatJSON {
		t.Error(".jsonc must be detected as JSON")
	}
}

func TestJSONCFileEndToEnd(t *testing.T) {
	proc, _, cfg := newJSONProcessor(t)
	file := filepath.Join(cfg.ConfigDir(), "app.jsonc")
	if err := os.WriteFile(file, []byte("{\n  \"password\": \"x\", // c\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	out, modified, err := proc.ProcessFile(file, true)
	if err != nil || !modified {
		t.Fatalf("ProcessFile: modified=%v err=%v", modified, err)
	}
	if !strings.HasSuffix(string(out), ", // c\n}\n") {
		t.Errorf("unexpected output: %q", out)
	}
	if err := proc.UpdateMAC(file, out); err != nil {
		t.Fatalf("UpdateMAC: %v", err)
	}
	if err := proc.VerifyMAC(file, out); err != nil {
		t.Fatalf("VerifyMAC: %v", err)
	}
}

func TestJSONDecryptRejectsCorruptTypedPlaintext(t *testing.T) {
	proc, identity, cfg := newJSONProcessor(t)

	// Encrypt an int, then forge the stored type to bool: the plaintext "7"
	// is not a valid boolean, so decryption must fail instead of writing
	// invalid JSON
	encrypted, _, err := proc.ProcessContent([]byte(`{"int_secret": 7}`), "x.json", true, FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	forged := strings.Replace(string(encrypted), "type:int]", "type:bool]", 1)

	proc2, _ := NewProcessor(cfg, nil)
	_, _ = proc2.SetupDecryption([]age.Identity{identity})
	if _, _, err := proc2.ProcessContent([]byte(forged), "x.json", false, FormatJSON); err == nil {
		t.Error("expected error for plaintext that is not a valid JSON boolean")
	}
}

func TestJSONDuplicateKeysAreRejected(t *testing.T) {
	proc, _, _ := newJSONProcessor(t)
	src := []byte(`{"password": "a", "password": "b"}`)
	if _, _, err := proc.ProcessContent(src, "x.json", true, FormatJSON); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected duplicate key error, got %v", err)
	}
	if _, err := proc.CheckContent(src, FormatJSON); err == nil {
		t.Error("check must reject duplicate keys too")
	}
}

func TestEnvNodeAdapter(t *testing.T) {
	envFile, err := ParseEnvFile([]byte("# comment\nexport A=1\nB=\"two\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	root := envDoc(envFile)
	if root.Len() != 2 || root.Key(0) != "A" || root.Key(1) != "B" {
		t.Fatalf("unexpected mapping: len=%d keys=%q,%q", root.Len(), root.Key(0), root.Key(1))
	}
	b, ok := root.Get("B")
	if !ok || b.Value() != `"two"` || b.Type() != format.TypeString {
		t.Fatalf("unexpected B: %v %q", ok, b.Value())
	}
	b.SetScalar("ENC[x]", format.TypeString, "")
	_ = root.Set("C", root.Item(0))
	root.Delete("A")
	if got, want := string(envFile.Marshal()), "# comment\nB=ENC[x]\nC=1\n"; got != want {
		t.Errorf("unexpected env output:\n got: %q\nwant: %q", got, want)
	}
}
