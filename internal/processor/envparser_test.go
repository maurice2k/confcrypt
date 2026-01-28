package processor

import (
	"strings"
	"testing"
)

func TestParseEnvFile(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKeys []string
		wantVals map[string]string
	}{
		{
			name: "basic key-value",
			input: `KEY=value
ANOTHER=test`,
			wantKeys: []string{"KEY", "ANOTHER"},
			wantVals: map[string]string{"KEY": "value", "ANOTHER": "test"},
		},
		{
			name: "with comments",
			input: `# This is a comment
KEY=value
# Another comment
SECRET=mysecret`,
			wantKeys: []string{"KEY", "SECRET"},
			wantVals: map[string]string{"KEY": "value", "SECRET": "mysecret"},
		},
		{
			name: "with export prefix",
			input: `export DB_PASSWORD=secret
export API_KEY=apikey123`,
			wantKeys: []string{"DB_PASSWORD", "API_KEY"},
			wantVals: map[string]string{"DB_PASSWORD": "secret", "API_KEY": "apikey123"},
		},
		{
			name: "double quoted values - raw preserved",
			input: `KEY="value with spaces"
MULTILINE="line1\nline2"`,
			wantKeys: []string{"KEY", "MULTILINE"},
			// Values include quotes (raw bytes preserved)
			wantVals: map[string]string{"KEY": `"value with spaces"`, "MULTILINE": `"line1\nline2"`},
		},
		{
			name: "single quoted values - raw preserved",
			input: `KEY='value with spaces'
LITERAL='no\nescape'`,
			wantKeys: []string{"KEY", "LITERAL"},
			// Values include quotes (raw bytes preserved)
			wantVals: map[string]string{"KEY": `'value with spaces'`, "LITERAL": `'no\nescape'`},
		},
		{
			name: "inline comments stripped",
			input: `KEY=value # this is a comment
ANOTHER=test`,
			wantKeys: []string{"KEY", "ANOTHER"},
			wantVals: map[string]string{"KEY": "value", "ANOTHER": "test"},
		},
		{
			name: "inline comment inside quotes not stripped",
			input: `KEY="value # not a comment"
ANOTHER=test`,
			wantKeys: []string{"KEY", "ANOTHER"},
			wantVals: map[string]string{"KEY": `"value # not a comment"`, "ANOTHER": "test"},
		},
		{
			name: "empty value",
			input: `KEY=
ANOTHER=value`,
			wantKeys: []string{"KEY", "ANOTHER"},
			wantVals: map[string]string{"KEY": "", "ANOTHER": "value"},
		},
		{
			name:     "blank lines preserved",
			input:    "KEY=value\n\nANOTHER=test",
			wantKeys: []string{"KEY", "ANOTHER"},
			wantVals: map[string]string{"KEY": "value", "ANOTHER": "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envFile, err := ParseEnvFile([]byte(tt.input))
			if err != nil {
				t.Fatalf("ParseEnvFile() error = %v", err)
			}

			gotKeys := envFile.Keys()
			if len(gotKeys) != len(tt.wantKeys) {
				t.Errorf("got %d keys, want %d", len(gotKeys), len(tt.wantKeys))
			}

			for i, key := range tt.wantKeys {
				if i >= len(gotKeys) {
					t.Errorf("missing key at index %d: %s", i, key)
					continue
				}
				if gotKeys[i] != key {
					t.Errorf("key at index %d = %s, want %s", i, gotKeys[i], key)
				}
			}

			for key, wantVal := range tt.wantVals {
				gotVal, ok := envFile.Get(key)
				if !ok {
					t.Errorf("key %s not found", key)
					continue
				}
				if gotVal != wantVal {
					t.Errorf("value for %s = %q, want %q", key, gotVal, wantVal)
				}
			}
		})
	}
}

func TestEnvFileMarshal(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "preserves structure",
			input: `# Database config
DB_HOST=localhost
DB_PASSWORD=secret

# API config
API_KEY=mykey
`,
		},
		{
			name:  "preserves export",
			input: "export DB_PASSWORD=secret\nexport API_KEY=key123\n",
		},
		{
			name: "preserves quotes exactly",
			input: `KEY="value with spaces"
SINGLE='single quoted'
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envFile, err := ParseEnvFile([]byte(tt.input))
			if err != nil {
				t.Fatalf("ParseEnvFile() error = %v", err)
			}

			output := envFile.Marshal()

			// Re-parse and compare values
			envFile2, err := ParseEnvFile(output)
			if err != nil {
				t.Fatalf("ParseEnvFile() on marshaled content error = %v", err)
			}

			keys1 := envFile.Keys()
			keys2 := envFile2.Keys()

			if len(keys1) != len(keys2) {
				t.Errorf("key count mismatch: original %d, marshaled %d", len(keys1), len(keys2))
			}

			for _, key := range keys1 {
				val1, _ := envFile.Get(key)
				val2, ok := envFile2.Get(key)
				if !ok {
					t.Errorf("key %s missing after marshal", key)
					continue
				}
				if val1 != val2 {
					t.Errorf("value mismatch for %s: original %q, marshaled %q", key, val1, val2)
				}
			}
		})
	}
}

func TestEnvFileSetValue(t *testing.T) {
	// Test that raw values are preserved through Set operations
	input := `DB_PASSWORD=original
API_KEY="quoted_original"`

	envFile, err := ParseEnvFile([]byte(input))
	if err != nil {
		t.Fatalf("ParseEnvFile() error = %v", err)
	}

	// Verify initial values (quoted value includes quotes)
	val1, _ := envFile.Get("DB_PASSWORD")
	if val1 != "original" {
		t.Errorf("DB_PASSWORD = %q, want %q", val1, "original")
	}
	val2, _ := envFile.Get("API_KEY")
	if val2 != `"quoted_original"` {
		t.Errorf("API_KEY = %q, want %q", val2, `"quoted_original"`)
	}

	// Set new values (simulating encrypt)
	envFile.Set("DB_PASSWORD", "ENC[AES256_GCM,data:xxx]")
	envFile.Set("API_KEY", "ENC[AES256_GCM,data:yyy]")

	output := string(envFile.Marshal())

	// Both get the ENC value directly (no quote manipulation)
	if !strings.Contains(output, `DB_PASSWORD=ENC[AES256_GCM,data:xxx]`) {
		t.Errorf("DB_PASSWORD not set correctly, got: %s", output)
	}
	if !strings.Contains(output, `API_KEY=ENC[AES256_GCM,data:yyy]`) {
		t.Errorf("API_KEY not set correctly, got: %s", output)
	}
}

func TestEnvFileRoundTrip(t *testing.T) {
	// Test that parse -> marshal produces identical output
	inputs := []string{
		`KEY=value`,
		`KEY="quoted value"`,
		`KEY='single quoted'`,
		`KEY=value # with comment`,
		`KEY="value # not comment"`,
		`export KEY=value`,
		`KEY=`,
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			envFile, err := ParseEnvFile([]byte(input))
			if err != nil {
				t.Fatalf("ParseEnvFile() error = %v", err)
			}

			output := string(envFile.Marshal())

			if output != input {
				t.Errorf("round-trip mismatch:\n  input:  %q\n  output: %q", input, output)
			}
		})
	}
}

func TestDetectFormatEnv(t *testing.T) {
	tests := []struct {
		path string
		want FileFormat
	}{
		{".env", FormatEnv},
		{"/path/to/.env", FormatEnv},
		{".env.local", FormatEnv},
		{".env.production", FormatEnv},
		{".env.development", FormatEnv},
		{"database.env", FormatEnv},
		{"/path/to/app.env", FormatEnv},
		{"config.yml", FormatYAML},
		{"config.yaml", FormatYAML},
		{"config.json", FormatJSON},
		{"Makefile", FormatYAML}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := DetectFormat(tt.path)
			if got != tt.want {
				t.Errorf("DetectFormat(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestEnvFileToMap(t *testing.T) {
	input := `KEY1=value1
KEY2="value2"
# comment
KEY3=value3`

	envFile, err := ParseEnvFile([]byte(input))
	if err != nil {
		t.Fatalf("ParseEnvFile() error = %v", err)
	}

	m := envFile.ToMap()

	if len(m) != 3 {
		t.Errorf("ToMap() returned %d entries, want 3", len(m))
	}

	expected := map[string]string{
		"KEY1": "value1",
		"KEY2": `"value2"`, // Includes quotes
		"KEY3": "value3",
	}

	for k, v := range expected {
		if got, ok := m[k]; !ok {
			t.Errorf("missing key %s", k)
		} else if got != v {
			t.Errorf("m[%s] = %q, want %q", k, got, v)
		}
	}
}
