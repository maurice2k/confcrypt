package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maurice2k/confcrypt/internal/crypto"
	"gopkg.in/yaml.v3"
)

func TestRecipientConfig_GetPublicKey(t *testing.T) {
	tests := []struct {
		name     string
		config   RecipientConfig
		expected string
	}{
		{
			name:     "age key only",
			config:   RecipientConfig{Age: "age1xyz"},
			expected: "age1xyz",
		},
		{
			name:     "ssh key only",
			config:   RecipientConfig{SSH: "ssh-ed25519 AAAA test"},
			expected: "ssh-ed25519 AAAA test",
		},
		{
			name:     "age key takes precedence",
			config:   RecipientConfig{Age: "age1xyz", SSH: "ssh-ed25519 AAAA"},
			expected: "age1xyz",
		},
		{
			name:     "empty config",
			config:   RecipientConfig{},
			expected: "",
		},
		{
			name:     "name only",
			config:   RecipientConfig{Name: "Alice"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetPublicKey()
			if got != tt.expected {
				t.Errorf("GetPublicKey() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestRecipientConfig_GetKeyType(t *testing.T) {
	tests := []struct {
		name     string
		config   RecipientConfig
		expected crypto.KeyType
	}{
		{
			name:     "age key",
			config:   RecipientConfig{Age: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"},
			expected: crypto.KeyTypeAge,
		},
		{
			name:     "ssh-ed25519 key",
			config:   RecipientConfig{SSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test@example.com"},
			expected: crypto.KeyTypeSSHEd25519,
		},
		{
			name:     "ssh-rsa key",
			config:   RecipientConfig{SSH: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB test@example.com"},
			expected: crypto.KeyTypeSSHRSA,
		},
		{
			name:     "ecdsa key",
			config:   RecipientConfig{SSH: "ecdsa-sha2-nistp256 AAAAE2VjZHNh test@example.com"},
			expected: crypto.KeyTypeSSHECDSA,
		},
		{
			name:     "empty config",
			config:   RecipientConfig{},
			expected: crypto.KeyTypeUnknown,
		},
		{
			name:     "age takes precedence over ssh",
			config:   RecipientConfig{Age: "age1xyz", SSH: "ssh-ed25519 AAAA"},
			expected: crypto.KeyTypeAge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetKeyType()
			if got != tt.expected {
				t.Errorf("GetKeyType() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestParseRenameRule(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		wantPattern string
		wantRepl    string
		wantErr     bool
	}{
		{
			name:        "valid encrypt rule",
			rule:        `/(\.\w+)$/.enc$1/`,
			wantPattern: `(\.\w+)$`,
			wantRepl:    ".enc$1",
			wantErr:     false,
		},
		{
			name:        "valid decrypt rule",
			rule:        `/\.enc(\.\w+)$/$1/`,
			wantPattern: `\.enc(\.\w+)$`,
			wantRepl:    "$1",
			wantErr:     false,
		},
		{
			name:        "backreference conversion",
			rule:        `/(\.\w+)$/.enc\1/`,
			wantPattern: `(\.\w+)$`,
			wantRepl:    ".enc$1",
			wantErr:     false,
		},
		{
			name:        "multiple backreferences",
			rule:        `/(.*)\.(.*)/$1_backup.$2/`,
			wantPattern: `(.*)\.(.*)`,
			wantRepl:    "$1_backup.$2",
			wantErr:     false,
		},
		{
			name:    "missing leading slash",
			rule:    `(\.\w+)$/.enc$1/`,
			wantErr: true,
		},
		{
			name:    "missing middle slash",
			rule:    `/(\.\w+)$.enc$1/`,
			wantErr: true,
		},
		{
			name:    "missing trailing slash",
			rule:    `/(\.\w+)$/.enc$1`,
			wantErr: true,
		},
		{
			name:    "invalid regex",
			rule:    `/[invalid/.enc$1/`,
			wantErr: true,
		},
		{
			name:    "too short",
			rule:    `//`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re, repl, err := ParseRenameRule(tt.rule)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseRenameRule() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("ParseRenameRule() unexpected error: %v", err)
				return
			}
			if re.String() != tt.wantPattern {
				t.Errorf("ParseRenameRule() pattern = %q, want %q", re.String(), tt.wantPattern)
			}
			if repl != tt.wantRepl {
				t.Errorf("ParseRenameRule() replacement = %q, want %q", repl, tt.wantRepl)
			}
		})
	}
}

func TestApplyRenameRules(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		rules    []string
		want     string
		wantErr  bool
	}{
		{
			name:     "encrypt yml file",
			filename: "config.yml",
			rules:    []string{`/(\.\w+)$/.enc$1/`},
			want:     "config.enc.yml",
			wantErr:  false,
		},
		{
			name:     "encrypt json file",
			filename: "settings.json",
			rules:    []string{`/(\.\w+)$/.enc$1/`},
			want:     "settings.enc.json",
			wantErr:  false,
		},
		{
			name:     "decrypt enc.yml file",
			filename: "config.enc.yml",
			rules:    []string{`/\.enc(\.\w+)$/$1/`},
			want:     "config.yml",
			wantErr:  false,
		},
		{
			name:     "no match returns original",
			filename: "readme.txt",
			rules:    []string{`/\.enc(\.\w+)$/$1/`},
			want:     "readme.txt",
			wantErr:  false,
		},
		{
			name:     "first match wins",
			filename: "config.yml",
			rules:    []string{`/\.yml$/.yaml/`, `/(\.\w+)$/.enc$1/`},
			want:     "config.yaml",
			wantErr:  false,
		},
		{
			name:     "empty rules returns original",
			filename: "config.yml",
			rules:    []string{},
			want:     "config.yml",
			wantErr:  false,
		},
		{
			name:     "invalid rule returns error",
			filename: "config.yml",
			rules:    []string{`invalid`},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ApplyRenameRules(tt.filename, tt.rules)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ApplyRenameRules() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("ApplyRenameRules() unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("ApplyRenameRules() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetEncryptRename(t *testing.T) {
	tests := []struct {
		name        string
		renameFiles *RenameFilesConfig
		filePath    string
		want        string
		wantErr     bool
	}{
		{
			name: "with encrypt rules",
			renameFiles: &RenameFilesConfig{
				Encrypt: []string{`/(\.\w+)$/.enc$1/`},
			},
			filePath: "/path/to/config.yml",
			want:     "/path/to/config.enc.yml",
			wantErr:  false,
		},
		{
			name:        "nil RenameFiles",
			renameFiles: nil,
			filePath:    "/path/to/config.yml",
			want:        "/path/to/config.yml",
			wantErr:     false,
		},
		{
			name: "empty encrypt rules",
			renameFiles: &RenameFilesConfig{
				Encrypt: []string{},
			},
			filePath: "/path/to/config.yml",
			want:     "/path/to/config.yml",
			wantErr:  false,
		},
		{
			name: "preserves directory path",
			renameFiles: &RenameFilesConfig{
				Encrypt: []string{`/(\.\w+)$/.enc$1/`},
			},
			filePath: "/deep/nested/path/config.yml",
			want:     "/deep/nested/path/config.enc.yml",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{RenameFiles: tt.renameFiles}
			got, err := cfg.GetEncryptRename(tt.filePath)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetEncryptRename() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("GetEncryptRename() unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("GetEncryptRename() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetDecryptRename(t *testing.T) {
	tests := []struct {
		name        string
		renameFiles *RenameFilesConfig
		filePath    string
		want        string
		wantErr     bool
	}{
		{
			name: "with decrypt rules",
			renameFiles: &RenameFilesConfig{
				Decrypt: []string{`/\.enc(\.\w+)$/$1/`},
			},
			filePath: "/path/to/config.enc.yml",
			want:     "/path/to/config.yml",
			wantErr:  false,
		},
		{
			name:        "nil RenameFiles",
			renameFiles: nil,
			filePath:    "/path/to/config.enc.yml",
			want:        "/path/to/config.enc.yml",
			wantErr:     false,
		},
		{
			name: "empty decrypt rules",
			renameFiles: &RenameFilesConfig{
				Decrypt: []string{},
			},
			filePath: "/path/to/config.enc.yml",
			want:     "/path/to/config.enc.yml",
			wantErr:  false,
		},
		{
			name: "no match returns original",
			renameFiles: &RenameFilesConfig{
				Decrypt: []string{`/\.enc(\.\w+)$/$1/`},
			},
			filePath: "/path/to/config.yml",
			want:     "/path/to/config.yml",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{RenameFiles: tt.renameFiles}
			got, err := cfg.GetDecryptRename(tt.filePath)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetDecryptRename() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("GetDecryptRename() unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("GetDecryptRename() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Helper to create a test config with rename rules
func createTestConfigWithRename(t *testing.T, dir string) *Config {
	cfg := &Config{
		Recipients: []RecipientConfig{
			{Name: "test", Age: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"},
		},
		Files: []string{"*.yml", "*.yaml", "*.enc.yml", "*.enc.yaml"},
		RenameFiles: &RenameFilesConfig{
			Encrypt: []string{`/(\.\w+)$/.enc$1/`},
			Decrypt: []string{`/\.enc(\.\w+)$/$1/`},
		},
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
	loaded, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	return loaded
}

func TestFindConfigFromPath(t *testing.T) {
	// Create a temp directory structure:
	// tmpdir/
	//   .confcrypt.yml
	//   subdir1/
	//     subdir2/
	//       file.yml
	dir := t.TempDir()

	// Create the config file at root
	configPath := filepath.Join(dir, ".confcrypt.yml")
	configContent := `recipients:
  - name: test
    age: age1test123
files:
  - "*.yml"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Create nested directories
	subdir1 := filepath.Join(dir, "subdir1")
	subdir2 := filepath.Join(subdir1, "subdir2")
	if err := os.MkdirAll(subdir2, 0755); err != nil {
		t.Fatalf("Failed to create directories: %v", err)
	}

	tests := []struct {
		name      string
		startDir  string
		wantPath  string
		wantError bool
	}{
		{
			name:     "find from root dir",
			startDir: dir,
			wantPath: configPath,
		},
		{
			name:     "find from subdir1",
			startDir: subdir1,
			wantPath: configPath,
		},
		{
			name:     "find from subdir2",
			startDir: subdir2,
			wantPath: configPath,
		},
		{
			name:      "not found in isolated dir",
			startDir:  t.TempDir(), // completely separate temp dir
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FindConfigFromPath(tt.startDir)
			if tt.wantError {
				if err == nil {
					t.Errorf("FindConfigFromPath() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("FindConfigFromPath() unexpected error: %v", err)
				return
			}
			if got != tt.wantPath {
				t.Errorf("FindConfigFromPath() = %q, want %q", got, tt.wantPath)
			}
		})
	}
}

func TestMatchesFile(t *testing.T) {
	dir := t.TempDir()

	// Create config
	configPath := filepath.Join(dir, ".confcrypt.yml")
	configContent := `recipients:
  - name: test
    age: age1test123
files:
  - "*.yml"
  - "*.yaml"
  - "subdir/config.json"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Create subdirectory
	subdir := filepath.Join(dir, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("Failed to create subdir: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	tests := []struct {
		name      string
		filePath  string
		wantMatch bool
		wantError bool
	}{
		{
			name:      "yml file matches",
			filePath:  filepath.Join(dir, "config.yml"),
			wantMatch: true,
		},
		{
			name:      "yaml file matches",
			filePath:  filepath.Join(dir, "config.yaml"),
			wantMatch: true,
		},
		{
			name:      "yml in subdir matches",
			filePath:  filepath.Join(subdir, "test.yml"),
			wantMatch: true,
		},
		{
			name:      "exact path matches",
			filePath:  filepath.Join(dir, "subdir", "config.json"),
			wantMatch: true,
		},
		{
			name:      "txt file does not match",
			filePath:  filepath.Join(dir, "readme.txt"),
			wantMatch: false,
		},
		{
			name:      "file outside config dir does not match",
			filePath:  "/some/other/path/config.yml",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cfg.MatchesFile(tt.filePath)
			if tt.wantError {
				if err == nil {
					t.Errorf("MatchesFile() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("MatchesFile() unexpected error: %v", err)
				return
			}
			if got != tt.wantMatch {
				t.Errorf("MatchesFile(%q) = %v, want %v", tt.filePath, got, tt.wantMatch)
			}
		})
	}
}

func TestAddFilePattern(t *testing.T) {
	dir := t.TempDir()

	// Create config
	configPath := filepath.Join(dir, ".confcrypt.yml")
	configContent := `recipients:
  - name: test
    age: age1test123
files:
  - "*.yml"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify initial state
	if len(cfg.Files) != 1 {
		t.Errorf("Expected 1 file pattern, got %d", len(cfg.Files))
	}

	// Add new pattern
	cfg.AddFilePattern("subdir/secrets.env")

	// Verify pattern was added
	if len(cfg.Files) != 2 {
		t.Errorf("Expected 2 file patterns after add, got %d", len(cfg.Files))
	}
	if cfg.Files[1] != "subdir/secrets.env" {
		t.Errorf("Expected second pattern to be 'subdir/secrets.env', got %q", cfg.Files[1])
	}

	// Save and reload
	if err := cfg.Save(); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	reloaded, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to reload config: %v", err)
	}

	// Verify pattern persisted
	if len(reloaded.Files) != 2 {
		t.Errorf("Expected 2 file patterns after reload, got %d", len(reloaded.Files))
	}

	found := false
	for _, f := range reloaded.Files {
		if f == "subdir/secrets.env" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Pattern 'subdir/secrets.env' not found after reload, files: %v", reloaded.Files)
	}
}

func TestConfigSavePreservesComments(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".confcrypt.yml")

	// Create a config file with comments
	// Note: Inline comments on recipients are NOT preserved when recipients
	// are modified (added/removed), as the list is rebuilt from scratch.
	// Header and section comments ARE preserved.
	configContent := `# confcrypt configuration file
# This comment should be preserved

# Recipients section
recipients:
  - name: test
    age: age1test123

# Files to process
files:
  - "*.yml"
  - "*.yaml"

# Keys to encrypt
keys_include:
  - password
  - secret
  - api_key
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Load config
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Modify the .confcrypt section (simulating encryption)
	cfg.Confcrypt = &ConfcryptSection{
		Version:   "1.0.0",
		UpdatedAt: "2024-01-01T00:00:00Z",
		Store: []SecretEntry{
			{Recipient: "age1test123", Secret: "encrypted-secret"},
		},
		MACs: map[string]string{
			"test.yml": "mac-value",
		},
	}

	// Save config
	if err := cfg.Save(); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Read saved content
	saved, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read saved config: %v", err)
	}

	savedStr := string(saved)

	// Verify header/section comments are preserved
	// Note: Inline comments on items inside rebuilt sections (like recipients)
	// are not preserved, only structural comments before sections
	commentsToCheck := []string{
		"# confcrypt configuration file",
		"# This comment should be preserved",
		"# Recipients section",
		"# Files to process",
		"# Keys to encrypt",
	}

	for _, comment := range commentsToCheck {
		if !strings.Contains(savedStr, comment) {
			t.Errorf("Comment not preserved after save: %q", comment)
		}
	}

	// Verify new .confcrypt section was added
	if !strings.Contains(savedStr, ".confcrypt:") {
		t.Error("Expected .confcrypt section in saved file")
	}
	if !strings.Contains(savedStr, "version: 1.0.0") {
		t.Error("Expected version in .confcrypt section")
	}
	if !strings.Contains(savedStr, "encrypted-secret") {
		t.Error("Expected encrypted secret in saved file")
	}
}
