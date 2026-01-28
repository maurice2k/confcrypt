package config

import (
	"os"
	"path/filepath"
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
