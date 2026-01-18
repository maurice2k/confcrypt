package config

import (
	"testing"

	"github.com/maurice2k/confcrypt/internal/crypto"
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
