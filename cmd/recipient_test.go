package cmd

import (
	"testing"
)

func TestSplitSSHKey(t *testing.T) {
	testCases := []struct {
		name     string
		key      string
		expected []string
	}{
		{
			name:     "full key with comment",
			key:      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@example.com",
			expected: []string{"ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAItest", "user@example.com"},
		},
		{
			name:     "key without comment",
			key:      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest",
			expected: []string{"ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAItest"},
		},
		{
			name:     "key with multi-word comment",
			key:      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest John Doe's Key",
			expected: []string{"ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAItest", "John Doe's Key"},
		},
		{
			name:     "rsa key with comment",
			key:      "ssh-rsa AAAAB3NzaC1yc2EAAAAtest admin@server",
			expected: []string{"ssh-rsa", "AAAAB3NzaC1yc2EAAAAtest", "admin@server"},
		},
		{
			name:     "key with extra whitespace",
			key:      "  ssh-ed25519   AAAAC3NzaC1lZDI1NTE5AAAAItest   user@host  ",
			expected: []string{"ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAItest", "user@host"},
		},
		{
			name:     "only type",
			key:      "ssh-ed25519",
			expected: []string{"ssh-ed25519"},
		},
		{
			name:     "empty string",
			key:      "",
			expected: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := splitSSHKey(tc.key)
			if len(result) != len(tc.expected) {
				t.Errorf("Expected %d parts, got %d: %v", len(tc.expected), len(result), result)
				return
			}
			for i, part := range result {
				if part != tc.expected[i] {
					t.Errorf("Part %d: expected %q, got %q", i, tc.expected[i], part)
				}
			}
		})
	}
}

func TestExtractSSHComment(t *testing.T) {
	testCases := []struct {
		name     string
		key      string
		expected string
	}{
		{
			name:     "key with email comment",
			key:      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@example.com",
			expected: "user@example.com",
		},
		{
			name:     "key with name comment",
			key:      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest John Doe",
			expected: "John Doe",
		},
		{
			name:     "key without comment",
			key:      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest",
			expected: "",
		},
		{
			name:     "rsa key with comment",
			key:      "ssh-rsa AAAAB3NzaC1yc2EAAAAtest admin@server",
			expected: "admin@server",
		},
		{
			name:     "empty string",
			key:      "",
			expected: "",
		},
		{
			name:     "only type and data",
			key:      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest",
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := extractSSHComment(tc.key)
			if result != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestMatchesKey(t *testing.T) {
	testCases := []struct {
		name      string
		storedKey string
		searchKey string
		expected  bool
	}{
		{
			name:      "exact match age key",
			storedKey: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
			searchKey: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
			expected:  true,
		},
		{
			name:      "exact match ssh key with comment",
			storedKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@example.com",
			searchKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@example.com",
			expected:  true,
		},
		{
			name:      "ssh key match without comment",
			storedKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@example.com",
			searchKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest",
			expected:  true,
		},
		{
			name:      "ssh key match different comments",
			storedKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@example.com",
			searchKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest different@comment.com",
			expected:  true,
		},
		{
			name:      "ssh key no match different key data",
			storedKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest1 user@example.com",
			searchKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest2",
			expected:  false,
		},
		{
			name:      "ssh key no match different type",
			storedKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@example.com",
			searchKey: "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAItest",
			expected:  false,
		},
		{
			name:      "age key no match",
			storedKey: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
			searchKey: "age1different",
			expected:  false,
		},
		{
			name:      "empty stored key",
			storedKey: "",
			searchKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest",
			expected:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := matchesKey(tc.storedKey, tc.searchKey)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}
