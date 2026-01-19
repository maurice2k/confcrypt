package cmd

import (
	"os"
	"path/filepath"
)

// getAgeKeyFiles returns paths to check for age keys (env vars + defaults)
func getAgeKeyFiles() []string {
	var paths []string

	// Environment variables take priority
	if f := os.Getenv("SOPS_AGE_KEY_FILE"); f != "" {
		paths = append(paths, f)
	}
	if f := os.Getenv("CONFCRYPT_AGE_KEY_FILE"); f != "" {
		paths = append(paths, f)
	}

	// Default location
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, filepath.Join(home, ".config", "age", "key.txt"))
	}

	return paths
}

// getSSHKeyFiles returns paths to check for SSH keys (env vars + defaults)
func getSSHKeyFiles() []string {
	var paths []string

	// Environment variable takes priority
	if f := os.Getenv("CONFCRYPT_SSH_KEY_FILE"); f != "" {
		paths = append(paths, f)
	}

	// Default locations
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, filepath.Join(home, ".ssh", "id_ed25519"))
		paths = append(paths, filepath.Join(home, ".ssh", "id_rsa"))
	}

	return paths
}
