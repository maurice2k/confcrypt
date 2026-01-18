package cmd

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/crypto"
)

var (
	initAgeKeyFile string
	initSSHKeyFile string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new .confcrypt.yml config file",
	Long: `Initialize a new .confcrypt.yml configuration file in the specified directory.

By default, auto-detects your key from environment variables and default locations.
Use --age-key or --ssh-key to specify a particular key file.`,
	Run: runInit,
}

const autoDetectMarker = "auto"

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().StringVar(&initAgeKeyFile, "age-key", "", "Path to age private key file (use without value to force age auto-detect)")
	initCmd.Flags().StringVar(&initSSHKeyFile, "ssh-key", "", "Path to SSH public key file (use without value to force SSH auto-detect)")
	// Allow --age-key and --ssh-key without a value (sets to "auto")
	initCmd.Flags().Lookup("age-key").NoOptDefVal = autoDetectMarker
	initCmd.Flags().Lookup("ssh-key").NoOptDefVal = autoDetectMarker
}

func runInit(cmd *cobra.Command, args []string) {
	path := basePath
	if path == "" {
		path = "."
	}

	// Ensure base path exists
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: path %q does not exist or is not a directory\n", path)
		os.Exit(1)
	}

	cfgPath := filepath.Join(path, config.DefaultConfigName)

	// Check if config already exists
	if _, err := os.Stat(cfgPath); err == nil {
		fmt.Fprintf(os.Stderr, "Error: %s already exists in %s\n", config.DefaultConfigName, path)
		os.Exit(1)
	}

	// Try to get public key from identity
	pubKey, keyType, err := getPublicKeyForInit()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Please create an age keypair (age-keygen -o ~/.config/age/key.txt) or ensure ~/.ssh/id_ed25519 exists\n")
		os.Exit(1)
	}

	// Get current user name
	userName := "Unknown"
	if u, err := user.Current(); err == nil {
		if u.Name != "" {
			userName = u.Name
		} else {
			userName = u.Username
		}
	}

	// Create default config with appropriate key field
	var recipientField string
	if keyType == crypto.KeyTypeAge {
		recipientField = fmt.Sprintf("age: %s", pubKey)
	} else {
		// For SSH keys, use ssh: field
		recipientField = fmt.Sprintf("ssh: %s", pubKey)
	}

	configContent := fmt.Sprintf(`# confcrypt configuration file
# See https://github.com/maurice2k/confcrypt for documentation

# Recipients who can decrypt the files
# Supports both native age keys (age:) and SSH keys (ssh:)
recipients:
  - name: "%s"
    %s

# Files to process (glob patterns)
files:
  - "*.yml"
  - "*.yaml"
  - "*.json"

# Keys to encrypt (exact match, /regex/, or $path)
# Regex patterns are case-insensitive by default
keys_include:
  - /password$/
  - /api_key$/
  - /secret$/
  - /token$/

# Keys to exclude from encryption
keys_exclude:
  - /_unencrypted$/

# confcrypt metadata (do not edit manually)
.confcrypt:
  version: "%s"
`, userName, recipientField, version)

	if err := os.WriteFile(cfgPath, []byte(configContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing config file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Created %s\n", config.DefaultConfigName)
	// Truncate long SSH keys for display
	displayKey := pubKey
	if len(pubKey) > 60 && strings.HasPrefix(pubKey, "ssh-") {
		displayKey = pubKey[:50] + "..."
	}
	fmt.Printf("  Recipient: %s (%s)\n", userName, displayKey)
	fmt.Println("\nEdit the file to customize recipients, files, and key patterns.")
	fmt.Println("Then run 'confcrypt' to encrypt matching keys in your config files.")
}

// getPublicKeyForInit tries to find a public key for initializing confcrypt.
// Priority: explicit flags > environment variables > default locations
func getPublicKeyForInit() (string, crypto.KeyType, error) {
	// --age-key with specific path
	if initAgeKeyFile != "" && initAgeKeyFile != autoDetectMarker {
		return getPublicKeyFromAgeFile(initAgeKeyFile)
	}

	// --ssh-key with specific path
	if initSSHKeyFile != "" && initSSHKeyFile != autoDetectMarker {
		return getPublicKeyFromSSHFile(initSSHKeyFile)
	}

	// --age-key without value: auto-detect age keys only
	if initAgeKeyFile == autoDetectMarker {
		return autoDetectAgeKey()
	}

	// --ssh-key without value: auto-detect SSH keys only
	if initSSHKeyFile == autoDetectMarker {
		return autoDetectSSHKey()
	}

	// No flags: full auto-detect (age first, then SSH)
	return autoDetectPublicKey()
}

// autoDetectPublicKey auto-detects the public key from environment and default locations
func autoDetectPublicKey() (string, crypto.KeyType, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("could not determine home directory: %w", err)
	}

	// Try age key files from environment variables first (same order as LoadIdentities)
	ageKeyFiles := []string{}
	if keyFile := os.Getenv("SOPS_AGE_KEY_FILE"); keyFile != "" {
		ageKeyFiles = append(ageKeyFiles, keyFile)
	}
	if keyFile := os.Getenv("CONFCRYPT_AGE_KEY_FILE"); keyFile != "" {
		ageKeyFiles = append(ageKeyFiles, keyFile)
	}
	ageKeyFiles = append(ageKeyFiles, filepath.Join(homeDir, ".config", "age", "key.txt"))

	for _, ageKeyFile := range ageKeyFiles {
		if pubKey, keyType, err := getPublicKeyFromAgeFile(ageKeyFile); err == nil {
			return pubKey, keyType, nil
		}
	}

	// Try CONFCRYPT_SSH_KEY_FILE
	if keyFile := os.Getenv("CONFCRYPT_SSH_KEY_FILE"); keyFile != "" {
		pubKeyFile := keyFile + ".pub"
		if pubKey, keyType, err := getPublicKeyFromSSHFile(pubKeyFile); err == nil {
			return pubKey, keyType, nil
		}
	}

	// Try default SSH public key files
	sshPubKeyPaths := []string{
		filepath.Join(homeDir, ".ssh", "id_ed25519.pub"),
		filepath.Join(homeDir, ".ssh", "id_rsa.pub"),
	}
	for _, sshKeyPath := range sshPubKeyPaths {
		if pubKey, keyType, err := getPublicKeyFromSSHFile(sshKeyPath); err == nil {
			return pubKey, keyType, nil
		}
	}

	return "", crypto.KeyTypeUnknown, fmt.Errorf("no identity found")
}

// autoDetectAgeKey auto-detects age keys only (ignores SSH)
func autoDetectAgeKey() (string, crypto.KeyType, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("could not determine home directory: %w", err)
	}

	ageKeyFiles := []string{}
	if keyFile := os.Getenv("SOPS_AGE_KEY_FILE"); keyFile != "" {
		ageKeyFiles = append(ageKeyFiles, keyFile)
	}
	if keyFile := os.Getenv("CONFCRYPT_AGE_KEY_FILE"); keyFile != "" {
		ageKeyFiles = append(ageKeyFiles, keyFile)
	}
	ageKeyFiles = append(ageKeyFiles, filepath.Join(homeDir, ".config", "age", "key.txt"))

	for _, ageKeyFile := range ageKeyFiles {
		if pubKey, keyType, err := getPublicKeyFromAgeFile(ageKeyFile); err == nil {
			return pubKey, keyType, nil
		}
	}

	return "", crypto.KeyTypeUnknown, fmt.Errorf("no age identity found")
}

// autoDetectSSHKey auto-detects SSH keys only (ignores age)
func autoDetectSSHKey() (string, crypto.KeyType, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("could not determine home directory: %w", err)
	}

	// Try CONFCRYPT_SSH_KEY_FILE
	if keyFile := os.Getenv("CONFCRYPT_SSH_KEY_FILE"); keyFile != "" {
		pubKeyFile := keyFile + ".pub"
		if pubKey, keyType, err := getPublicKeyFromSSHFile(pubKeyFile); err == nil {
			return pubKey, keyType, nil
		}
	}

	// Try default SSH public key files
	sshPubKeyPaths := []string{
		filepath.Join(homeDir, ".ssh", "id_ed25519.pub"),
		filepath.Join(homeDir, ".ssh", "id_rsa.pub"),
	}
	for _, sshKeyPath := range sshPubKeyPaths {
		if pubKey, keyType, err := getPublicKeyFromSSHFile(sshKeyPath); err == nil {
			return pubKey, keyType, nil
		}
	}

	return "", crypto.KeyTypeUnknown, fmt.Errorf("no SSH identity found")
}

// getPublicKeyFromAgeFile extracts public key from an age private key file
func getPublicKeyFromAgeFile(path string) (string, crypto.KeyType, error) {
	if _, err := os.Stat(path); err != nil {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("age key file not found: %s", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("failed to read age key file: %w", err)
	}
	identities, err := crypto.ParseIdentities(string(content))
	if err != nil {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("failed to parse age key: %w", err)
	}
	if len(identities) == 0 {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("no identities found in %s", path)
	}
	if x25519, ok := identities[0].(*age.X25519Identity); ok {
		return x25519.Recipient().String(), crypto.KeyTypeAge, nil
	}
	return "", crypto.KeyTypeUnknown, fmt.Errorf("unexpected identity type in %s", path)
}

// getPublicKeyFromSSHFile reads and validates an SSH public key file
func getPublicKeyFromSSHFile(path string) (string, crypto.KeyType, error) {
	if _, err := os.Stat(path); err != nil {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("SSH key file not found: %s", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("failed to read SSH key file: %w", err)
	}
	pubKey := strings.TrimSpace(string(content))
	if _, err := agessh.ParseRecipient(pubKey); err != nil {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("invalid SSH public key: %w", err)
	}
	return pubKey, crypto.DetectKeyType(pubKey), nil
}
