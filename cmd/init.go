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
Use --age-key or --ssh-key to specify a particular key file.
Use --yubikey-key to generate a YubiKey-derived key.
Use --fido2-key to generate a FIDO2-derived key (requires CGO build).`,
	Run: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().StringVar(&initAgeKeyFile, "age-key", "", "Path to age private key file (use without value to force age auto-detect)")
	initCmd.Flags().StringVar(&initSSHKeyFile, "ssh-key", "", "Path to SSH public key file (use without value to force SSH auto-detect)")
	// Allow --age-key and --ssh-key without a value (sets to "auto")
	initCmd.Flags().Lookup("age-key").NoOptDefVal = AutoDetectMarker
	initCmd.Flags().Lookup("ssh-key").NoOptDefVal = AutoDetectMarker
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
		// Provide context-aware help message
		if IsFIDO2InitEnabled() {
			fmt.Fprintf(os.Stderr, "Make sure your FIDO2 security key is connected and supports hmac-secret.\n")
			fmt.Fprintf(os.Stderr, "\nAlternatively, use --age-key or --ssh-key instead.\n")
		} else if initYubiKeyFlag {
			fmt.Fprintf(os.Stderr, "Make sure your YubiKey is connected and has HMAC-SHA1 configured.\n")
			fmt.Fprintf(os.Stderr, "\nAlternatively, use --age-key or --ssh-key instead.\n")
		} else {
			fmt.Fprintf(os.Stderr, "Please create an age keypair (age-keygen -o ~/.config/age/key.txt) or ensure ~/.ssh/id_ed25519 exists\n")
		}
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
	switch keyType {
	case crypto.KeyTypeAge:
		recipientField = fmt.Sprintf("age: %s", pubKey)
	case crypto.KeyTypeYubiKey:
		recipientField = fmt.Sprintf("yubikey: %s", pubKey)
	case crypto.KeyTypeFIDO2:
		recipientField = fmt.Sprintf("fido2: %s", pubKey)
	default:
		// For SSH keys, use ssh: field
		recipientField = fmt.Sprintf("ssh: %s", pubKey)
	}

	// Escape special YAML characters in username for double-quoted string
	escapedUserName := strings.ReplaceAll(userName, `\`, `\\`)
	escapedUserName = strings.ReplaceAll(escapedUserName, `"`, `\"`)

	configContent := fmt.Sprintf(`# confcrypt configuration file
# See https://github.com/maurice2k/confcrypt for documentation

# Recipients who can decrypt the files
# Supports age keys (age:), SSH keys (ssh:), YubiKey keys (yubikey:), and FIDO2 keys (fido2:)
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
  - /private_key$/
  - /private_key_id$/

# Keys to exclude from encryption
keys_exclude:
  - /_unencrypted$/

# confcrypt metadata (do not edit manually)
.confcrypt:
  version: "%s"
`, escapedUserName, recipientField, version)

	if err := os.WriteFile(cfgPath, []byte(configContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing config file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Created %s\n", config.DefaultConfigName)
	// Truncate long keys for display
	displayKey := pubKey
	if len(pubKey) > 60 && (strings.HasPrefix(pubKey, "ssh-") || crypto.IsYubiKeyRecipient(pubKey) || crypto.IsFIDO2Recipient(pubKey)) {
		displayKey = pubKey[:50] + "..."
	}
	fmt.Printf("  Recipient: %s (%s)\n", userName, displayKey)
	fmt.Println("\nEdit the file to customize recipients, files, and key patterns.")
	fmt.Println("Then run 'confcrypt' to encrypt matching keys in your config files.")
}

// getPublicKeyForInit tries to find a public key for initializing confcrypt.
// Priority: explicit flags > auto-detect in order (age > ssh > fido2 > yubikey)
func getPublicKeyForInit() (string, crypto.KeyType, error) {
	// Explicit flags have highest priority
	if initAgeKeyFile != "" && initAgeKeyFile != AutoDetectMarker {
		return getPublicKeyFromAgeFile(initAgeKeyFile)
	}
	if initSSHKeyFile != "" && initSSHKeyFile != AutoDetectMarker {
		return getPublicKeyFromSSHFile(initSSHKeyFile)
	}
	if initAgeKeyFile == AutoDetectMarker {
		return detectAgePublicKey()
	}
	if initSSHKeyFile == AutoDetectMarker {
		return detectSSHPublicKey()
	}
	if initYubiKeyFlag {
		return generateYubiKeyRecipient()
	}
	if IsFIDO2InitEnabled() {
		return generateFIDO2Recipient()
	}

	// No flags: auto-detect in priority order (age > ssh > fido2 > yubikey)
	return detectPublicKey()
}

// detectPublicKey tries all key types in priority order
func detectPublicKey() (string, crypto.KeyType, error) {
	// Priority 1: age keys
	if key, kt, err := detectAgePublicKey(); err == nil {
		return key, kt, nil
	}
	// Priority 2: SSH keys
	if key, kt, err := detectSSHPublicKey(); err == nil {
		return key, kt, nil
	}
	// Priority 3: FIDO2 (requires device interaction)
	if IsFIDO2Available() {
		if key, kt, err := generateFIDO2Recipient(); err == nil {
			return key, kt, nil
		}
	}
	// Priority 4: YubiKey (requires device interaction)
	if IsYubiKeyAvailable() {
		if key, kt, err := generateYubiKeyRecipient(); err == nil {
			return key, kt, nil
		}
	}
	return "", crypto.KeyTypeUnknown, fmt.Errorf("no identity found")
}

// detectAgePublicKey uses shared path discovery to find age public keys
func detectAgePublicKey() (string, crypto.KeyType, error) {
	for _, path := range getAgeKeyFiles() {
		if key, kt, err := getPublicKeyFromAgeFile(path); err == nil {
			return key, kt, nil
		}
	}
	return "", crypto.KeyTypeUnknown, fmt.Errorf("no age key found")
}

// detectSSHPublicKey uses shared path discovery to find SSH public keys
func detectSSHPublicKey() (string, crypto.KeyType, error) {
	for _, path := range getSSHKeyFiles() {
		pubPath := path + ".pub"
		if key, kt, err := getPublicKeyFromSSHFile(pubPath); err == nil {
			return key, kt, nil
		}
	}
	return "", crypto.KeyTypeUnknown, fmt.Errorf("no SSH key found")
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
