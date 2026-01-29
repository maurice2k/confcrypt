package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/crypto"
	"github.com/maurice2k/confcrypt/internal/yubikey"
)

// version can be overridden at build time via:
//
//	go build -ldflags "-X github.com/maurice2k/confcrypt/cmd.version=x.y.z"
var version = "dev"

const AutoDetectMarker = "auto"

var (
	// Global flags
	basePath   string
	configPath string
	filePath   string
	toStdout   bool

	// Resolved config path (computed from flags)
	resolvedConfigPath string
)

func init() {
	config.Version = version
}

var rootCmd = &cobra.Command{
	Use:   "confcrypt",
	Short: "Encrypt sensitive values in config files",
	Long: `confcrypt - Encrypt sensitive values in config files
https://github.com/maurice2k/confcrypt`,
	Version: version,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Resolve config path from flags
		resolvedConfigPath = configPath
		if resolvedConfigPath == "" && basePath != "" {
			resolvedConfigPath = filepath.Join(basePath, config.DefaultConfigName)
		}
	},
	// Run encrypt by default when no subcommand is given
	Run: func(cmd *cobra.Command, args []string) {
		encryptCmd.Run(cmd, args)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&basePath, "path", "", "Base path where .confcrypt.yml is located (default: current directory)")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to .confcrypt.yml config file (overrides --path)")
	rootCmd.PersistentFlags().StringVar(&filePath, "file", "", "Process a specific file only (deprecated: use positional argument instead)")
	rootCmd.PersistentFlags().BoolVar(&toStdout, "stdout", false, "Output to stdout instead of modifying files in-place")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// loadFileBasedIdentities loads ALL available file-based identities (age and SSH) from environment and default locations.
// Uses shared path discovery from keydetect.go
func loadFileBasedIdentities() ([]age.Identity, error) {
	var allIdentities []age.Identity

	// Load age identities
	for _, path := range getAgeKeyFiles() {
		if ids, err := loadIdentitiesFromFile(path); err == nil {
			allIdentities = append(allIdentities, ids...)
		}
	}

	// Try CONFCRYPT_AGE_KEY (direct key content)
	if keyContent := os.Getenv("CONFCRYPT_AGE_KEY"); keyContent != "" {
		if ids, err := crypto.ParseIdentities(keyContent); err == nil {
			allIdentities = append(allIdentities, ids...)
		}
	}

	// Load SSH identities
	for _, path := range getSSHKeyFiles() {
		if _, err := os.Stat(path); err == nil {
			if ids, err := loadIdentitiesFromFile(path); err == nil {
				allIdentities = append(allIdentities, ids...)
			}
		}
	}

	if len(allIdentities) == 0 {
		return nil, fmt.Errorf("no identity found. Set SOPS_AGE_KEY_FILE, CONFCRYPT_AGE_KEY_FILE, CONFCRYPT_SSH_KEY_FILE, or create ~/.config/age/key.txt or ~/.ssh/id_ed25519")
	}

	return allIdentities, nil
}

func loadIdentitiesFromFile(path string) ([]age.Identity, error) {
	return loadIdentitiesFromFileWithPassphrase(path, promptPassphrase)
}

func loadIdentitiesFromFileWithPassphrase(path string, passphraseFunc crypto.PassphraseFunc) ([]age.Identity, error) {
	// Check file permissions for SSH keys (security warning)
	if info, err := os.Stat(path); err == nil {
		perm := info.Mode().Perm()
		if strings.Contains(path, ".ssh") && perm&0077 != 0 {
			fmt.Fprintf(os.Stderr, "Warning: %s has permissive permissions %04o, should be 0600\n", path, perm)
		}
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", path, err)
	}
	return crypto.ParseIdentitiesWithPassphrase(string(content), path, passphraseFunc)
}

// promptPassphrase prompts the user for a passphrase to decrypt an SSH key.
func promptPassphrase(keyPath string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "Enter passphrase for %s: ", filepath.Base(keyPath))
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after password input
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	return passphrase, nil
}

// GetFilesToProcess returns the list of files to process based on flags and config
func GetFilesToProcess(cfg *config.Config) ([]string, error) {
	if filePath != "" {
		absPath, err := filepath.Abs(filePath)
		if err != nil {
			return nil, err
		}
		return []string{absPath}, nil
	}
	return cfg.GetMatchingFiles()
}

// ResolveTarget resolves a target path (file or folder) to a config path and optional single file.
// For a file: searches upward from the file's directory to find .confcrypt.yml
// For a folder: the folder must contain .confcrypt.yml directly (no upward search)
// Returns: configPath, singleFile (empty if folder/all files), error
func ResolveTarget(target string) (configPath string, singleFile string, err error) {
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", "", fmt.Errorf("failed to resolve path: %w", err)
	}

	info, err := os.Stat(absTarget)
	if err != nil {
		return "", "", fmt.Errorf("target not found: %w", err)
	}

	if info.IsDir() {
		// Folder: config must be directly in this folder
		cfgPath := filepath.Join(absTarget, config.DefaultConfigName)
		if _, err := os.Stat(cfgPath); err != nil {
			return "", "", fmt.Errorf("no %s in folder %s", config.DefaultConfigName, target)
		}
		return cfgPath, "", nil
	}

	// File: search upward from file's directory
	cfgPath, err := config.FindConfigFromPath(filepath.Dir(absTarget))
	if err != nil {
		return "", "", err
	}
	return cfgPath, absTarget, nil
}

// LoadDecryptionIdentity loads a single identity that can decrypt a store entry.
// Priority: age > ssh > fido2 > yubikey
// Only loads identity types that are present in the store.
func LoadDecryptionIdentity(cfg *config.Config, ageKeyFile, sshKeyFile string, useYubiKey, useFIDO2 bool) ([]age.Identity, error) {
	// Get recipients from store
	storeRecipients := getStoreRecipients(cfg)
	if len(storeRecipients) == 0 {
		// No store entries - load all available for first encryption
		return loadAllAvailableIdentities(cfg)
	}

	// Explicit flags: only try that type
	if ageKeyFile != "" && ageKeyFile != AutoDetectMarker {
		return findAgeIdentity(ageKeyFile, storeRecipients)
	}
	if sshKeyFile != "" && sshKeyFile != AutoDetectMarker {
		return findSSHIdentity(sshKeyFile, storeRecipients)
	}
	if ageKeyFile == AutoDetectMarker {
		return findMatchingAgeIdentity(storeRecipients)
	}
	if sshKeyFile == AutoDetectMarker {
		return findMatchingSSHIdentity(storeRecipients)
	}
	if useYubiKey {
		return findYubiKeyIdentity(storeRecipients)
	}
	if useFIDO2 {
		return findFIDO2Identity(storeRecipients)
	}

	// No flags: iterate by priority, only for types in store
	requiredTypes := getRequiredKeyTypes(storeRecipients)

	// Priority 1 & 2: age and SSH (file-based identities)
	if requiredTypes[crypto.KeyTypeAge] || hasSSHTypes(requiredTypes) {
		if ids, err := findMatchingFileIdentity(storeRecipients); err == nil && len(ids) > 0 {
			return ids, nil
		}
	}
	// Priority 3: FIDO2
	if requiredTypes[crypto.KeyTypeFIDO2] {
		if ids, err := findFIDO2Identity(storeRecipients); err == nil && len(ids) > 0 {
			return ids, nil
		}
	}
	// Priority 4: YubiKey
	if requiredTypes[crypto.KeyTypeYubiKey] {
		if ids, err := findYubiKeyIdentity(storeRecipients); err == nil && len(ids) > 0 {
			return ids, nil
		}
	}

	return nil, fmt.Errorf("no matching identity found for store recipients")
}

// getStoreRecipients returns a list of recipient public keys from the store
func getStoreRecipients(cfg *config.Config) []string {
	var recipients []string
	if cfg.Confcrypt == nil {
		return recipients
	}
	for _, entry := range cfg.Confcrypt.Store {
		recipients = append(recipients, entry.Recipient)
	}
	return recipients
}

// getRequiredKeyTypes returns a map of key types required by store recipients
func getRequiredKeyTypes(storeRecipients []string) map[crypto.KeyType]bool {
	types := make(map[crypto.KeyType]bool)
	for _, recipient := range storeRecipients {
		keyType := crypto.DetectKeyType(recipient)
		types[keyType] = true
	}
	return types
}

// hasSSHTypes checks if any SSH key types are in the map
func hasSSHTypes(types map[crypto.KeyType]bool) bool {
	return types[crypto.KeyTypeSSHEd25519] || types[crypto.KeyTypeSSHRSA] || types[crypto.KeyTypeSSHECDSA]
}

// loadAllAvailableIdentities loads all available identities when store is empty
func loadAllAvailableIdentities(cfg *config.Config) ([]age.Identity, error) {
	var identities []age.Identity

	// Load file-based identities
	if ids, err := loadFileBasedIdentities(); err == nil {
		identities = append(identities, ids...)
	}

	// Load YubiKey identities
	if ykIds, err := loadYubiKeyIdentities(cfg); err == nil {
		identities = append(identities, ykIds...)
	}

	// Load FIDO2 identities
	if fido2Ids, err := loadFIDO2Identities(cfg); err == nil {
		identities = append(identities, fido2Ids...)
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("no identities found")
	}

	return identities, nil
}

// findAgeIdentity loads an age identity from a specific path
func findAgeIdentity(path string, storeRecipients []string) ([]age.Identity, error) {
	ids, pubKey, err := loadAgeIdentityWithPubKey(path)
	if err != nil {
		return nil, err
	}
	if contains(storeRecipients, pubKey) {
		return ids, nil
	}
	return nil, fmt.Errorf("age identity at %s does not match any store recipient", path)
}

// findSSHIdentity loads an SSH identity from a specific path
func findSSHIdentity(path string, storeRecipients []string) ([]age.Identity, error) {
	ids, pubKey, err := loadSSHIdentityWithPubKey(path)
	if err != nil {
		return nil, err
	}
	if containsSSHKey(storeRecipients, pubKey) {
		return ids, nil
	}
	return nil, fmt.Errorf("SSH identity at %s does not match any store recipient", path)
}

// findMatchingAgeIdentity finds an age identity that matches a store recipient
func findMatchingAgeIdentity(storeRecipients []string) ([]age.Identity, error) {
	for _, path := range getAgeKeyFiles() {
		if ids, pubKey, err := loadAgeIdentityWithPubKey(path); err == nil {
			if contains(storeRecipients, pubKey) {
				return ids, nil
			}
		}
	}
	return nil, fmt.Errorf("no matching age identity found")
}

// findMatchingSSHIdentity finds an SSH identity that matches a store recipient
func findMatchingSSHIdentity(storeRecipients []string) ([]age.Identity, error) {
	for _, path := range getSSHKeyFiles() {
		if ids, pubKey, err := loadSSHIdentityWithPubKey(path); err == nil {
			if containsSSHKey(storeRecipients, pubKey) {
				return ids, nil
			}
		}
	}
	return nil, fmt.Errorf("no matching SSH identity found")
}

// findMatchingFileIdentity checks if any local age/SSH key matches a store recipient
func findMatchingFileIdentity(storeRecipients []string) ([]age.Identity, error) {
	// For age keys: load identity, get public key, check if in storeRecipients
	for _, path := range getAgeKeyFiles() {
		if ids, pubKey, err := loadAgeIdentityWithPubKey(path); err == nil {
			if contains(storeRecipients, pubKey) {
				return ids, nil
			}
		}
	}

	// For SSH keys: load identity, derive public key, check if in storeRecipients
	for _, path := range getSSHKeyFiles() {
		if ids, pubKey, err := loadSSHIdentityWithPubKey(path); err == nil {
			if containsSSHKey(storeRecipients, pubKey) {
				return ids, nil
			}
		}
	}

	return nil, fmt.Errorf("no matching file identity found")
}

// findYubiKeyIdentity checks if connected YubiKey matches any store recipient
func findYubiKeyIdentity(storeRecipients []string) ([]age.Identity, error) {
	for _, recipient := range storeRecipients {
		if !yubikey.IsYubiKeyRecipient(recipient) {
			continue
		}
		ykId, err := yubikey.DecodeRecipient(recipient)
		if err != nil {
			continue
		}
		// Check if this YubiKey is connected (uses serial from recipient)
		if _, err := yubikey.FindYubiKeyBySerial(ykId.Serial); err != nil {
			continue
		}
		// YubiKey is connected - derive identity
		fmt.Fprintf(os.Stderr, "Found YubiKey %d, touch to decrypt...\n", ykId.Serial)
		identity, err := ykId.ToAgeIdentity()
		if err != nil {
			continue
		}
		return []age.Identity{identity}, nil
	}
	return nil, fmt.Errorf("no matching YubiKey found")
}

// findFIDO2Identity checks if connected FIDO2 device matches any store recipient
// This is implemented in helpers_fido2.go / helpers_nofido2.go
func findFIDO2Identity(storeRecipients []string) ([]age.Identity, error) {
	return findFIDO2IdentityImpl(storeRecipients)
}

// loadAgeIdentityWithPubKey loads an age identity and returns both the identity and its public key
func loadAgeIdentityWithPubKey(path string) ([]age.Identity, string, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, "", err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	ids, err := crypto.ParseIdentities(string(content))
	if err != nil {
		return nil, "", err
	}
	if len(ids) == 0 {
		return nil, "", fmt.Errorf("no identities in file")
	}
	// Get public key from first identity
	if x25519, ok := ids[0].(*age.X25519Identity); ok {
		return ids, x25519.Recipient().String(), nil
	}
	return nil, "", fmt.Errorf("not an age X25519 identity")
}

// loadSSHIdentityWithPubKey loads an SSH identity and returns both the identity and its public key
func loadSSHIdentityWithPubKey(path string) ([]age.Identity, string, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, "", err
	}

	// Load identity from private key
	ids, err := loadIdentitiesFromFile(path)
	if err != nil {
		return nil, "", err
	}
	if len(ids) == 0 {
		return nil, "", fmt.Errorf("no identities in file")
	}

	// Read public key from .pub file
	pubPath := path + ".pub"
	pubContent, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read public key: %w", err)
	}

	pubKey := strings.TrimSpace(string(pubContent))
	return ids, pubKey, nil
}

// contains checks if a string is in a slice
func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// containsSSHKey checks if an SSH public key matches any recipient in the slice
// SSH keys can have different comments, so we match by key content (first two space-separated fields)
func containsSSHKey(storeRecipients []string, pubKey string) bool {
	// Extract key type and key data (ignore comment)
	pubKeyParts := strings.Fields(pubKey)
	if len(pubKeyParts) < 2 {
		return false
	}
	pubKeyPrefix := pubKeyParts[0] + " " + pubKeyParts[1]

	for _, recipient := range storeRecipients {
		recipientParts := strings.Fields(recipient)
		if len(recipientParts) >= 2 {
			recipientPrefix := recipientParts[0] + " " + recipientParts[1]
			if recipientPrefix == pubKeyPrefix {
				return true
			}
		}
	}
	return false
}
