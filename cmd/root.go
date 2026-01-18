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
)

const version = "1.4.0"

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
	rootCmd.PersistentFlags().StringVar(&filePath, "file", "", "Process a specific file only")
	rootCmd.PersistentFlags().BoolVar(&toStdout, "stdout", false, "Output to stdout instead of modifying files in-place")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// LoadIdentities loads ALL available identities from environment and default locations.
// Supports both native age keys and SSH keys (ed25519, RSA).
// Returns all found identities so SetupDecryption can try each one.
func LoadIdentities() ([]age.Identity, error) {
	return LoadIdentitiesWithOptions("", "")
}

// LoadIdentitiesWithOptions loads identities with optional explicit key file paths.
// If ageKeyFile is set, only load from that age key file.
// If sshKeyFile is set, only load from that SSH key file.
// If both are empty, collect ALL available identities.
func LoadIdentitiesWithOptions(ageKeyFile, sshKeyFile string) ([]age.Identity, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not determine home directory: %w", err)
	}

	// If explicit age key file is specified, use only that
	if ageKeyFile != "" {
		return loadIdentitiesFromFile(ageKeyFile)
	}

	// If explicit SSH key file is specified, use only that
	if sshKeyFile != "" {
		return loadIdentitiesFromFile(sshKeyFile)
	}

	// Collect ALL available identities
	var allIdentities []age.Identity

	// Try SOPS_AGE_KEY_FILE
	if keyFile := os.Getenv("SOPS_AGE_KEY_FILE"); keyFile != "" {
		if ids, err := loadIdentitiesFromFile(keyFile); err == nil {
			allIdentities = append(allIdentities, ids...)
		}
	}

	// Try CONFCRYPT_AGE_KEY_FILE
	if keyFile := os.Getenv("CONFCRYPT_AGE_KEY_FILE"); keyFile != "" {
		if ids, err := loadIdentitiesFromFile(keyFile); err == nil {
			allIdentities = append(allIdentities, ids...)
		}
	}

	// Try CONFCRYPT_AGE_KEY (direct key content)
	if keyContent := os.Getenv("CONFCRYPT_AGE_KEY"); keyContent != "" {
		if ids, err := crypto.ParseIdentities(keyContent); err == nil {
			allIdentities = append(allIdentities, ids...)
		}
	}

	// Try CONFCRYPT_SSH_KEY_FILE (SSH private key file)
	if keyFile := os.Getenv("CONFCRYPT_SSH_KEY_FILE"); keyFile != "" {
		if ids, err := loadIdentitiesFromFile(keyFile); err == nil {
			allIdentities = append(allIdentities, ids...)
		}
	}

	// Try default age key location
	defaultKeyFile := filepath.Join(homeDir, ".config", "age", "key.txt")
	if _, err := os.Stat(defaultKeyFile); err == nil {
		if ids, err := loadIdentitiesFromFile(defaultKeyFile); err == nil {
			allIdentities = append(allIdentities, ids...)
		}
	}

	// Try default SSH key locations
	// Use passphrase callback - agessh.EncryptedSSHIdentity has lazy evaluation,
	// so passphrase is only prompted when the identity is actually used for decryption
	sshKeyPaths := []string{
		filepath.Join(homeDir, ".ssh", "id_ed25519"),
		filepath.Join(homeDir, ".ssh", "id_rsa"),
	}
	for _, sshKeyPath := range sshKeyPaths {
		if _, err := os.Stat(sshKeyPath); err == nil {
			if ids, err := loadIdentitiesFromFile(sshKeyPath); err == nil {
				allIdentities = append(allIdentities, ids...)
			}
		}
	}

	if len(allIdentities) == 0 {
		return nil, fmt.Errorf("no identity found. Set SOPS_AGE_KEY_FILE, CONFCRYPT_AGE_KEY_FILE, CONFCRYPT_SSH_KEY_FILE, or create %s or ~/.ssh/id_ed25519", defaultKeyFile)
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
