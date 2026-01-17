package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/crypto"
)

const version = "1.3.0"

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

// LoadIdentities loads age identities from environment or default location
func LoadIdentities() ([]age.Identity, error) {
	// Try SOPS_AGE_KEY_FILE first
	if keyFile := os.Getenv("SOPS_AGE_KEY_FILE"); keyFile != "" {
		return loadIdentitiesFromFile(keyFile)
	}

	// Try CONFCRYPT_AGE_KEY_FILE
	if keyFile := os.Getenv("CONFCRYPT_AGE_KEY_FILE"); keyFile != "" {
		return loadIdentitiesFromFile(keyFile)
	}

	// Try CONFCRYPT_AGE_KEY (direct key content)
	if keyContent := os.Getenv("CONFCRYPT_AGE_KEY"); keyContent != "" {
		return crypto.ParseAgeIdentities(keyContent)
	}

	// Try default age key location
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not determine home directory: %w", err)
	}

	defaultKeyFile := filepath.Join(homeDir, ".config", "age", "key.txt")
	if _, err := os.Stat(defaultKeyFile); err == nil {
		return loadIdentitiesFromFile(defaultKeyFile)
	}

	return nil, fmt.Errorf("no age identity found. Set SOPS_AGE_KEY_FILE, CONFCRYPT_AGE_KEY_FILE, CONFCRYPT_AGE_KEY, or create %s", defaultKeyFile)
}

func loadIdentitiesFromFile(path string) ([]age.Identity, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", path, err)
	}
	return crypto.ParseAgeIdentities(string(content))
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
