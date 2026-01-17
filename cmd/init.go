package cmd

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/config"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new .confcrypt.yml config file",
	Long:  `Initialize a new .confcrypt.yml configuration file in the specified directory.`,
	Run:   runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
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

	// Try to load age identity to get public key
	identities, err := LoadIdentities()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Please create an age keypair first: age-keygen -o ~/.config/age/key.txt\n")
		os.Exit(1)
	}

	// Get public key from first identity
	var pubKey string
	if len(identities) > 0 {
		if x25519, ok := identities[0].(*age.X25519Identity); ok {
			pubKey = x25519.Recipient().String()
		}
	}

	if pubKey == "" {
		fmt.Fprintf(os.Stderr, "Error: could not extract public key from age identity\n")
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

	// Create default config
	configContent := fmt.Sprintf(`# confcrypt configuration file
# See https://github.com/maurice2k/confcrypt for documentation

# Recipients who can decrypt the files
recipients:
  - name: "%s"
    age: %s

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
`, userName, pubKey, version)

	if err := os.WriteFile(cfgPath, []byte(configContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing config file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Created %s\n", config.DefaultConfigName)
	fmt.Printf("  Recipient: %s (%s)\n", userName, pubKey)
	fmt.Println("\nEdit the file to customize recipients, files, and key patterns.")
	fmt.Println("Then run 'confcrypt' to encrypt matching keys in your config files.")
}
