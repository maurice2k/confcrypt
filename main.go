package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/crypto"
	"github.com/maurice2k/confcrypt/internal/processor"
)

const version = "1.1.0"

func init() {
	// Set the version in the config package
	config.Version = version
}

func main() {
	// Global flags
	basePath := flag.String("path", "", "Base path where .confcrypt.yml is located (default: current directory)")
	configPath := flag.String("config", "", "Path to .confcrypt.yml config file (overrides -path)")
	filePath := flag.String("file", "", "Process a specific file only")
	stdout := flag.Bool("stdout", false, "Output to stdout instead of modifying files in-place")
	showVersion := flag.Bool("version", false, "Show version")
	help := flag.Bool("help", false, "Show help")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "confcrypt - Encrypt sensitive values in config files\n")
		fmt.Fprintf(os.Stderr, "https://github.com/maurice2k/confcrypt\n\n")
		fmt.Fprintf(os.Stderr, "Usage: confcrypt [command] [options]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  init           Initialize a new .confcrypt.yml config file\n")
		fmt.Fprintf(os.Stderr, "  encrypt        Encrypt matching keys (default)\n")
		fmt.Fprintf(os.Stderr, "  decrypt        Decrypt encrypted values\n")
		fmt.Fprintf(os.Stderr, "  check          Check for unencrypted keys (exit 1 if found)\n")
		fmt.Fprintf(os.Stderr, "  rekey          Rotate the AES key and re-encrypt all values\n")
		fmt.Fprintf(os.Stderr, "  recipient-add  Add a recipient (age key required, --name optional)\n")
		fmt.Fprintf(os.Stderr, "  recipient-rm   Remove a recipient by age key (rekeys by default)\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("confcrypt version %s\n", version)
		os.Exit(0)
	}

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	// Determine command
	command := "encrypt"
	args := flag.Args()
	if len(args) > 0 {
		switch args[0] {
		case "init", "encrypt", "decrypt", "check", "rekey", "recipient-add", "recipient-rm":
			command = args[0]
		default:
			// Treat as file path if not a command
			if *filePath == "" {
				*filePath = args[0]
			}
		}
	}

	// Resolve config path from -path or -config flags
	resolvedConfigPath := *configPath
	if resolvedConfigPath == "" && *basePath != "" {
		resolvedConfigPath = filepath.Join(*basePath, config.DefaultConfigName)
	}

	// Handle init command separately (doesn't need existing config)
	if command == "init" {
		exitCode := runInit(*basePath)
		os.Exit(exitCode)
	}

	// Handle recipient commands
	if command == "recipient-add" {
		exitCode := runRecipientAdd(resolvedConfigPath, args[1:])
		os.Exit(exitCode)
	}
	if command == "recipient-rm" {
		exitCode := runRecipientRemove(resolvedConfigPath, args[1:])
		os.Exit(exitCode)
	}

	// Handle rekey command
	if command == "rekey" {
		exitCode := runRekey(resolvedConfigPath)
		os.Exit(exitCode)
	}

	// Load config
	cfg, err := config.Load(resolvedConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Create processor
	proc, err := processor.NewProcessor(cfg, loadIdentities)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Get files to process
	var files []string
	if *filePath != "" {
		absPath, err := filepath.Abs(*filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		files = []string{absPath}
	} else {
		files, err = cfg.GetMatchingFiles()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "No files to process\n")
		os.Exit(0)
	}

	// Execute command
	switch command {
	case "encrypt":
		exitCode := runEncrypt(proc, cfg, files, *stdout)
		os.Exit(exitCode)
	case "decrypt":
		exitCode := runDecrypt(proc, cfg, files, *stdout)
		os.Exit(exitCode)
	case "check":
		exitCode := runCheck(proc, files)
		os.Exit(exitCode)
	}
}

func runEncrypt(proc *processor.Processor, cfg *config.Config, files []string, toStdout bool) int {
	if err := proc.SetupEncryption(); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up encryption: %v\n", err)
		return 1
	}

	anyModified := false
	for _, file := range files {
		relPath, _ := filepath.Rel(cfg.ConfigDir(), file)
		if relPath == "" {
			relPath = file
		}

		output, modified, err := proc.ProcessFile(file, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", relPath, err)
			return 1
		}

		if modified {
			anyModified = true
			if toStdout {
				fmt.Printf("--- %s ---\n", relPath)
				fmt.Print(string(output))
				fmt.Println()
			} else {
				if err := proc.WriteFile(file, output); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", relPath, err)
					return 1
				}
				// Update MAC for the file
				if err := proc.UpdateMAC(file, output); err != nil {
					fmt.Fprintf(os.Stderr, "Error updating MAC for %s: %v\n", relPath, err)
					return 1
				}
				fmt.Printf("Encrypted: %s\n", relPath)
			}
		}
	}

	// Save encrypted secrets and MACs to config if anything was modified
	if anyModified && !toStdout {
		if err := proc.SaveEncryptedSecrets(); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			return 1
		}
	}

	return 0
}

func runDecrypt(proc *processor.Processor, cfg *config.Config, files []string, toStdout bool) int {
	// Load identities
	identities, err := loadIdentities()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading age identities: %v\n", err)
		return 1
	}

	if err := proc.SetupDecryption(identities); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up decryption: %v\n", err)
		return 1
	}

	anyModified := false
	for _, file := range files {
		relPath, _ := filepath.Rel(cfg.ConfigDir(), file)
		if relPath == "" {
			relPath = file
		}

		// Read file content for MAC verification
		content, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", relPath, err)
			return 1
		}

		// Only verify MAC if file has encrypted values
		if proc.HasEncryptedValues(content, file) {
			if err := proc.VerifyMAC(file, content); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: %s: %v\n", relPath, err)
			}
		}

		output, modified, err := proc.ProcessFile(file, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", relPath, err)
			return 1
		}

		if toStdout {
			fmt.Print(string(output))
		} else if modified {
			if err := proc.WriteFile(file, output); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", relPath, err)
				return 1
			}
			// Remove MAC for decrypted file
			cfg.RemoveMAC(relPath)
			anyModified = true
			fmt.Printf("Decrypted: %s\n", relPath)
		}
	}

	// Save config if MACs were removed
	if anyModified && !toStdout {
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			return 1
		}
	}

	return 0
}

func runCheck(proc *processor.Processor, files []string) int {
	foundUnencrypted := false

	for _, file := range files {
		unencrypted, err := proc.CheckFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking %s: %v\n", file, err)
			return 1
		}

		if len(unencrypted) > 0 {
			foundUnencrypted = true
			fmt.Printf("%s:\n", file)
			for _, r := range unencrypted {
				fmt.Printf("  - %s\n", strings.Join(r.Path, "."))
			}
		}
	}

	if foundUnencrypted {
		fmt.Println("\nFound unencrypted keys that should be encrypted.")
		return 1
	}

	fmt.Println("All matching keys are encrypted.")
	return 0
}

// loadIdentities loads age identities from environment or default location
func loadIdentities() ([]age.Identity, error) {
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

// runInit initializes a new .confcrypt.yml configuration file
func runInit(basePath string) int {
	if basePath == "" {
		basePath = "."
	}

	// Ensure base path exists
	if info, err := os.Stat(basePath); err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: path %q does not exist or is not a directory\n", basePath)
		return 1
	}

	configPath := filepath.Join(basePath, config.DefaultConfigName)

	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		fmt.Fprintf(os.Stderr, "Error: %s already exists in %s\n", config.DefaultConfigName, basePath)
		return 1
	}

	// Try to load age identity to get public key
	identities, err := loadIdentities()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Please create an age keypair first: age-keygen -o ~/.config/age/key.txt\n")
		return 1
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
		return 1
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

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing config file: %v\n", err)
		return 1
	}

	fmt.Printf("Created %s\n", config.DefaultConfigName)
	fmt.Printf("  Recipient: %s (%s)\n", userName, pubKey)
	fmt.Println("\nEdit the file to customize recipients, files, and key patterns.")
	fmt.Println("Then run 'confcrypt' to encrypt matching keys in your config files.")

	return 0
}

// runRecipientAdd adds a new recipient to the config
func runRecipientAdd(configPath string, args []string) int {
	// Parse subcommand flags
	fs := flag.NewFlagSet("recipient-add", flag.ExitOnError)
	name := fs.String("name", "", "Name for the recipient (optional)")
	fs.Parse(args)

	remaining := fs.Args()
	if len(remaining) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: confcrypt recipient-add [--name NAME] <age-public-key>\n")
		return 1
	}

	ageKey := remaining[0]

	// Validate age key format
	if _, err := crypto.ParseAgeRecipient(ageKey); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid age public key: %v\n", err)
		return 1
	}

	// Load config
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Check if recipient already exists
	for _, r := range cfg.Recipients {
		if r.Age == ageKey {
			fmt.Fprintf(os.Stderr, "Error: recipient %s already exists\n", ageKey)
			return 1
		}
	}

	// Add recipient
	newRecipient := config.RecipientConfig{
		Age:  ageKey,
		Name: *name,
	}
	cfg.Recipients = append(cfg.Recipients, newRecipient)

	// If there are existing encrypted secrets, re-encrypt for all recipients
	if cfg.HasSecrets() {
		identities, err := loadIdentities()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot re-encrypt secrets for new recipient: %v\n", err)
			return 1
		}

		proc, err := processor.NewProcessor(cfg, loadIdentities)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}

		if err := proc.SetupEncryptionWithIdentities(identities); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}

		if err := proc.SaveEncryptedSecrets(); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving secrets: %v\n", err)
			return 1
		}
	} else {
		// No secrets yet, just save the config
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			return 1
		}
	}

	if *name != "" {
		fmt.Printf("Added recipient: %s (%s)\n", *name, ageKey)
	} else {
		fmt.Printf("Added recipient: %s\n", ageKey)
	}

	return 0
}

// runRecipientRemove removes a recipient from the config
func runRecipientRemove(configPath string, args []string) int {
	// Parse subcommand flags
	fs := flag.NewFlagSet("recipient-rm", flag.ExitOnError)
	noRekey := fs.Bool("no-rekey", false, "Don't rekey (just remove recipient's access to current key)")
	fs.Parse(args)

	remaining := fs.Args()
	if len(remaining) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: confcrypt recipient-rm [--no-rekey] <age-public-key>\n")
		return 1
	}

	ageKey := remaining[0]

	// Load config
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Find and remove recipient
	found := false
	var removedName string
	newRecipients := make([]config.RecipientConfig, 0, len(cfg.Recipients))
	for _, r := range cfg.Recipients {
		if r.Age == ageKey {
			found = true
			removedName = r.Name
		} else {
			newRecipients = append(newRecipients, r)
		}
	}

	if !found {
		fmt.Fprintf(os.Stderr, "Error: recipient %s not found\n", ageKey)
		return 1
	}

	if len(newRecipients) == 0 {
		fmt.Fprintf(os.Stderr, "Error: cannot remove last recipient\n")
		return 1
	}

	cfg.Recipients = newRecipients

	// If there are existing encrypted secrets, handle rekey
	if cfg.HasSecrets() {
		identities, err := loadIdentities()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot decrypt secrets: %v\n", err)
			return 1
		}

		if *noRekey {
			// Just re-encrypt the existing AES key for remaining recipients (no rekey)
			proc, err := processor.NewProcessor(cfg, loadIdentities)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				return 1
			}

			if err := proc.SetupEncryptionWithIdentities(identities); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				return 1
			}

			if err := proc.SaveEncryptedSecrets(); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving secrets: %v\n", err)
				return 1
			}
		} else {
			// Rekey: decrypt all, generate new key, re-encrypt all
			proc, err := processor.NewProcessor(cfg, loadIdentities)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				return 1
			}

			if err := proc.SetupDecryption(identities); err != nil {
				fmt.Fprintf(os.Stderr, "Error setting up decryption: %v\n", err)
				return 1
			}

			// Get all files
			files, err := cfg.GetMatchingFiles()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				return 1
			}

			// Decrypt all files first
			decryptedFiles := make(map[string][]byte)
			for _, file := range files {
				content, err := os.ReadFile(file)
				if err != nil {
					continue // Skip files that can't be read
				}

				if proc.HasEncryptedValues(content, file) {
					output, _, err := proc.ProcessFile(file, false) // decrypt
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error decrypting %s: %v\n", file, err)
						return 1
					}
					decryptedFiles[file] = output
				}
			}

			// Clear existing secrets to force new key generation
			cfg.Confcrypt.Store = nil

			// Create new processor with fresh key
			proc2, err := processor.NewProcessor(cfg, loadIdentities)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				return 1
			}

			if err := proc2.SetupEncryption(); err != nil {
				fmt.Fprintf(os.Stderr, "Error setting up encryption with new key: %v\n", err)
				return 1
			}

			// Re-encrypt all files with new key
			for file, content := range decryptedFiles {
				if err := os.WriteFile(file, content, 0644); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", file, err)
					return 1
				}

				output, _, err := proc2.ProcessFile(file, true) // encrypt
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error re-encrypting %s: %v\n", file, err)
					return 1
				}

				if err := os.WriteFile(file, output, 0644); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", file, err)
					return 1
				}

				if err := proc2.UpdateMAC(file, output); err != nil {
					fmt.Fprintf(os.Stderr, "Error updating MAC for %s: %v\n", file, err)
					return 1
				}
			}

			if err := proc2.SaveEncryptedSecrets(); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
				return 1
			}

			if len(decryptedFiles) > 0 {
				fmt.Printf("Rekeyed %d file(s) with new AES key\n", len(decryptedFiles))
			}
		}
	} else {
		// No secrets yet, just save the config
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			return 1
		}
	}

	if removedName != "" {
		fmt.Printf("Removed recipient: %s (%s)\n", removedName, ageKey)
	} else {
		fmt.Printf("Removed recipient: %s\n", ageKey)
	}

	return 0
}

// runRekey rotates the AES key and re-encrypts all values
func runRekey(configPath string) int {
	// Load config
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if !cfg.HasSecrets() {
		fmt.Fprintf(os.Stderr, "Error: no encrypted secrets found - nothing to rekey\n")
		return 1
	}

	// Load identities to decrypt current values
	identities, err := loadIdentities()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading age identities: %v\n", err)
		return 1
	}

	// Create processor and setup decryption with old key
	proc, err := processor.NewProcessor(cfg, loadIdentities)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if err := proc.SetupDecryption(identities); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up decryption: %v\n", err)
		return 1
	}

	// Get all files
	files, err := cfg.GetMatchingFiles()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Decrypt all files first
	decryptedFiles := make(map[string][]byte)
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", file, err)
			return 1
		}

		if proc.HasEncryptedValues(content, file) {
			output, _, err := proc.ProcessFile(file, false) // decrypt
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decrypting %s: %v\n", file, err)
				return 1
			}
			decryptedFiles[file] = output
		}
	}

	if len(decryptedFiles) == 0 {
		fmt.Println("No encrypted files found - nothing to rekey")
		return 0
	}

	// Clear existing secrets to force new key generation
	cfg.Confcrypt.Store = nil

	// Create new processor with fresh key
	proc2, err := processor.NewProcessor(cfg, loadIdentities)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if err := proc2.SetupEncryption(); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up encryption with new key: %v\n", err)
		return 1
	}

	// Write decrypted content temporarily, then re-encrypt with new key
	for file, content := range decryptedFiles {
		// Write decrypted content
		if err := os.WriteFile(file, content, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", file, err)
			return 1
		}

		// Re-encrypt with new key
		output, _, err := proc2.ProcessFile(file, true) // encrypt
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error re-encrypting %s: %v\n", file, err)
			return 1
		}

		if err := os.WriteFile(file, output, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", file, err)
			return 1
		}

		// Update MAC
		if err := proc2.UpdateMAC(file, output); err != nil {
			fmt.Fprintf(os.Stderr, "Error updating MAC for %s: %v\n", file, err)
			return 1
		}

		relPath, _ := filepath.Rel(cfg.ConfigDir(), file)
		if relPath == "" {
			relPath = file
		}
		fmt.Printf("Rekeyed: %s\n", relPath)
	}

	// Save new encrypted secrets
	if err := proc2.SaveEncryptedSecrets(); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
		return 1
	}

	fmt.Printf("\nSuccessfully rekeyed %d file(s) with new AES key\n", len(decryptedFiles))
	return 0
}
