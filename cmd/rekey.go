package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/processor"
)

var (
	rekeyAgeKeyFile string
	rekeySSHKeyFile string
)

const rekeyAutoDetectMarker = "auto"

var rekeyCmd = &cobra.Command{
	Use:   "rekey",
	Short: "Rotate the AES key and re-encrypt all values",
	Long:  `Generate a new AES key and re-encrypt all values with the new key.`,
	Run:   runRekey,
}

func init() {
	rekeyCmd.Flags().StringVar(&rekeyAgeKeyFile, "age-key", "", "Path to age private key file (use without value to force age auto-detect)")
	rekeyCmd.Flags().StringVar(&rekeySSHKeyFile, "ssh-key", "", "Path to SSH private key file (use without value to force SSH auto-detect)")
	// Allow --age-key and --ssh-key without a value (sets to "auto")
	rekeyCmd.Flags().Lookup("age-key").NoOptDefVal = rekeyAutoDetectMarker
	rekeyCmd.Flags().Lookup("ssh-key").NoOptDefVal = rekeyAutoDetectMarker
	rootCmd.AddCommand(rekeyCmd)
}

func runRekey(cmd *cobra.Command, args []string) {
	// Load config
	cfg, err := config.Load(resolvedConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !cfg.HasSecrets() {
		fmt.Fprintf(os.Stderr, "Error: no encrypted secrets found - nothing to rekey\n")
		os.Exit(1)
	}

	// Load identities to decrypt current values
	identities, err := loadRekeyIdentities()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading identities: %v\n", err)
		os.Exit(1)
	}

	// Create processor and setup decryption with old key
	proc, err := processor.NewProcessor(cfg, LoadIdentities)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if _, err := proc.SetupDecryption(identities); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up decryption: %v\n", err)
		os.Exit(1)
	}

	// Get all files
	files, err := cfg.GetMatchingFiles()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Decrypt all files first
	decryptedFiles := make(map[string][]byte)
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", file, err)
			os.Exit(1)
		}

		if proc.HasEncryptedValues(content, file) {
			output, _, err := proc.ProcessFile(file, false) // decrypt
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decrypting %s: %v\n", file, err)
				os.Exit(1)
			}
			decryptedFiles[file] = output
		}
	}

	if len(decryptedFiles) == 0 {
		fmt.Println("No encrypted files found - nothing to rekey")
		return
	}

	// Clear existing secrets to force new key generation
	cfg.Confcrypt.Store = nil

	// Create new processor with fresh key
	proc2, err := processor.NewProcessor(cfg, LoadIdentities)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := proc2.SetupEncryption(); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up encryption with new key: %v\n", err)
		os.Exit(1)
	}

	// Write decrypted content temporarily, then re-encrypt with new key
	for file, content := range decryptedFiles {
		// Write decrypted content
		if err := os.WriteFile(file, content, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", file, err)
			os.Exit(1)
		}

		// Re-encrypt with new key
		output, _, err := proc2.ProcessFile(file, true) // encrypt
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error re-encrypting %s: %v\n", file, err)
			os.Exit(1)
		}

		if err := os.WriteFile(file, output, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", file, err)
			os.Exit(1)
		}

		// Update MAC
		if err := proc2.UpdateMAC(file, output); err != nil {
			fmt.Fprintf(os.Stderr, "Error updating MAC for %s: %v\n", file, err)
			os.Exit(1)
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
		os.Exit(1)
	}

	fmt.Printf("\nSuccessfully rekeyed %d file(s) with new AES key\n", len(decryptedFiles))
}

// loadRekeyIdentities loads identities based on rekey command flags
func loadRekeyIdentities() ([]age.Identity, error) {
	// --age-key with specific path
	if rekeyAgeKeyFile != "" && rekeyAgeKeyFile != rekeyAutoDetectMarker {
		return LoadIdentitiesWithOptions(rekeyAgeKeyFile, "")
	}

	// --ssh-key with specific path
	if rekeySSHKeyFile != "" && rekeySSHKeyFile != rekeyAutoDetectMarker {
		return LoadIdentitiesWithOptions("", rekeySSHKeyFile)
	}

	// --age-key without value (auto-detect age only)
	if rekeyAgeKeyFile == rekeyAutoDetectMarker {
		return autoDetectAgeIdentities()
	}

	// --ssh-key without value (auto-detect SSH only)
	if rekeySSHKeyFile == rekeyAutoDetectMarker {
		return autoDetectSSHIdentities()
	}

	// No flags - load all available identities
	return LoadIdentities()
}
