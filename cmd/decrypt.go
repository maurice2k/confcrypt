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
	forceDecrypt       bool
	decryptAgeKeyFile  string
	decryptSSHKeyFile  string
	decryptYubiKeyFlag bool
	decryptFIDO2Flag   bool
	decryptOutputPath  string
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt encrypted values",
	Long:  `Decrypt all encrypted values in the matching config files.`,
	Run:   runDecrypt,
}

func init() {
	decryptCmd.Flags().BoolVar(&forceDecrypt, "force", false, "Continue decryption even if MAC verification fails")
	decryptCmd.Flags().StringVar(&decryptAgeKeyFile, "age-key", "", "Path to age private key file (use without value to force age auto-detect)")
	decryptCmd.Flags().StringVar(&decryptSSHKeyFile, "ssh-key", "", "Path to SSH private key file (use without value to force SSH auto-detect)")
	decryptCmd.Flags().BoolVar(&decryptYubiKeyFlag, "yubikey-key", false, "Use YubiKey HMAC challenge-response")
	decryptCmd.Flags().BoolVar(&decryptFIDO2Flag, "fido2-key", false, "Use FIDO2 hmac-secret (requires CGO build)")
	decryptCmd.Flags().StringVar(&decryptOutputPath, "output-path", "", "Write decrypted files to this directory (relative to .confcrypt.yml if not absolute)")
	// Allow --age-key and --ssh-key without a value (sets to "auto")
	decryptCmd.Flags().Lookup("age-key").NoOptDefVal = AutoDetectMarker
	decryptCmd.Flags().Lookup("ssh-key").NoOptDefVal = AutoDetectMarker
	rootCmd.AddCommand(decryptCmd)
}

func runDecrypt(cmd *cobra.Command, args []string) {
	// Load config
	cfg, err := config.Load(resolvedConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Create processor
	proc, err := processor.NewProcessor(cfg, func() ([]age.Identity, error) {
		return LoadDecryptionIdentity(cfg, "", "", false, false)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Get files to process
	files, err := GetFilesToProcess(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "No files to process\n")
		os.Exit(0)
	}

	// Check if any files have encrypted values before loading identities
	hasEncrypted := false
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if proc.HasEncryptedValues(content, file) {
			hasEncrypted = true
			break
		}
	}

	if !hasEncrypted {
		fmt.Println("No encrypted values found")
		os.Exit(0)
	}

	// Load identities based on flags
	identities, err := LoadDecryptionIdentity(cfg, decryptAgeKeyFile, decryptSSHKeyFile, decryptYubiKeyFlag, decryptFIDO2Flag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading identities: %v\n", err)
		os.Exit(1)
	}

	usedKey, err := proc.SetupDecryption(identities)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up decryption: %v\n", err)
		os.Exit(1)
	}

	// Display which key was used
	if recipient := cfg.FindRecipientByKey(usedKey); recipient != nil {
		if recipient.Name != "" {
			fmt.Printf("Using key: %s (%s)\n", recipient.Name, truncateKey(usedKey))
		} else {
			fmt.Printf("Using key: %s\n", truncateKey(usedKey))
		}
	} else {
		fmt.Printf("Using key: %s\n", truncateKey(usedKey))
	}

	anyMACsRemoved := false
	for _, file := range files {
		relPath, _ := filepath.Rel(cfg.ConfigDir(), file)
		if relPath == "" {
			relPath = file
		}

		// Read file content for MAC verification
		content, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", relPath, err)
			os.Exit(1)
		}

		// Only verify MAC if file has encrypted values
		if proc.HasEncryptedValues(content, file) {
			if err := proc.VerifyMAC(file, content); err != nil {
				if forceDecrypt {
					fmt.Fprintf(os.Stderr, "Warning: %s: %v (continuing due to --force)\n", relPath, err)
				} else {
					fmt.Fprintf(os.Stderr, "Error: %s: %v\n", relPath, err)
					fmt.Fprintf(os.Stderr, "Use --force to decrypt anyway\n")
					os.Exit(1)
				}
			}
		}

		output, modified, err := proc.ProcessFile(file, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", relPath, err)
			os.Exit(1)
		}

		if toStdout {
			fmt.Print(string(output))
		} else if modified {
			// Determine output file path
			outputFile := file
			if decryptOutputPath != "" {
				// Resolve output path (relative to config dir if not absolute)
				outDir := decryptOutputPath
				if !filepath.IsAbs(outDir) {
					outDir = filepath.Join(cfg.ConfigDir(), outDir)
				}
				outputFile = filepath.Join(outDir, relPath)
				// Create parent directories
				if err := os.MkdirAll(filepath.Dir(outputFile), 0755); err != nil {
					fmt.Fprintf(os.Stderr, "Error creating directory for %s: %v\n", outputFile, err)
					os.Exit(1)
				}
			}

			if err := proc.WriteFile(outputFile, output); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", outputFile, err)
				os.Exit(1)
			}

			// Only remove MAC if we're overwriting the source file
			if outputFile == file {
				cfg.RemoveMAC(relPath)
				anyMACsRemoved = true
			}
			fmt.Printf("Decrypted: %s\n", outputFile)
		}
	}

	// Save config if MACs were removed
	if anyMACsRemoved && !toStdout {
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			os.Exit(1)
		}
	}

	// Check if all files are now fully decrypted (no encrypted values remain)
	// If so, clear the secret store to trigger fresh key generation on next encrypt
	if !toStdout {
		// Get ALL matching files (not just the ones processed via --file flag)
		allFiles, err := cfg.GetMatchingFiles()
		if err == nil && len(allFiles) > 0 {
			hasAnyEncrypted := false
			for _, file := range allFiles {
				content, err := os.ReadFile(file)
				if err != nil {
					continue
				}
				if proc.HasEncryptedValues(content, file) {
					hasAnyEncrypted = true
					break
				}
			}

			if !hasAnyEncrypted && cfg.HasSecrets() {
				cfg.ClearSecrets()
				if err := cfg.Save(); err != nil {
					fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
					os.Exit(1)
				}
				fmt.Println("All values decrypted, secret store cleared (new key will be generated on next encrypt)")
			}
		}
	}
}
