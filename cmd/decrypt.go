package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/processor"
)

var forceDecrypt bool

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt encrypted values",
	Long:  `Decrypt all encrypted values in the matching config files.`,
	Run:   runDecrypt,
}

func init() {
	decryptCmd.Flags().BoolVar(&forceDecrypt, "force", false, "Continue decryption even if MAC verification fails")
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
	proc, err := processor.NewProcessor(cfg, LoadIdentities)
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

	// Load identities
	identities, err := LoadIdentities()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading age identities: %v\n", err)
		os.Exit(1)
	}

	if err := proc.SetupDecryption(identities); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up decryption: %v\n", err)
		os.Exit(1)
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
			if err := proc.WriteFile(file, output); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", relPath, err)
				os.Exit(1)
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
			os.Exit(1)
		}
	}
}
