package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/processor"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt matching keys (default command)",
	Long:  `Encrypt values for keys matching the configured patterns.`,
	Run:   runEncrypt,
}

func init() {
	rootCmd.AddCommand(encryptCmd)
}

func runEncrypt(cmd *cobra.Command, args []string) {
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

	// Check if any files have unencrypted values that need encryption
	hasUnencrypted := false
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if proc.HasUnencryptedValues(content, file) {
			hasUnencrypted = true
			break
		}
	}

	if !hasUnencrypted {
		fmt.Println("No values to encrypt")
		os.Exit(0)
	}

	// Check if secrets already exist (we'll reuse the key, no need to re-save secrets)
	hadSecrets := cfg.HasSecrets()

	if err := proc.SetupEncryption(); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up encryption: %v\n", err)
		os.Exit(1)
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
			os.Exit(1)
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
					os.Exit(1)
				}
				// Update MAC for the file
				if err := proc.UpdateMAC(file, output); err != nil {
					fmt.Fprintf(os.Stderr, "Error updating MAC for %s: %v\n", relPath, err)
					os.Exit(1)
				}
				fmt.Printf("Encrypted: %s\n", relPath)
			}
		}
	}

	// Save config if anything was modified
	if anyModified && !toStdout {
		if hadSecrets {
			// Secrets already existed, just save config (for MACs)
			if err := cfg.Save(); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
				os.Exit(1)
			}
		} else {
			// New encryption, save encrypted secrets for all recipients
			if err := proc.SaveEncryptedSecrets(); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
				os.Exit(1)
			}
		}
	}
}
