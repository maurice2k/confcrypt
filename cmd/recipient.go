package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/crypto"
	"github.com/maurice2k/confcrypt/internal/processor"
)

var (
	recipientName string
	noRekey       bool
)

var recipientCmd = &cobra.Command{
	Use:   "recipient",
	Short: "Manage recipients",
	Long:  `Add or remove recipients who can decrypt the files.`,
}

var recipientAddCmd = &cobra.Command{
	Use:   "add <age-public-key>",
	Short: "Add a recipient",
	Long:  `Add a new recipient who can decrypt the files.`,
	Args:  cobra.ExactArgs(1),
	Run:   runRecipientAdd,
}

var recipientRmCmd = &cobra.Command{
	Use:   "rm <age-public-key>",
	Short: "Remove a recipient",
	Long:  `Remove a recipient. By default, this will rekey all encrypted values.`,
	Args:  cobra.ExactArgs(1),
	Run:   runRecipientRm,
}

var recipientListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all recipients",
	Long:  `List all recipients who can decrypt the files.`,
	Run:   runRecipientList,
}

func init() {
	recipientAddCmd.Flags().StringVar(&recipientName, "name", "", "Name for the recipient (optional)")
	recipientRmCmd.Flags().BoolVar(&noRekey, "no-rekey", false, "Don't rekey (just remove recipient's access to current key)")

	recipientCmd.AddCommand(recipientAddCmd)
	recipientCmd.AddCommand(recipientRmCmd)
	recipientCmd.AddCommand(recipientListCmd)
	rootCmd.AddCommand(recipientCmd)
}

func runRecipientList(cmd *cobra.Command, args []string) {
	// Load config
	cfg, err := config.Load(resolvedConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(cfg.Recipients) == 0 {
		fmt.Println("No recipients configured.")
		return
	}

	for _, r := range cfg.Recipients {
		if r.Name != "" {
			fmt.Printf("%s (%s)\n", r.Name, r.Age)
		} else {
			fmt.Println(r.Age)
		}
	}
}

func runRecipientAdd(cmd *cobra.Command, args []string) {
	ageKey := args[0]

	// Validate age key format
	if _, err := crypto.ParseAgeRecipient(ageKey); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid age public key: %v\n", err)
		os.Exit(1)
	}

	// Load config
	cfg, err := config.Load(resolvedConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Check if recipient already exists
	for _, r := range cfg.Recipients {
		if r.Age == ageKey {
			fmt.Fprintf(os.Stderr, "Error: recipient %s already exists\n", ageKey)
			os.Exit(1)
		}
	}

	// Add recipient
	newRecipient := config.RecipientConfig{
		Age:  ageKey,
		Name: recipientName,
	}
	cfg.Recipients = append(cfg.Recipients, newRecipient)

	// If there are existing encrypted secrets, re-encrypt for all recipients
	if cfg.HasSecrets() {
		identities, err := LoadIdentities()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot re-encrypt secrets for new recipient: %v\n", err)
			os.Exit(1)
		}

		proc, err := processor.NewProcessor(cfg, LoadIdentities)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := proc.SetupEncryptionWithIdentities(identities); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := proc.SaveEncryptedSecrets(); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving secrets: %v\n", err)
			os.Exit(1)
		}
	} else {
		// No secrets yet, just save the config
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			os.Exit(1)
		}
	}

	if recipientName != "" {
		fmt.Printf("Added recipient: %s (%s)\n", recipientName, ageKey)
	} else {
		fmt.Printf("Added recipient: %s\n", ageKey)
	}
}

func runRecipientRm(cmd *cobra.Command, args []string) {
	ageKey := args[0]

	// Load config
	cfg, err := config.Load(resolvedConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
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
		os.Exit(1)
	}

	if len(newRecipients) == 0 {
		fmt.Fprintf(os.Stderr, "Error: cannot remove last recipient\n")
		os.Exit(1)
	}

	cfg.Recipients = newRecipients

	// If there are existing encrypted secrets, handle rekey
	if cfg.HasSecrets() {
		identities, err := LoadIdentities()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot decrypt secrets: %v\n", err)
			os.Exit(1)
		}

		if noRekey {
			// Just re-encrypt the existing AES key for remaining recipients (no rekey)
			proc, err := processor.NewProcessor(cfg, LoadIdentities)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := proc.SetupEncryptionWithIdentities(identities); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := proc.SaveEncryptedSecrets(); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving secrets: %v\n", err)
				os.Exit(1)
			}
		} else {
			// Rekey: decrypt all, generate new key, re-encrypt all
			proc, err := processor.NewProcessor(cfg, LoadIdentities)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := proc.SetupDecryption(identities); err != nil {
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
					continue // Skip files that can't be read
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

			// Re-encrypt all files with new key
			for file, content := range decryptedFiles {
				if err := os.WriteFile(file, content, 0644); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", file, err)
					os.Exit(1)
				}

				output, _, err := proc2.ProcessFile(file, true) // encrypt
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error re-encrypting %s: %v\n", file, err)
					os.Exit(1)
				}

				if err := os.WriteFile(file, output, 0644); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", file, err)
					os.Exit(1)
				}

				if err := proc2.UpdateMAC(file, output); err != nil {
					fmt.Fprintf(os.Stderr, "Error updating MAC for %s: %v\n", file, err)
					os.Exit(1)
				}
			}

			if err := proc2.SaveEncryptedSecrets(); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
				os.Exit(1)
			}

			if len(decryptedFiles) > 0 {
				relPaths := make([]string, 0, len(decryptedFiles))
				for file := range decryptedFiles {
					relPath, _ := filepath.Rel(cfg.ConfigDir(), file)
					if relPath == "" {
						relPath = file
					}
					relPaths = append(relPaths, relPath)
				}
				fmt.Printf("Rekeyed %d file(s) with new AES key\n", len(decryptedFiles))
			}
		}
	} else {
		// No secrets yet, just save the config
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			os.Exit(1)
		}
	}

	if removedName != "" {
		fmt.Printf("Removed recipient: %s (%s)\n", removedName, ageKey)
	} else {
		fmt.Printf("Removed recipient: %s\n", ageKey)
	}
}
