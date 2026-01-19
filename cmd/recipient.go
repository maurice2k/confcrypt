package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/crypto"
	"github.com/maurice2k/confcrypt/internal/processor"
	"github.com/maurice2k/confcrypt/internal/yubikey"
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
	Use:   "add <public-key>",
	Short: "Add a recipient",
	Long:  `Add a new recipient who can decrypt the files. Supports age keys, SSH keys (ed25519, RSA), YubiKey, and FIDO2 recipients.`,
	Args:  cobra.ExactArgs(1),
	Run:   runRecipientAdd,
}

var recipientRmCmd = &cobra.Command{
	Use:   "rm <public-key>",
	Short: "Remove a recipient",
	Long:  `Remove a recipient. By default, this will rekey all encrypted values. Supports both age keys and SSH keys.`,
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
		pubKey := r.GetPublicKey()
		keyType := r.GetKeyType()
		displayKey := truncateKey(pubKey)

		if r.Name != "" {
			fmt.Printf("%s [%s] (%s)\n", r.Name, keyType, displayKey)
		} else {
			fmt.Printf("[%s] %s\n", keyType, displayKey)
		}
	}
}

func runRecipientAdd(cmd *cobra.Command, args []string) {
	pubKey := strings.TrimSpace(args[0])

	// Check for empty key first
	if pubKey == "" {
		fmt.Fprintf(os.Stderr, "Error: public key cannot be empty\n")
		os.Exit(1)
	}

	// Validate key format (supports age, SSH, YubiKey, and FIDO2 keys)
	if _, err := crypto.ParseRecipient(pubKey); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid public key format\n")
		fmt.Fprintf(os.Stderr, "  Expected: age1... (age key), ssh-ed25519/ssh-rsa... (SSH key), age1yubikey1... (YubiKey), or age1fido21... (FIDO2)\n")
		os.Exit(1)
	}

	// Load config
	cfg, err := config.Load(resolvedConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Check if recipient already exists (use matchesKey to ignore SSH key comments)
	for _, r := range cfg.Recipients {
		if matchesKey(r.Age, pubKey) || matchesKey(r.SSH, pubKey) || matchesKey(r.YubiKey, pubKey) || matchesKey(r.FIDO2, pubKey) {
			fmt.Fprintf(os.Stderr, "Error: recipient %s already exists\n", truncateKey(pubKey))
			os.Exit(1)
		}
	}

	// Add recipient with appropriate field based on key type
	newRecipient := config.RecipientConfig{
		Name: recipientName,
	}
	keyType := crypto.DetectKeyType(pubKey)
	switch keyType {
	case crypto.KeyTypeYubiKey:
		newRecipient.YubiKey = pubKey
	case crypto.KeyTypeFIDO2:
		newRecipient.FIDO2 = pubKey
	case crypto.KeyTypeSSHEd25519, crypto.KeyTypeSSHRSA, crypto.KeyTypeSSHECDSA:
		newRecipient.SSH = pubKey
		// If no name provided, use SSH key comment as name
		if newRecipient.Name == "" {
			if comment := extractSSHComment(pubKey); comment != "" {
				newRecipient.Name = comment
			}
		}
	default:
		newRecipient.Age = pubKey
	}
	cfg.Recipients = append(cfg.Recipients, newRecipient)

	// If there are existing encrypted secrets, re-encrypt for all recipients
	if cfg.HasSecrets() {
		identities, err := LoadDecryptionIdentity(cfg, "", "", false, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot re-encrypt secrets for new recipient: %v\n", err)
			os.Exit(1)
		}

		proc, err := processor.NewProcessor(cfg, func() ([]age.Identity, error) {
			return LoadDecryptionIdentity(cfg, "", "", false, false)
		})
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
		fmt.Printf("Added recipient: %s (%s)\n", recipientName, truncateKey(pubKey))
	} else {
		fmt.Printf("Added recipient: %s\n", truncateKey(pubKey))
	}
}

// truncateKey truncates long keys for display
func truncateKey(key string) string {
	// Truncate SSH keys
	if len(key) > 60 && (len(key) > 4 && key[:4] == "ssh-" || len(key) > 5 && key[:5] == "ecdsa") {
		return key[:50] + "..."
	}
	// Truncate YubiKey recipients (they're ~129 chars)
	if len(key) > 60 && yubikey.IsYubiKeyRecipient(key) {
		return key[:50] + "..."
	}
	// Truncate FIDO2 recipients (they can be very long due to variable credential ID)
	if len(key) > 60 && crypto.IsFIDO2Recipient(key) {
		return key[:50] + "..."
	}
	return key
}

// matchesKey checks if storedKey matches the search key.
// For SSH keys, it matches by prefix (type + key data) ignoring the comment.
// For age keys, it requires an exact match.
func matchesKey(storedKey, searchKey string) bool {
	if storedKey == "" {
		return false
	}
	// Exact match
	if storedKey == searchKey {
		return true
	}
	// For SSH keys, try prefix match (ignore comment)
	if crypto.IsSSHKey(storedKey) && crypto.IsSSHKey(searchKey) {
		storedParts := splitSSHKey(storedKey)
		searchParts := splitSSHKey(searchKey)
		// Match if type and key data are the same
		if len(storedParts) >= 2 && len(searchParts) >= 2 {
			return storedParts[0] == searchParts[0] && storedParts[1] == searchParts[1]
		}
	}
	return false
}

// splitSSHKey splits an SSH public key into parts: [type, key-data, comment (optional)]
func splitSSHKey(key string) []string {
	parts := make([]string, 0, 3)
	key = strings.TrimSpace(key)
	// Split by spaces, but only first 2 splits (type, key, rest is comment)
	for i := 0; i < 2 && len(key) > 0; i++ {
		idx := strings.Index(key, " ")
		if idx == -1 {
			parts = append(parts, key)
			return parts
		}
		parts = append(parts, key[:idx])
		key = strings.TrimSpace(key[idx+1:])
	}
	if len(key) > 0 {
		parts = append(parts, key) // comment
	}
	return parts
}

// extractSSHComment extracts the comment from an SSH public key (if present)
func extractSSHComment(key string) string {
	parts := splitSSHKey(key)
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

func runRecipientRm(cmd *cobra.Command, args []string) {
	pubKey := args[0]

	// Load config
	cfg, err := config.Load(resolvedConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Find and remove recipient (check age, ssh, yubikey, and fido2 fields)
	// For SSH keys, match by prefix (ignoring comment) to make removal easier
	found := false
	var removedName string
	newRecipients := make([]config.RecipientConfig, 0, len(cfg.Recipients))
	for _, r := range cfg.Recipients {
		if matchesKey(r.Age, pubKey) || matchesKey(r.SSH, pubKey) || matchesKey(r.YubiKey, pubKey) || matchesKey(r.FIDO2, pubKey) {
			found = true
			removedName = r.Name
		} else {
			newRecipients = append(newRecipients, r)
		}
	}

	if !found {
		fmt.Fprintf(os.Stderr, "Error: recipient %s not found\n", truncateKey(pubKey))
		os.Exit(1)
	}

	if len(newRecipients) == 0 {
		fmt.Fprintf(os.Stderr, "Error: cannot remove last recipient\n")
		os.Exit(1)
	}

	cfg.Recipients = newRecipients

	// If there are existing encrypted secrets, handle rekey
	if cfg.HasSecrets() {
		identities, err := LoadDecryptionIdentity(cfg, "", "", false, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot decrypt secrets: %v\n", err)
			os.Exit(1)
		}

		if noRekey {
			// Just re-encrypt the existing AES key for remaining recipients (no rekey)
			proc, err := processor.NewProcessor(cfg, func() ([]age.Identity, error) {
				return LoadDecryptionIdentity(cfg, "", "", false, false)
			})
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
			proc, err := processor.NewProcessor(cfg, func() ([]age.Identity, error) {
				return LoadDecryptionIdentity(cfg, "", "", false, false)
			})
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
			proc2, err := processor.NewProcessor(cfg, func() ([]age.Identity, error) {
				return LoadDecryptionIdentity(cfg, "", "", false, false)
			})
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
		fmt.Printf("Removed recipient: %s (%s)\n", removedName, truncateKey(pubKey))
	} else {
		fmt.Printf("Removed recipient: %s\n", truncateKey(pubKey))
	}
}
