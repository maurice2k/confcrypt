package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/processor"
)

var (
	dryRun     bool
	jsonOutput bool
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt matching keys (default command)",
	Long:  `Encrypt values for keys matching the configured patterns.`,
	Run:   runEncrypt,
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be encrypted without making changes")
	encryptCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output encrypted fields in JSON format")
}

func runEncrypt(cmd *cobra.Command, args []string) {
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
		if jsonOutput {
			fmt.Println(`{"files":{}}`)
		} else {
			fmt.Fprintf(os.Stderr, "No files to process\n")
		}
		os.Exit(0)
	}

	// Handle dry-run mode (preview only, no changes)
	if dryRun {
		runEncryptDryRun(proc, cfg, files)
		return
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
		if jsonOutput {
			fmt.Println(`{"files":{}}`)
		} else {
			fmt.Println("No values to encrypt")
		}
		os.Exit(0)
	}

	// Collect what will be encrypted (for JSON output)
	var encryptedFields map[string][]string
	if jsonOutput {
		encryptedFields = make(map[string][]string)
		for _, file := range files {
			unencrypted, err := proc.CheckFile(file)
			if err != nil {
				continue
			}
			if len(unencrypted) > 0 {
				var fields []string
				for _, r := range unencrypted {
					fields = append(fields, strings.Join(r.Path, "."))
				}
				encryptedFields[file] = fields
			}
		}
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
				if !jsonOutput {
					fmt.Printf("Encrypted: %s\n", relPath)
				}
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

	// Output JSON if requested
	if jsonOutput {
		output := struct {
			Files map[string][]string `json:"files"`
		}{
			Files: encryptedFields,
		}
		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonBytes))
	}
}

// runEncryptDryRun handles --dry-run and --json output modes
func runEncryptDryRun(proc *processor.Processor, cfg *config.Config, files []string) {
	// Collect unencrypted keys per file
	result := make(map[string][]string)

	for _, file := range files {
		unencrypted, err := proc.CheckFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking %s: %v\n", file, err)
			os.Exit(1)
		}

		if len(unencrypted) > 0 {
			var fields []string
			for _, r := range unencrypted {
				fields = append(fields, strings.Join(r.Path, "."))
			}
			result[file] = fields
		}
	}

	if jsonOutput {
		output := struct {
			Files map[string][]string `json:"files"`
		}{
			Files: result,
		}
		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonBytes))
	} else {
		// Human-readable dry-run output
		if len(result) == 0 {
			fmt.Println("No values to encrypt")
			return
		}

		fmt.Println("Would encrypt:")
		for file, fields := range result {
			relPath, _ := filepath.Rel(cfg.ConfigDir(), file)
			if relPath == "" {
				relPath = file
			}
			fmt.Printf("  %s:\n", relPath)
			for _, field := range fields {
				fmt.Printf("    - %s\n", field)
			}
		}
	}
}
