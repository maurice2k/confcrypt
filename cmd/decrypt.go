package cmd

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

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
	decryptOutputTar   string
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt [file|folder]",
	Short: "Decrypt encrypted values",
	Long: `Decrypt all encrypted values in the matching config files.

If a file is specified, searches upward from the file's directory to find .confcrypt.yml
and decrypts only that file.

If a folder is specified, it must contain .confcrypt.yml directly and all matching
files in that folder are decrypted.

If no argument is given, searches from current directory upward for .confcrypt.yml.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runDecrypt,
}

func init() {
	decryptCmd.Flags().BoolVar(&forceDecrypt, "force", false, "Continue decryption even if MAC verification fails")
	decryptCmd.Flags().StringVar(&decryptAgeKeyFile, "age-key", "", "Path to age private key file (use without value to force age auto-detect)")
	decryptCmd.Flags().StringVar(&decryptSSHKeyFile, "ssh-key", "", "Path to SSH private key file (use without value to force SSH auto-detect)")
	decryptCmd.Flags().BoolVar(&decryptYubiKeyFlag, "yubikey-key", false, "Use YubiKey HMAC challenge-response")
	decryptCmd.Flags().BoolVar(&decryptFIDO2Flag, "fido2-key", false, "Use FIDO2 hmac-secret (requires CGO build)")
	decryptCmd.Flags().StringVar(&decryptOutputPath, "output-path", "", "Write decrypted files to this directory (relative to .confcrypt.yml if not absolute)")
	decryptCmd.Flags().StringVar(&decryptOutputTar, "output-tar", "", "Write decrypted files to tar archive (use '-' for stdout)")
	// Allow --age-key and --ssh-key without a value (sets to "auto")
	decryptCmd.Flags().Lookup("age-key").NoOptDefVal = AutoDetectMarker
	decryptCmd.Flags().Lookup("ssh-key").NoOptDefVal = AutoDetectMarker
	rootCmd.AddCommand(decryptCmd)
}

func runDecrypt(cmd *cobra.Command, args []string) {
	// Check mutually exclusive flags
	if decryptOutputTar != "" && decryptOutputPath != "" {
		fmt.Fprintf(os.Stderr, "Error: cannot use both --output-tar and --output-path\n")
		os.Exit(1)
	}
	if decryptOutputTar != "" && toStdout {
		fmt.Fprintf(os.Stderr, "Error: cannot use both --output-tar and --stdout\n")
		os.Exit(1)
	}

	var singleFile string
	cfgPath := resolvedConfigPath

	// Handle positional argument
	if len(args) > 0 {
		// Check for conflict with --file flag
		if filePath != "" {
			fmt.Fprintf(os.Stderr, "Error: cannot use both positional argument and --file flag\n")
			os.Exit(1)
		}

		var err error
		cfgPath, singleFile, err = ResolveTarget(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	// Load config
	cfg, err := config.Load(cfgPath)
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
	var files []string
	if singleFile != "" {
		files = []string{singleFile}
	} else {
		files, err = GetFilesToProcess(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
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
		// If outputting to tar, create an empty tar file
		if decryptOutputTar != "" {
			var out io.Writer
			if decryptOutputTar == "-" {
				out = os.Stdout
			} else {
				f, err := os.Create(decryptOutputTar)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error creating tar file: %v\n", err)
					os.Exit(1)
				}
				defer f.Close()
				out = f
			}
			tw := tar.NewWriter(out)
			tw.Close() // Creates valid empty tar with EOF blocks
			fmt.Fprintf(os.Stderr, "No encrypted values found (empty tar created)\n")
			os.Exit(0)
		}
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

	// Display which key was used (to stderr if tar goes to stdout)
	printInfo := func(format string, args ...interface{}) {
		if decryptOutputTar == "-" {
			fmt.Fprintf(os.Stderr, format, args...)
		} else {
			fmt.Printf(format, args...)
		}
	}
	if recipient := cfg.FindRecipientByKey(usedKey); recipient != nil {
		if recipient.Name != "" {
			printInfo("Using key: %s (%s)\n", recipient.Name, truncateKey(usedKey))
		} else {
			printInfo("Using key: %s\n", truncateKey(usedKey))
		}
	} else {
		printInfo("Using key: %s\n", truncateKey(usedKey))
	}

	// Set up tar writer if --output-tar is specified
	var tarWriter *tar.Writer
	var tarFile *os.File
	if decryptOutputTar != "" {
		var out io.Writer
		if decryptOutputTar == "-" {
			out = os.Stdout
		} else {
			var err error
			tarFile, err = os.Create(decryptOutputTar)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating tar file: %v\n", err)
				os.Exit(1)
			}
			defer tarFile.Close()
			out = tarFile
		}
		tarWriter = tar.NewWriter(out)
		defer tarWriter.Close()
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
		} else if tarWriter != nil {
			// Write to tar archive
			// Apply rename rules to get final filename
			outputName, err := cfg.GetDecryptRename(relPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error computing rename for %s: %v\n", relPath, err)
				os.Exit(1)
			}

			// Include base directory name in tar path
			baseDir := filepath.Base(cfg.ConfigDir())
			tarPath := filepath.Join(baseDir, outputName)

			header := &tar.Header{
				Name:    tarPath,
				Size:    int64(len(output)),
				Mode:    0644,
				ModTime: time.Now(),
			}
			if err := tarWriter.WriteHeader(header); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing tar header for %s: %v\n", outputName, err)
				os.Exit(1)
			}
			if _, err := tarWriter.Write(output); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing tar content for %s: %v\n", outputName, err)
				os.Exit(1)
			}

			// Display progress (to stderr if tar goes to stdout)
			if decryptOutputTar == "-" {
				fmt.Fprintf(os.Stderr, "Decrypted: %s\n", tarPath)
			} else {
				fmt.Printf("Decrypted: %s\n", tarPath)
			}
		} else if modified {
			// Determine output file path
			outputFile := file
			originalFile := file
			if decryptOutputPath != "" {
				// Resolve output path (relative to config dir if not absolute)
				outDir := decryptOutputPath
				if !filepath.IsAbs(outDir) {
					outDir = filepath.Join(cfg.ConfigDir(), outDir)
				}
				outputFile = filepath.Join(outDir, relPath)

				// Apply rename rules to output path
				renamedOutput, err := cfg.GetDecryptRename(outputFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error computing rename for %s: %v\n", outputFile, err)
					os.Exit(1)
				}
				outputFile = renamedOutput

				// Create parent directories
				if err := os.MkdirAll(filepath.Dir(outputFile), 0755); err != nil {
					fmt.Fprintf(os.Stderr, "Error creating directory for %s: %v\n", outputFile, err)
					os.Exit(1)
				}
			} else {
				// In-place mode: compute renamed path
				renamedFile, err := cfg.GetDecryptRename(file)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error computing rename for %s: %v\n", relPath, err)
					os.Exit(1)
				}
				outputFile = renamedFile
			}

			if err := proc.WriteFile(outputFile, output); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", outputFile, err)
				os.Exit(1)
			}

			// If in-place mode and renamed, delete the original file
			if decryptOutputPath == "" && outputFile != originalFile {
				if err := os.Remove(originalFile); err != nil {
					fmt.Fprintf(os.Stderr, "Error removing original file %s: %v\n", relPath, err)
					os.Exit(1)
				}
			}

			// Only remove MAC if we're modifying in-place (no --output-path)
			if decryptOutputPath == "" {
				cfg.RemoveMAC(relPath)
				anyMACsRemoved = true
			}

			// Display output (include base directory for consistency)
			outputRelPath, _ := filepath.Rel(cfg.ConfigDir(), outputFile)
			if outputRelPath == "" {
				outputRelPath = outputFile
			}
			baseDir := filepath.Base(cfg.ConfigDir())
			displayPath := filepath.Join(baseDir, outputRelPath)
			if outputFile != originalFile && decryptOutputPath == "" {
				displayFrom := filepath.Join(baseDir, relPath)
				fmt.Printf("Decrypted: %s -> %s\n", displayFrom, displayPath)
			} else {
				fmt.Printf("Decrypted: %s\n", displayPath)
			}
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
	// Skip this check for non-destructive exports (--output-tar, --output-path)
	if !toStdout && decryptOutputTar == "" && decryptOutputPath == "" {
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
