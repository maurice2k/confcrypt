package cmd

import (
	"archive/tar"
	"bytes"
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
	forceDecrypt        bool
	decryptAgeKeyFile   string
	decryptSSHKeyFile   string
	decryptYubiKeyFlag  bool
	decryptFIDO2Flag    bool
	decryptOutputPath   string
	decryptOutputTar    string
	decryptClearSecrets bool
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
	decryptCmd.Flags().StringVar(&decryptOutputPath, "output-path", "", "Write decrypted files to this directory (relative to current working directory if not absolute)")
	decryptCmd.Flags().StringVar(&decryptOutputTar, "output-tar", "", "Write decrypted files to tar archive (use '-' for stdout)")
	decryptCmd.Flags().BoolVar(&decryptClearSecrets, "clear-secrets", false, "Clear encrypted AES key store after all in-place encrypted values are removed")
	// Allow --age-key and --ssh-key without a value (sets to "auto")
	decryptCmd.Flags().Lookup("age-key").NoOptDefVal = AutoDetectMarker
	decryptCmd.Flags().Lookup("ssh-key").NoOptDefVal = AutoDetectMarker
	rootCmd.AddCommand(decryptCmd)
}

func runDecrypt(cmd *cobra.Command, args []string) {
	// Check mutually exclusive flags
	if err := validateDecryptOptions(toStdout, decryptOutputPath, decryptOutputTar, decryptClearSecrets); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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

	printConfigInUse(cfg, toStdout || decryptOutputTar == "-")

	// Create processor
	proc, err := processor.NewProcessor(cfg, func() ([]age.Identity, error) {
		return LoadDecryptionIdentity(cfg, "", "", false, false)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Get files to process (with format information)
	var filesWithFormat []FileWithFormat
	if singleFile != "" {
		// Get format from config if the file matches a pattern
		format, _, _ := cfg.MatchesFileWithFormat(singleFile)
		filesWithFormat = []FileWithFormat{{Path: singleFile, Format: format}}
	} else {
		filesWithFormat, err = GetFilesToProcessWithFormat(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	// Extract file paths for backwards compatibility
	files := make([]string, len(filesWithFormat))
	fileFormats := make(map[string]string)
	for i, f := range filesWithFormat {
		files[i] = f.Path
		fileFormats[f.Path] = f.Format
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
		if proc.HasEncryptedValues(content, file, fileFormats[file]) {
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
		if proc.HasEncryptedValues(content, file, fileFormats[file]) {
			if err := proc.VerifyMAC(file, content, fileFormats[file]); err != nil {
				if forceDecrypt {
					fmt.Fprintf(os.Stderr, "Warning: %s: %v (continuing due to --force)\n", relPath, err)
				} else {
					fmt.Fprintf(os.Stderr, "Error: %s: %v\n", relPath, err)
					fmt.Fprintf(os.Stderr, "Use --force to decrypt anyway\n")
					os.Exit(1)
				}
			}
		}

		output, modified, err := proc.ProcessFile(file, false, fileFormats[file])
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
					cwd, err := os.Getwd()
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error getting current directory: %v\n", err)
						os.Exit(1)
					}
					outDir = filepath.Join(cwd, outDir)
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

			// Display output relative to the current working directory
			if outputFile != originalFile && decryptOutputPath == "" {
				fmt.Printf("Decrypted: %s -> %s\n", displayPath(originalFile), displayPath(outputFile))
			} else {
				fmt.Printf("Decrypted: %s\n", displayPath(outputFile))
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

	// Check if all files are now fully decrypted. By default the secret store is
	// retained as recovery metadata; --clear-secrets removes it only after strict
	// validation confirms no encrypted values remain.
	if !toStdout && decryptOutputTar == "" && decryptOutputPath == "" {
		message, err := finishSecretStoreAfterInPlaceDecrypt(cfg, proc, decryptClearSecrets)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if message != "" {
			fmt.Println(message)
		}
	}
}

func validateDecryptOptions(stdout bool, outputPath, outputTar string, clearSecrets bool) error {
	if outputTar != "" && outputPath != "" {
		return fmt.Errorf("cannot use both --output-tar and --output-path")
	}
	if outputTar != "" && stdout {
		return fmt.Errorf("cannot use both --output-tar and --stdout")
	}
	if clearSecrets && stdout {
		return fmt.Errorf("cannot use --clear-secrets with --stdout")
	}
	if clearSecrets && outputPath != "" {
		return fmt.Errorf("cannot use --clear-secrets with --output-path")
	}
	if clearSecrets && outputTar != "" {
		return fmt.Errorf("cannot use --clear-secrets with --output-tar")
	}
	return nil
}

func finishSecretStoreAfterInPlaceDecrypt(cfg *config.Config, proc *processor.Processor, clearSecrets bool) (string, error) {
	if !cfg.HasSecrets() {
		return "", nil
	}

	hasAnyEncrypted, err := encryptedContentRemains(cfg, proc)
	if err != nil {
		if clearSecrets {
			return "", fmt.Errorf("cannot clear secret store: %w", err)
		}
		return "", nil
	}

	if hasAnyEncrypted {
		if clearSecrets {
			return "", fmt.Errorf("cannot clear secret store: encrypted values remain")
		}
		return "", nil
	}

	if !clearSecrets {
		return "All values decrypted; secret store retained for recovery. Use --clear-secrets to remove it.", nil
	}

	cfg.ClearSecrets()
	if err := cfg.Save(); err != nil {
		return "", fmt.Errorf("saving config: %w", err)
	}

	return "All values decrypted, secret store cleared (new key will be generated on next encrypt)", nil
}

func encryptedContentRemains(cfg *config.Config, proc *processor.Processor) (bool, error) {
	allFilesWithFormat, err := cfg.GetMatchingFilesWithFormat()
	if err != nil {
		return false, err
	}

	for _, f := range allFilesWithFormat {
		content, err := os.ReadFile(f.Path)
		if err != nil {
			return false, fmt.Errorf("reading %s: %w", displayConfigRelativePath(cfg, f.Path), err)
		}

		if hasRawEncryptedMarker(content) {
			return true, nil
		}

		hasEncrypted, err := proc.HasEncryptedValuesStrict(content, f.Path, f.Format)
		if err != nil {
			return false, fmt.Errorf("checking %s: %w", displayConfigRelativePath(cfg, f.Path), err)
		}
		if hasEncrypted {
			return true, nil
		}
	}

	return false, nil
}

func hasRawEncryptedMarker(content []byte) bool {
	return bytes.Contains(content, []byte("ENC[AES256_GCM,")) ||
		bytes.Contains(content, []byte("$CONFCRYPT_ENCRYPTED;"))
}

func displayConfigRelativePath(cfg *config.Config, path string) string {
	relPath, err := filepath.Rel(cfg.ConfigDir(), path)
	if err == nil && relPath != "" {
		return relPath
	}
	return path
}
