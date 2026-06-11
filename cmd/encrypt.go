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
	Use:   "encrypt [file|folder]",
	Short: "Encrypt matching keys (default command)",
	Long: `Encrypt values for keys matching the configured patterns.

If a file is specified, searches upward from the file's directory to find .confcrypt.yml
and encrypts only that file. The file must match a pattern in the 'files' list.

If a folder is specified, it must contain .confcrypt.yml directly and all matching
files in that folder are encrypted.

If no argument is given, searches from current directory upward for .confcrypt.yml.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runEncrypt,
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be encrypted without making changes")
	encryptCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output encrypted fields in JSON format")
}

func runEncrypt(cmd *cobra.Command, args []string) {
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

	printConfigInUse(cfg, jsonOutput || toStdout)

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
		// Check if file matches existing patterns and get format
		format, matches, err := cfg.MatchesFileWithFormat(singleFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking file pattern: %v\n", err)
			os.Exit(1)
		}
		if !matches {
			relPath, _ := filepath.Rel(cfg.ConfigDir(), singleFile)
			if relPath == "" || strings.HasPrefix(relPath, "..") {
				fmt.Fprintf(os.Stderr, "Error: file %s is outside config directory %s\n", singleFile, cfg.ConfigDir())
			} else {
				fmt.Fprintf(os.Stderr, "Error: file %q does not match any pattern in files list\n", relPath)
				fmt.Fprintf(os.Stderr, "Add it to the 'files' section in %s\n", cfg.ConfigPath())
			}
			os.Exit(1)
		}
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
		if jsonOutput {
			fmt.Println(`{"files":{}}`)
		} else {
			fmt.Fprintf(os.Stderr, "No files to process\n")
		}
		os.Exit(0)
	}

	// Handle dry-run mode (preview only, no changes)
	if dryRun {
		runEncryptDryRun(proc, cfg, files, fileFormats)
		return
	}

	// Collect what will be encrypted (for JSON output). Keyed by path relative to
	// the config dir (same key space as --dry-run --json); renames hold the
	// would-be output path for files that get renamed on encrypt.
	var encryptedFields map[string][]string
	var renames map[string]string
	if jsonOutput {
		encryptedFields = make(map[string][]string)
		renames = make(map[string]string)
	}

	// Check if secrets already exist (we'll reuse the key, no need to re-save secrets)
	hadSecrets := cfg.HasSecrets()

	// Recipients added by hand-editing .confcrypt.yml are wrapped with the
	// existing AES key and appended to the store (see store sync below).
	missingRecipients := missingStoreRecipients(cfg)
	willSyncStore := hadSecrets && len(missingRecipients) > 0 && !toStdout

	// Stage all outputs in memory first; nothing is written to disk until
	// every file processed successfully and the key store is persisted
	var stages []stagedWrite
	anyModified := false
	for _, file := range files {
		relPath := configRelPath(cfg, file)

		if jsonOutput {
			unencrypted, err := proc.CheckFile(file, fileFormats[file])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error checking %s: %v\n", relPath, err)
				os.Exit(1)
			}
			if len(unencrypted) > 0 {
				encryptedFields[relPath] = fieldNames(unencrypted)
				if renamed, rerr := cfg.GetEncryptRename(file); rerr == nil && renamed != file {
					renames[relPath] = configRelPath(cfg, renamed)
				}
			}
		}

		output, modified, err := proc.ProcessFile(file, true, fileFormats[file])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", relPath, err)
			os.Exit(1)
		}

		if !modified {
			continue
		}
		anyModified = true

		if toStdout {
			fmt.Printf("--- %s ---\n", relPath)
			fmt.Print(string(output))
			fmt.Println()
			continue
		}

		// Compute renamed path
		renamedFile, err := cfg.GetEncryptRename(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error computing rename for %s: %v\n", relPath, err)
			os.Exit(1)
		}

		stages = append(stages, stagedWrite{
			originalPath: file,
			outputPath:   renamedFile,
			content:      output,
			format:       fileFormats[file],
		})
	}

	if !anyModified && !jsonOutput && !willSyncStore {
		fmt.Println("No values to encrypt")
	}

	if !toStdout {
		// Sync the store: wrap the existing AES key for recipients that were
		// added to the config by hand. ensureEncryptionSetup (inside) reuses
		// the setup already done by the encrypt loop, so this never triggers a
		// second hardware-key prompt.
		var addedRecipients []string
		if willSyncStore {
			addedRecipients, err = proc.AddMissingStoreRecipients()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error updating recipient store: %v\n", err)
				os.Exit(1)
			}
		}

		// Stage MACs for the new outputs and drop MACs of files that will no
		// longer exist after the staged renames
		if err := stageMACs(proc, stages); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		macsRemoved := cleanupStaleMACs(cfg, stages)

		if len(stages) > 0 {
			// Persist the key store (and MACs) BEFORE writing any file:
			// a fresh AES key must never exist only in memory while files
			// encrypted with it are already on disk
			if hadSecrets {
				err = cfg.Save()
			} else {
				err = proc.SaveEncryptedSecrets()
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
				os.Exit(1)
			}

			if err := writeStagedFiles(proc, stages, func(s stagedWrite) {
				if jsonOutput {
					return
				}
				if s.outputPath != s.originalPath {
					fmt.Printf("Encrypted: %s -> %s\n", displayPath(s.originalPath), displayPath(s.outputPath))
				} else {
					fmt.Printf("Encrypted: %s\n", displayPath(s.originalPath))
				}
			}); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		} else if macsRemoved || len(addedRecipients) > 0 {
			if err := cfg.Save(); err != nil {
				fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
				os.Exit(1)
			}
		}

		// Report newly granted recipients (stderr in --json mode to keep stdout clean)
		recipientOut := os.Stdout
		if jsonOutput {
			recipientOut = os.Stderr
		}
		for _, pub := range addedRecipients {
			fmt.Fprintf(recipientOut, "Granted access to new recipient: %s\n", recipientLabel(cfg, pub))
		}
		warnStaleStoreEntries(cfg)
	}

	// Output JSON if requested
	if jsonOutput {
		printEncryptJSON(encryptedFields, renames)
	}
}

// runEncryptDryRun handles --dry-run and --json output modes.
// JSON output uses the same key space as the live --json run: keys are paths
// relative to the config dir (original, not renamed), with renames reported
// separately.
func runEncryptDryRun(proc *processor.Processor, cfg *config.Config, files []string, fileFormats map[string]string) {
	result := make(map[string][]string)  // relOriginal -> fields
	renames := make(map[string]string)   // relOriginal -> relRenamed
	origPaths := make(map[string]string) // relOriginal -> absolute original (for display)

	for _, file := range files {
		unencrypted, err := proc.CheckFile(file, fileFormats[file])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking %s: %v\n", configRelPath(cfg, file), err)
			os.Exit(1)
		}

		if len(unencrypted) > 0 {
			rel := configRelPath(cfg, file)
			result[rel] = fieldNames(unencrypted)
			origPaths[rel] = file

			renamedFile, err := cfg.GetEncryptRename(file)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error computing rename for %s: %v\n", rel, err)
				os.Exit(1)
			}
			if renamedFile != file {
				renames[rel] = configRelPath(cfg, renamedFile)
			}
		}
	}

	if jsonOutput {
		printEncryptJSON(result, renames)
		return
	}

	// Human-readable dry-run output
	if len(result) == 0 {
		fmt.Println("No values to encrypt")
		return
	}

	fmt.Println("Would encrypt:")
	for rel, fields := range result {
		if renamed, ok := renames[rel]; ok {
			fmt.Printf("  %s -> %s:\n", displayPath(origPaths[rel]), displayPath(filepath.Join(cfg.ConfigDir(), renamed)))
		} else {
			fmt.Printf("  %s:\n", displayPath(origPaths[rel]))
		}

		for _, field := range fields {
			fmt.Printf("    - %s\n", field)
		}
	}
}

// configRelPath returns path relative to the config directory (a stable JSON
// key independent of the caller's cwd), falling back to the input path.
func configRelPath(cfg *config.Config, path string) string {
	rel, err := filepath.Rel(cfg.ConfigDir(), path)
	if err != nil || rel == "" {
		return path
	}
	return rel
}

// fieldNames flattens matcher results into dotted field names.
func fieldNames(results []processor.MatchResult) []string {
	fields := make([]string, 0, len(results))
	for _, r := range results {
		name := strings.Join(r.Path, ".")
		if name == "" {
			name = r.KeyName
		}
		fields = append(fields, name)
	}
	return fields
}

// printEncryptJSON writes the shared encrypt/dry-run JSON shape to stdout.
func printEncryptJSON(files map[string][]string, renames map[string]string) {
	output := struct {
		Files   map[string][]string `json:"files"`
		Renames map[string]string   `json:"renames,omitempty"`
	}{
		Files:   files,
		Renames: renames,
	}
	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(jsonBytes))
}
