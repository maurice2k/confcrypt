package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/processor"
)

var (
	editForce       bool
	editAgeKeyFile  string
	editSSHKeyFile  string
	editYubiKeyFlag bool
	editFIDO2Flag   bool
	editEditor      string
)

var editCmd = &cobra.Command{
	Use:   "edit <file>",
	Short: "Edit a file with its values decrypted, re-encrypting on save",
	Long: `Decrypt a file into a private temporary copy, open it in your editor, and
write it back encrypted once the editor exits. Nothing is written if the
content did not change. Values you did not touch keep their exact ciphertext,
so the resulting diff only shows what you changed.

The editor is taken from --editor, $VISUAL or $EDITOR (default: vi). The
temporary copy lives in a directory only you can read and is removed when
the editor exits. The file must match a pattern in the 'files' list.`,
	Args: cobra.ExactArgs(1),
	Run:  runEdit,
}

func init() {
	editCmd.Flags().BoolVar(&editForce, "force", false, "Edit even if MAC verification fails")
	editCmd.Flags().StringVar(&editEditor, "editor", "", "Editor command (default: $VISUAL, $EDITOR, or vi)")
	editCmd.Flags().StringVar(&editAgeKeyFile, "age-key", "", "Path to age private key file (use without value to force age auto-detect)")
	editCmd.Flags().StringVar(&editSSHKeyFile, "ssh-key", "", "Path to SSH private key file (use without value to force SSH auto-detect)")
	editCmd.Flags().BoolVar(&editYubiKeyFlag, "yubikey-key", false, "Use YubiKey HMAC challenge-response")
	editCmd.Flags().BoolVar(&editFIDO2Flag, "fido2-key", false, "Use FIDO2 hmac-secret (requires CGO build)")
	editCmd.Flags().Lookup("age-key").NoOptDefVal = AutoDetectMarker
	editCmd.Flags().Lookup("ssh-key").NoOptDefVal = AutoDetectMarker
	rootCmd.AddCommand(editCmd)
}

func runEdit(cmd *cobra.Command, args []string) {
	if filePath != "" {
		fmt.Fprintf(os.Stderr, "Error: cannot use both positional argument and --file flag\n")
		os.Exit(1)
	}
	if toStdout {
		fmt.Fprintf(os.Stderr, "Error: --stdout cannot be used with edit\n")
		os.Exit(1)
	}

	cfgPath, singleFile, err := ResolveTarget(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if singleFile == "" {
		fmt.Fprintf(os.Stderr, "Error: edit requires a file, not a folder\n")
		os.Exit(1)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	printConfigInUse(cfg, false)

	identityLoader := func() ([]age.Identity, error) {
		return LoadDecryptionIdentity(cfg, editAgeKeyFile, editSSHKeyFile, editYubiKeyFlag, editFIDO2Flag)
	}

	res, err := performEdit(cfg, singleFile, identityLoader, resolveEditor(editEditor), editForce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if quiet >= 3 {
		return
	}
	if !res.changed {
		fmt.Println("No changes")
		return
	}
	if res.outputPath != res.originalPath {
		fmt.Printf("Encrypted: %s -> %s\n", displayPath(res.originalPath), displayPath(res.outputPath))
	} else {
		fmt.Printf("Encrypted: %s\n", displayPath(res.outputPath))
	}
}

// resolveEditor picks the editor command: explicit flag, then $VISUAL, then
// $EDITOR, then vi.
func resolveEditor(flag string) string {
	for _, candidate := range []string{flag, os.Getenv("VISUAL"), os.Getenv("EDITOR")} {
		if strings.TrimSpace(candidate) != "" {
			return candidate
		}
	}
	return "vi"
}

type editResult struct {
	changed      bool
	originalPath string
	outputPath   string
}

// performEdit runs the decrypt/edit/encrypt round-trip for one file.
// The editor command is split on whitespace and invoked with the temporary
// file path as its last argument. Nothing touches the working tree until
// the edited content has been encrypted and the key store persisted.
func performEdit(cfg *config.Config, file string, identityLoader processor.IdentityLoader, editor string, force bool) (*editResult, error) {
	format, matches, err := cfg.MatchesFileWithFormat(file)
	if err != nil {
		return nil, fmt.Errorf("checking file pattern: %w", err)
	}
	if !matches {
		relPath, _ := filepath.Rel(cfg.ConfigDir(), file)
		if relPath == "" || strings.HasPrefix(relPath, "..") {
			return nil, fmt.Errorf("file %s is outside config directory %s", file, cfg.ConfigDir())
		}
		return nil, fmt.Errorf("file %q does not match any pattern in files list; add it to the 'files' section in %s", relPath, cfg.ConfigPath())
	}

	content, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", file, err)
	}
	proc, err := processor.NewProcessor(cfg, identityLoader)
	if err != nil {
		return nil, err
	}
	// Remember decrypted values so untouched ones keep their ciphertext
	proc.EnableCiphertextReuse()

	hadSecrets := cfg.HasSecrets()
	wasEncrypted := proc.HasEncryptedValues(content, file, format)

	plaintext := content
	if wasEncrypted {
		identities, err := identityLoader()
		if err != nil {
			return nil, fmt.Errorf("loading identities: %w", err)
		}
		if err := proc.SetupEncryptionWithIdentities(identities); err != nil {
			return nil, err
		}

		if err := proc.VerifyMAC(file, content, format); err != nil {
			if !force {
				return nil, fmt.Errorf("%s: %w (use --force to edit anyway)", displayPath(file), err)
			}
			fmt.Fprintf(os.Stderr, "Warning: %s: %v (continuing due to --force)\n", displayPath(file), err)
		}

		plaintext, _, err = proc.ProcessContent(content, file, false, processor.DetectFormat(file, format))
		if err != nil {
			return nil, fmt.Errorf("decrypting %s: %w", displayPath(file), err)
		}
	}

	edited, err := runEditor(editor, cfg, file, plaintext)
	if err != nil {
		return nil, err
	}

	res := &editResult{originalPath: file, outputPath: file}
	if bytes.Equal(edited, plaintext) {
		return res, nil
	}
	res.changed = true

	output, modified, err := proc.ProcessContent(edited, file, true, processor.DetectFormat(file, format))
	if err != nil {
		return nil, fmt.Errorf("encrypting edited content: %w", err)
	}

	// A file that was plaintext before gets the encrypt rename, like
	// `confcrypt encrypt` would do; an already-encrypted file keeps its name
	if modified && !wasEncrypted {
		renamed, err := cfg.GetEncryptRename(file)
		if err != nil {
			return nil, fmt.Errorf("computing rename: %w", err)
		}
		res.outputPath = renamed
	}

	stages := []stagedWrite{{
		originalPath: file,
		outputPath:   res.outputPath,
		content:      output,
		format:       format,
	}}

	relPath, _ := filepath.Rel(cfg.ConfigDir(), file)
	if proc.HasEncryptedValues(output, res.outputPath, format) {
		if err := stageMACs(proc, stages); err != nil {
			return nil, err
		}
	} else if relPath != "" {
		cfg.RemoveMAC(relPath)
	}
	if res.outputPath != file && relPath != "" {
		cfg.RemoveMAC(relPath)
	}

	// Persist the key store (and MACs) before writing the file, so no
	// ciphertext ever reaches disk under a key that exists only in memory
	if !hadSecrets && modified {
		err = proc.SaveEncryptedSecrets()
	} else {
		err = cfg.Save()
	}
	if err != nil {
		return nil, fmt.Errorf("saving config: %w", err)
	}

	if err := writeStagedFiles(proc, stages, nil); err != nil {
		return nil, err
	}

	return res, nil
}

// runEditor writes plaintext to a private temporary file, runs the editor
// on it, and returns the edited content. The temporary directory is created
// with mode 0700 and removed afterwards. SIGINT is ignored while the editor
// runs so a Ctrl-C inside the editor does not kill confcrypt and leave the
// plaintext copy behind.
func runEditor(editor string, cfg *config.Config, file string, plaintext []byte) ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "confcrypt-edit-")
	if err != nil {
		return nil, fmt.Errorf("creating temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Use the decrypted filename so editors pick the right syntax mode
	tmpName := filepath.Base(file)
	if renamed, err := cfg.GetDecryptRename(file); err == nil {
		tmpName = filepath.Base(renamed)
	}
	tmpFile := filepath.Join(tmpDir, tmpName)
	if err := os.WriteFile(tmpFile, plaintext, 0600); err != nil {
		return nil, fmt.Errorf("writing temporary file: %w", err)
	}

	parts := strings.Fields(editor)
	if len(parts) == 0 {
		return nil, errors.New("no editor configured; set $EDITOR or pass --editor")
	}
	args := append(parts[1:], tmpFile)
	cmd := exec.Command(parts[0], args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	signal.Ignore(os.Interrupt)
	runErr := cmd.Run()
	signal.Reset(os.Interrupt)
	if runErr != nil {
		return nil, fmt.Errorf("editor %q failed: %w", parts[0], runErr)
	}

	edited, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("reading edited file: %w", err)
	}
	return edited, nil
}
