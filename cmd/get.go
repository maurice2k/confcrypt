package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/doc"
	"github.com/maurice2k/confcrypt/internal/format"
	"github.com/maurice2k/confcrypt/internal/processor"
)

var (
	getJSON        bool
	getYAML        bool
	getDocIndex    int
	getForce       bool
	getAgeKeyFile  string
	getSSHKeyFile  string
	getYubiKeyFlag bool
	getFIDO2Flag   bool
)

var getCmd = &cobra.Command{
	Use:   "get <file> [path...]",
	Short: "Print a file or values of it, decrypted",
	Long: `Print a config file, or the values at paths inside it, decrypted.

Without a path (or with the path "."), the whole file is printed decrypted,
exactly as it is on disk otherwise: comments and formatting are kept. This
also works for full-file encrypted files such as keys and certificates.

Paths use dotted keys and bracketed list indices, e.g. db.password or
db.hosts[0].password; keys containing '.', '[' or '"' are double-quoted.
For env files the path is the variable name.

A scalar prints as its raw value. A map or list prints as a subtree in the
file's own format (JSON for JSON files, YAML otherwise); --json and --yaml
override that. Several paths print one value per line, or one object keyed
by path with --json.

Only the requested values are decrypted: if nothing under the path is
encrypted, no key is loaded and no hardware key is touched. The exit code
is 1 when a path does not exist.`,
	Args: cobra.MinimumNArgs(1),
	Run:  runGet,
}

func init() {
	getCmd.Flags().BoolVar(&getJSON, "json", false, "Output as JSON")
	getCmd.Flags().BoolVar(&getYAML, "yaml", false, "Output as YAML")
	getCmd.Flags().IntVar(&getDocIndex, "doc", -1, "Document index for multi-document YAML files (0-based; default: first, or the whole stream for the root path)")
	getCmd.Flags().BoolVar(&getForce, "force", false, "Continue even if MAC verification fails")
	getCmd.Flags().StringVar(&getAgeKeyFile, "age-key", "", "Path to age private key file (use without value to force age auto-detect)")
	getCmd.Flags().StringVar(&getSSHKeyFile, "ssh-key", "", "Path to SSH private key file (use without value to force SSH auto-detect)")
	getCmd.Flags().BoolVar(&getYubiKeyFlag, "yubikey-key", false, "Use YubiKey HMAC challenge-response")
	getCmd.Flags().BoolVar(&getFIDO2Flag, "fido2-key", false, "Use FIDO2 hmac-secret (requires CGO build)")
	getCmd.Flags().Lookup("age-key").NoOptDefVal = AutoDetectMarker
	getCmd.Flags().Lookup("ssh-key").NoOptDefVal = AutoDetectMarker
	rootCmd.AddCommand(getCmd)
}

func runGet(cmd *cobra.Command, args []string) {
	if filePath != "" {
		fmt.Fprintf(os.Stderr, "Error: cannot use both positional argument and --file flag\n")
		os.Exit(1)
	}
	if getJSON && getYAML {
		fmt.Fprintf(os.Stderr, "Error: cannot use both --json and --yaml\n")
		os.Exit(1)
	}

	cfgPath, singleFile, err := ResolveTarget(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if singleFile == "" {
		fmt.Fprintf(os.Stderr, "Error: get requires a file, not a folder\n")
		os.Exit(1)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// stdout carries the values, so status output goes to stderr
	printConfigInUse(cfg, true)

	loader := func() ([]age.Identity, error) {
		return LoadDecryptionIdentity(cfg, getAgeKeyFile, getSSHKeyFile, getYubiKeyFlag, getFIDO2Flag)
	}
	paths := args[1:]
	if len(paths) == 0 {
		paths = []string{"."}
	}
	out, err := performGet(cfg, singleFile, paths, getOptions{JSON: getJSON, YAML: getYAML, Doc: getDocIndex, Force: getForce}, loader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(out)
}

type getOptions struct {
	JSON  bool
	YAML  bool
	Doc   int // document index for multi-document YAML; negative means unspecified
	Force bool
}

// performGet resolves the paths in file, decrypts what they address, and
// renders the values. Identities are only loaded when an addressed value
// is encrypted. The root path ("." or no path) prints the decrypted file
// as it is on disk, which for full-file formats is the only valid path.
func performGet(cfg *config.Config, file string, paths []string, opts getOptions, identityLoader processor.IdentityLoader) ([]byte, error) {
	formatOverride, matches, err := cfg.MatchesFileWithFormat(file)
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
	fileFormat := processor.DetectFormat(file, formatOverride)

	content, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", file, err)
	}

	parsed := make([]doc.Path, len(paths))
	for i, p := range paths {
		parsed[i], err = doc.ParsePath(p)
		if err != nil {
			return nil, err
		}
	}

	proc, err := processor.NewProcessor(cfg, identityLoader)
	if err != nil {
		return nil, err
	}

	// setupDecryption loads identities and verifies the MAC, once
	decryptionReady := false
	setupDecryption := func() error {
		if decryptionReady {
			return nil
		}
		identities, err := identityLoader()
		if err != nil {
			return fmt.Errorf("loading identities: %w", err)
		}
		if _, err := proc.SetupDecryption(identities); err != nil {
			return err
		}
		if err := proc.VerifyMAC(file, content, formatOverride); err != nil {
			if !opts.Force {
				return fmt.Errorf("%s: %w (use --force to read anyway)", displayPath(file), err)
			}
			fmt.Fprintf(os.Stderr, "Warning: %s: %v (continuing due to --force)\n", displayPath(file), err)
		}
		decryptionReady = true
		return nil
	}

	// Full-file formats have no structure: only the root path is valid
	if fileFormat == processor.FormatFull {
		for _, p := range parsed {
			if len(p) > 0 {
				return nil, fmt.Errorf("%s is a full-file encrypted file and has no paths; use 'confcrypt get %s' for its content", displayPath(file), displayPath(file))
			}
		}
		if !proc.HasEncryptedValues(content, file, formatOverride) {
			return content, nil
		}
		if err := setupDecryption(); err != nil {
			return nil, err
		}
		out, _, err := proc.ProcessContent(content, file, false, fileFormat)
		if err != nil {
			return nil, fmt.Errorf("decrypting %s: %w", displayPath(file), err)
		}
		return out, nil
	}

	roots, err := processor.ParseRoots(content, fileFormat)
	if err != nil {
		return nil, err
	}
	docIndex := opts.Doc
	if docIndex < 0 {
		docIndex = 0
	}
	if docIndex >= len(roots) {
		return nil, fmt.Errorf("document index %d out of range: %s has %d document(s)", docIndex, displayPath(file), len(roots))
	}
	root := roots[docIndex]

	nodes := make([]doc.Node, len(paths))
	needDecrypt := false
	for i := range parsed {
		nodes[i], err = doc.Resolve(root, parsed[i])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", displayPath(file), err)
		}
		if processor.HasEncryptedNodes(nodes[i]) {
			needDecrypt = true
		}
	}

	if needDecrypt {
		if err := setupDecryption(); err != nil {
			return nil, err
		}
		for i, n := range nodes {
			if err := proc.DecryptSubtree(n, keyPathOf(parsed[i])); err != nil {
				return nil, fmt.Errorf("%s: %w", parsed[i].String(), err)
			}
		}
	}

	// The root in the file's own format is the decrypted file as it is on
	// disk (comments and formatting kept), unless a single document of a
	// multi-document stream was requested
	var wholeFile []byte
	if !opts.JSON && !opts.YAML && opts.Doc < 0 {
		for _, p := range parsed {
			if len(p) == 0 {
				wholeFile, _, err = proc.ProcessContent(content, file, false, fileFormat)
				if err != nil {
					return nil, fmt.Errorf("decrypting %s: %w", displayPath(file), err)
				}
				if len(wholeFile) > 0 && wholeFile[len(wholeFile)-1] != '\n' {
					wholeFile = append(wholeFile, '\n')
				}
				break
			}
		}
	}

	return renderGet(nodes, parsed, fileFormat, opts, wholeFile)
}

// keyPathOf returns the mapping keys of a path (indices skipped), the form
// the processor uses for value paths.
func keyPathOf(p doc.Path) []string {
	var keys []string
	for _, seg := range p {
		if !seg.IsIndex {
			keys = append(keys, seg.Key)
		}
	}
	return keys
}

func renderGet(nodes []doc.Node, paths []doc.Path, fileFormat processor.FileFormat, opts getOptions, wholeFile []byte) ([]byte, error) {
	var buf bytes.Buffer

	if len(nodes) > 1 && opts.JSON {
		buf.WriteString("{\n")
		for i, n := range nodes {
			if i > 0 {
				buf.WriteString(",\n")
			}
			buf.WriteString("  ")
			if err := writeJSONKey(&buf, paths[i].String()); err != nil {
				return nil, err
			}
			buf.WriteString(": ")
			out, err := doc.RenderJSONIndented(n, 1)
			if err != nil {
				return nil, err
			}
			buf.Write(out)
		}
		buf.WriteString("\n}\n")
		return buf.Bytes(), nil
	}

	for i, n := range nodes {
		if len(paths[i]) == 0 && wholeFile != nil {
			buf.Write(wholeFile)
			continue
		}
		out, err := renderGetValue(n, fileFormat, opts)
		if err != nil {
			return nil, err
		}
		buf.Write(out)
	}
	return buf.Bytes(), nil
}

func renderGetValue(n doc.Node, fileFormat processor.FileFormat, opts getOptions) ([]byte, error) {
	switch {
	case n.Kind() == doc.Scalar && !opts.JSON && !opts.YAML:
		return []byte(n.Value() + "\n"), nil
	case opts.JSON || (!opts.YAML && fileFormat == processor.FormatJSON):
		out, err := doc.RenderJSON(n)
		if err != nil {
			return nil, err
		}
		return append(out, '\n'), nil
	default:
		return doc.RenderYAML(n)
	}
}

func writeJSONKey(buf *bytes.Buffer, key string) error {
	out, err := doc.RenderJSON(doc.NewYAMLScalar(key, format.TypeString, ""))
	if err != nil {
		return err
	}
	buf.Write(out)
	return nil
}
