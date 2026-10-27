package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/doc"
	"github.com/maurice2k/confcrypt/internal/format"
	"github.com/maurice2k/confcrypt/internal/processor"
)

var (
	setValue       string
	setFromFile    string
	setType        string
	setDelete      bool
	setDocIndex    int
	setDryRun      bool
	setForce       bool
	setAgeKeyFile  string
	setSSHKeyFile  string
	setYubiKeyFlag bool
	setFIDO2Flag   bool
)

var setCmd = &cobra.Command{
	Use:   "set <file> <path>",
	Short: "Set one value in a file, encrypting it if its key matches the rules",
	Long: `Set the value at a path inside a config file and write the file back.

The value is read from stdin by default (a single trailing newline is
dropped), so secrets stay out of shell history; on a terminal it is asked
for without echo. --value and --from-file are alternatives.

If the key matches the configured key rules the value is stored encrypted,
otherwise in plaintext, exactly like 'confcrypt encrypt' decides. Values
are strings unless --type says otherwise; nothing is inferred.

Paths are the same as for 'get': dotted keys with [n] list indices and
double-quoted keys for names containing '.', '[' or '"'. Missing map keys
are created; [+] appends to a list. For env files the path is the variable
name. With a full-file encrypted file, the path "." replaces its content.

All other values keep their exact bytes, so the resulting diff is one line.
Setting a value that is already there changes nothing. --delete (or the
'unset' command) removes the key or list item instead.`,
	Args: cobra.ExactArgs(2),
	Run:  runSet,
}

var unsetCmd = &cobra.Command{
	Use:   "unset <file> <path>",
	Short: "Remove one key or list item from a file",
	Long:  `Remove the key or list item at a path inside a config file. Same as 'set --delete'.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		setDelete = true
		runSet(cmd, args)
	},
}

func init() {
	for _, c := range []*cobra.Command{setCmd, unsetCmd} {
		c.Flags().IntVar(&setDocIndex, "doc", 0, "Document index for multi-document YAML files (0-based)")
		c.Flags().BoolVar(&setDryRun, "dry-run", false, "Print the resulting file to stdout instead of writing it")
		c.Flags().BoolVar(&setForce, "force", false, "Continue even if MAC verification fails")
		c.Flags().StringVar(&setAgeKeyFile, "age-key", "", "Path to age private key file (use without value to force age auto-detect)")
		c.Flags().StringVar(&setSSHKeyFile, "ssh-key", "", "Path to SSH private key file (use without value to force SSH auto-detect)")
		c.Flags().BoolVar(&setYubiKeyFlag, "yubikey-key", false, "Use YubiKey HMAC challenge-response")
		c.Flags().BoolVar(&setFIDO2Flag, "fido2-key", false, "Use FIDO2 hmac-secret (requires CGO build)")
		c.Flags().Lookup("age-key").NoOptDefVal = AutoDetectMarker
		c.Flags().Lookup("ssh-key").NoOptDefVal = AutoDetectMarker
	}
	setCmd.Flags().StringVar(&setValue, "value", "", "The value (default: read from stdin)")
	setCmd.Flags().StringVar(&setFromFile, "from-file", "", "Read the value from this file, verbatim")
	setCmd.Flags().StringVar(&setType, "type", "string", "Value type: string, int, float, bool or null")
	setCmd.Flags().BoolVar(&setDelete, "delete", false, "Remove the key or list item instead of setting it")
	rootCmd.AddCommand(setCmd)
	rootCmd.AddCommand(unsetCmd)
}

func runSet(cmd *cobra.Command, args []string) {
	if filePath != "" {
		fmt.Fprintf(os.Stderr, "Error: cannot use both positional argument and --file flag\n")
		os.Exit(1)
	}
	if toStdout {
		fmt.Fprintf(os.Stderr, "Error: --stdout cannot be used with set; use --dry-run\n")
		os.Exit(1)
	}

	cfgPath, singleFile, err := ResolveTarget(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if singleFile == "" {
		fmt.Fprintf(os.Stderr, "Error: set requires a file, not a folder\n")
		os.Exit(1)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	printConfigInUse(cfg, setDryRun)

	opts := setOptions{Delete: setDelete, Doc: setDocIndex, DryRun: setDryRun, Force: setForce}
	var value string
	if !setDelete {
		opts.Type, err = parseValueType(setType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		value, err = readSetValue(cmd, args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	loader := func() ([]age.Identity, error) {
		return LoadDecryptionIdentity(cfg, setAgeKeyFile, setSSHKeyFile, setYubiKeyFlag, setFIDO2Flag)
	}
	res, err := performSet(cfg, singleFile, args[1], value, opts, loader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if opts.DryRun {
		os.Stdout.Write(res.output)
		return
	}
	if quiet >= 1 {
		return
	}
	switch {
	case !res.changed:
		fmt.Println("No change")
	case opts.Delete:
		fmt.Printf("Deleted %s from %s\n", args[1], displayPath(res.outputPath))
	case res.outputPath != res.originalPath:
		fmt.Printf("Set %s, encrypted: %s -> %s\n", args[1], displayPath(res.originalPath), displayPath(res.outputPath))
	case res.encrypted:
		fmt.Printf("Set %s in %s (encrypted)\n", args[1], displayPath(res.outputPath))
	default:
		fmt.Printf("Set %s in %s\n", args[1], displayPath(res.outputPath))
	}
}

// readSetValue picks the value source: --value, --from-file, a hidden
// terminal prompt, or stdin with one trailing newline dropped.
func readSetValue(cmd *cobra.Command, path string) (string, error) {
	if cmd.Flags().Changed("value") {
		return setValue, nil
	}
	if setFromFile != "" {
		data, err := os.ReadFile(setFromFile)
		if err != nil {
			return "", fmt.Errorf("reading value file: %w", err)
		}
		return string(data), nil
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "Value for %s: ", path)
		v, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("reading value: %w", err)
		}
		return string(v), nil
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("reading value from stdin: %w", err)
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r"), nil
}

func parseValueType(s string) (format.ValueType, error) {
	switch strings.ToLower(s) {
	case "", "string", "str":
		return format.TypeString, nil
	case "int", "integer":
		return format.TypeInt, nil
	case "float", "number":
		return format.TypeFloat, nil
	case "bool", "boolean":
		return format.TypeBool, nil
	case "null":
		return format.TypeNull, nil
	default:
		return "", fmt.Errorf("unknown --type %q (string, int, float, bool, null)", s)
	}
}

// validateTypedValue checks that value is a valid literal for typ and
// returns it normalized.
func validateTypedValue(value string, typ format.ValueType) (string, error) {
	switch typ {
	case format.TypeInt:
		v := strings.TrimSpace(value)
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			if !isDigits(v) {
				return "", fmt.Errorf("%q is not an integer", value)
			}
		}
		return v, nil
	case format.TypeFloat:
		v := strings.TrimSpace(value)
		if _, err := strconv.ParseFloat(v, 64); err != nil {
			return "", fmt.Errorf("%q is not a number", value)
		}
		return v, nil
	case format.TypeBool:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "true":
			return "true", nil
		case "false":
			return "false", nil
		default:
			return "", fmt.Errorf("%q is not a boolean (true or false)", value)
		}
	case format.TypeNull:
		if v := strings.TrimSpace(value); v != "" && v != "null" {
			return "", fmt.Errorf("--type null takes no value, got %q", value)
		}
		return "", nil
	default:
		return value, nil
	}
}

func isDigits(s string) bool {
	s = strings.TrimPrefix(s, "-")
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

type setOptions struct {
	Delete bool
	Type   format.ValueType
	Doc    int
	DryRun bool
	Force  bool
}

type setResult struct {
	changed      bool
	encrypted    bool // the value was stored encrypted
	originalPath string
	outputPath   string
	output       []byte // the resulting file content (dry run)
}

// performSet applies one change to file and writes it back (unless DryRun).
// The AES key is only loaded when the change touches encrypted values:
// setting a matching key, or deleting an encrypted one.
func performSet(cfg *config.Config, file, pathStr, value string, opts setOptions, identityLoader processor.IdentityLoader) (*setResult, error) {
	formatOverride, err := requireMatchingFile(cfg, file)
	if err != nil {
		return nil, err
	}
	fileFormat := processor.DetectFormat(file, formatOverride)

	content, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", file, err)
	}
	path, err := doc.ParsePath(pathStr)
	if err != nil {
		return nil, err
	}
	if opts.Type == "" {
		opts.Type = format.TypeString
	}
	if !opts.Delete {
		value, err = validateTypedValue(value, opts.Type)
		if err != nil {
			return nil, err
		}
	}

	proc, err := processor.NewProcessor(cfg, identityLoader)
	if err != nil {
		return nil, err
	}
	hadSecrets := cfg.HasSecrets()
	wasEncrypted := proc.HasEncryptedValues(content, file, formatOverride)
	res := &setResult{originalPath: file, outputPath: file}

	// ensureKey sets up the AES key (loading identities or generating a
	// fresh key for a repository without secrets) and verifies the MAC once
	keyReady := false
	ensureKey := func() error {
		if keyReady {
			return nil
		}
		if err := proc.SetupEncryption(); err != nil {
			return err
		}
		if wasEncrypted {
			if err := proc.VerifyMAC(file, content, formatOverride); err != nil {
				if !opts.Force {
					return fmt.Errorf("%s: %w (use --force to change anyway)", displayPath(file), err)
				}
				fmt.Fprintf(os.Stderr, "Warning: %s: %v (continuing due to --force)\n", displayPath(file), err)
			}
		}
		keyReady = true
		return nil
	}

	if fileFormat == processor.FormatFull {
		return performSetFullFile(cfg, proc, file, formatOverride, content, path, value, opts, wasEncrypted, hadSecrets, ensureKey, res)
	}
	if len(path) == 0 {
		return nil, fmt.Errorf("set needs a path inside %s; use 'confcrypt edit' to change the whole file", displayPath(file))
	}

	document, err := processor.ParseDocument(content, fileFormat)
	if err != nil {
		return nil, err
	}
	roots := document.Roots()
	if opts.Doc < 0 || opts.Doc >= len(roots) {
		return nil, fmt.Errorf("document index %d out of range: %s has %d document(s)", opts.Doc, displayPath(file), len(roots))
	}
	root := roots[opts.Doc]

	var touchedEncrypted bool
	if opts.Delete {
		touchedEncrypted, err = deleteAtPath(root, path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", displayPath(file), err)
		}
		if touchedEncrypted {
			if err := ensureKey(); err != nil {
				return nil, err
			}
		}
	} else {
		parent, err := ensureParent(document, root, path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", displayPath(file), err)
		}
		last := path[len(path)-1]
		keyPath := keyPathOf(path)
		matched := len(keyPath) > 0 && proc.ShouldEncrypt(keyPath[len(keyPath)-1], keyPath)

		// Nothing to do when the value is already there (an encrypted value
		// is decrypted in place for the comparison; it is replaced anyway
		// if it differs)
		if existing := existingAt(parent, last); existing != nil && existing.Kind() == doc.Scalar {
			if format.IsEncrypted(existing.Value()) {
				if err := ensureKey(); err != nil {
					return nil, err
				}
				if err := proc.DecryptSubtree(existing, keyPath); err != nil {
					return nil, fmt.Errorf("%s: %w", pathStr, err)
				}
			}
			if existing.Value() == value && existing.Type() == opts.Type {
				return res, nil
			}
		}

		placed, err := placeValue(parent, last, document.NewScalar(value, opts.Type))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", displayPath(file), err)
		}
		if matched {
			if err := ensureKey(); err != nil {
				return nil, err
			}
			if err := proc.EncryptScalar(placed, keyPath); err != nil {
				return nil, fmt.Errorf("encrypting %s: %w", pathStr, err)
			}
			touchedEncrypted = true
			res.encrypted = true
		}
	}

	output, err := document.Marshal()
	if err != nil {
		return nil, fmt.Errorf("rendering %s: %w", displayPath(file), err)
	}
	res.changed = true
	res.output = output
	if opts.DryRun {
		return res, nil
	}

	res.outputPath, err = commitOutput(cfg, proc, file, formatOverride, output, res.encrypted, wasEncrypted, hadSecrets, touchedEncrypted)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// performSetFullFile replaces the content of a full-file encrypted file.
func performSetFullFile(cfg *config.Config, proc *processor.Processor, file, formatOverride string, content []byte, path doc.Path, value string, opts setOptions, wasEncrypted, hadSecrets bool, ensureKey func() error, res *setResult) (*setResult, error) {
	if len(path) > 0 {
		return nil, fmt.Errorf("%s is a full-file encrypted file and has no paths; use the path . to replace its content", displayPath(file))
	}
	if opts.Delete {
		return nil, fmt.Errorf("cannot delete the content of %s; remove the file instead", displayPath(file))
	}
	if err := ensureKey(); err != nil {
		return nil, err
	}
	if wasEncrypted {
		plaintext, _, err := proc.ProcessContent(content, file, false, processor.FormatFull)
		if err != nil {
			return nil, fmt.Errorf("decrypting %s: %w", displayPath(file), err)
		}
		if bytes.Equal(plaintext, []byte(value)) {
			return res, nil
		}
	} else if bytes.Equal(content, []byte(value)) {
		return res, nil
	}
	output, _, err := proc.ProcessContent([]byte(value), file, true, processor.FormatFull)
	if err != nil {
		return nil, fmt.Errorf("encrypting %s: %w", displayPath(file), err)
	}
	res.changed = true
	res.encrypted = true
	res.output = output
	if opts.DryRun {
		return res, nil
	}
	res.outputPath, err = commitOutput(cfg, proc, file, formatOverride, output, true, wasEncrypted, hadSecrets, true)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// ensureParent walks path up to (not including) its last segment, creating
// missing mappings and appending to lists for [+], and returns the parent.
func ensureParent(document *processor.Document, root doc.Node, path doc.Path) (doc.Node, error) {
	cur := root.Target()
	for i, seg := range path[:len(path)-1] {
		where := "the document root"
		if i > 0 {
			where = path[:i].String()
		}
		next := path[i+1]
		newContainer := func() (doc.Node, error) {
			if next.IsIndex {
				return document.NewSequence()
			}
			return document.NewMapping()
		}
		switch {
		case seg.Append:
			if cur.Kind() != doc.Sequence {
				return nil, fmt.Errorf("%s is not a list, cannot append with [+]", where)
			}
			n, err := newContainer()
			if err != nil {
				return nil, err
			}
			if err := cur.Append(n); err != nil {
				return nil, err
			}
			cur = cur.Item(cur.Len() - 1).Target()
		case seg.IsIndex:
			if cur.Kind() != doc.Sequence {
				return nil, fmt.Errorf("%s is not a list, cannot index it with [%d]", where, seg.Index)
			}
			if seg.Index >= cur.Len() {
				return nil, fmt.Errorf("%s has %d item(s), index %d is out of range", where, cur.Len(), seg.Index)
			}
			cur = cur.Item(seg.Index).Target()
		default:
			if cur.Kind() != doc.Mapping {
				return nil, fmt.Errorf("%s is not a mapping, cannot look up key %q", where, seg.Key)
			}
			child, ok := cur.Get(seg.Key)
			if !ok {
				n, err := newContainer()
				if err != nil {
					return nil, err
				}
				if err := cur.Set(seg.Key, n); err != nil {
					return nil, err
				}
				child, _ = cur.Get(seg.Key)
			}
			cur = child.Target()
		}
	}
	return cur, nil
}

// existingAt returns the node addressed by seg in parent, or nil.
func existingAt(parent doc.Node, seg doc.Segment) doc.Node {
	switch {
	case seg.Append:
		return nil
	case seg.IsIndex:
		if parent.Kind() != doc.Sequence || seg.Index >= parent.Len() {
			return nil
		}
		return parent.Item(seg.Index).Target()
	default:
		if parent.Kind() != doc.Mapping {
			return nil
		}
		if n, ok := parent.Get(seg.Key); ok {
			return n.Target()
		}
		return nil
	}
}

// placeValue stores value under seg in parent and returns the node now
// held there (formats may copy the value into their own representation).
func placeValue(parent doc.Node, seg doc.Segment, value doc.Node) (doc.Node, error) {
	switch {
	case seg.Append:
		if parent.Kind() != doc.Sequence {
			return nil, fmt.Errorf("cannot append with [+]: not a list")
		}
		if err := parent.Append(value); err != nil {
			return nil, err
		}
		return parent.Item(parent.Len() - 1), nil
	case seg.IsIndex:
		if parent.Kind() != doc.Sequence {
			return nil, fmt.Errorf("cannot set [%d]: not a list", seg.Index)
		}
		if seg.Index >= parent.Len() {
			return nil, fmt.Errorf("list has %d item(s), index %d is out of range (use [+] to append)", parent.Len(), seg.Index)
		}
		if err := parent.SetItem(seg.Index, value); err != nil {
			return nil, err
		}
		return parent.Item(seg.Index), nil
	default:
		if parent.Kind() != doc.Mapping {
			return nil, fmt.Errorf("cannot set key %q: not a mapping", seg.Key)
		}
		if err := parent.Set(seg.Key, value); err != nil {
			return nil, err
		}
		n, _ := parent.Get(seg.Key)
		return n, nil
	}
}

// deleteAtPath removes the node at path and reports whether it contained
// encrypted values.
func deleteAtPath(root doc.Node, path doc.Path) (bool, error) {
	parentPath := path[:len(path)-1]
	parent, err := doc.Resolve(root, parentPath)
	if err != nil {
		return false, err
	}
	last := path[len(path)-1]
	target := existingAt(parent, last)
	if target == nil {
		if last.IsIndex {
			return false, fmt.Errorf("%s: index %d does not exist", path.String(), last.Index)
		}
		return false, fmt.Errorf("key %q not found in %s", last.Key, parentPath.String())
	}
	encrypted := processor.HasEncryptedNodes(target)
	if last.IsIndex {
		if !parent.DeleteItem(last.Index) {
			return false, fmt.Errorf("cannot delete %s", path.String())
		}
		return encrypted, nil
	}
	if !parent.Delete(last.Key) {
		return false, fmt.Errorf("cannot delete %s", path.String())
	}
	return encrypted, nil
}
