package processor

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"gopkg.in/yaml.v3"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/crypto"
	"github.com/maurice2k/confcrypt/internal/doc"
	"github.com/maurice2k/confcrypt/internal/fileutil"
	"github.com/maurice2k/confcrypt/internal/format"
)

// FileFormat represents the format of a config file
type FileFormat int

const (
	FormatYAML FileFormat = iota
	FormatJSON
	FormatEnv
	FormatFull // Full file encryption (binary or text)
)

// IdentityLoader is a function that loads age identities
type IdentityLoader func() ([]age.Identity, error)

// Processor handles encryption/decryption of config files
type Processor struct {
	config          *config.Config
	matcher         *Matcher
	aesKey          []byte
	altKeys         [][]byte // additional decryption candidates (e.g. from an interrupted rekey)
	altKeysLoaded   bool
	recipients      []age.Recipient
	identities      []age.Identity
	identityLoader  IdentityLoader
	encryptionReady bool

	// reuse, when non-nil, maps (path, type, tag, plaintext) to ciphertexts
	// recorded while decrypting; see EnableCiphertextReuse
	reuse map[string][]*format.EncryptedValue
}

// EnableCiphertextReuse makes the processor remember every value it decrypts
// from now on, and reuse that exact ciphertext when it later encrypts the same
// plaintext at the same path with the same type. Each recorded ciphertext is
// handed out at most once, in the order it was recorded. This keeps
// untouched values byte-identical across a decrypt/edit/encrypt round-trip
// (stable diffs) without ever reusing an IV for different plaintext.
func (p *Processor) EnableCiphertextReuse() {
	p.reuse = make(map[string][]*format.EncryptedValue)
}

func reuseKey(path []string, valueType format.ValueType, yamlTag string, plaintext []byte) string {
	return strings.Join(path, "\x00") + "\x01" + string(valueType) + "\x01" + yamlTag + "\x01" + string(plaintext)
}

func (p *Processor) recordCiphertext(path []string, plaintext []byte, ev *format.EncryptedValue) {
	if p.reuse == nil {
		return
	}
	k := reuseKey(path, ev.Type, ev.YAMLTag, plaintext)
	p.reuse[k] = append(p.reuse[k], ev)
}

func (p *Processor) takeCiphertext(path []string, valueType format.ValueType, yamlTag string, plaintext []byte) *format.EncryptedValue {
	if p.reuse == nil {
		return nil
	}
	k := reuseKey(path, valueType, yamlTag, plaintext)
	list := p.reuse[k]
	if len(list) == 0 {
		return nil
	}
	ev := list[0]
	if len(list) == 1 {
		delete(p.reuse, k)
	} else {
		p.reuse[k] = list[1:]
	}
	return ev
}

// NewProcessor creates a new Processor
func NewProcessor(cfg *config.Config, identityLoader IdentityLoader) (*Processor, error) {
	// Parse key rules
	includeRules, err := config.ParseKeyRules(cfg.KeysInclude)
	if err != nil {
		return nil, fmt.Errorf("invalid include rules: %w", err)
	}

	excludeRules, err := config.ParseKeyRules(cfg.KeysExclude)
	if err != nil {
		return nil, fmt.Errorf("invalid exclude rules: %w", err)
	}

	matcher, err := NewMatcher(includeRules, excludeRules)
	if err != nil {
		return nil, fmt.Errorf("failed to create matcher: %w", err)
	}

	return &Processor{
		config:         cfg,
		matcher:        matcher,
		identityLoader: identityLoader,
	}, nil
}

// Config returns the processor's config
func (p *Processor) Config() *config.Config {
	return p.config
}

// SetupEncryption prepares the processor for encryption
func (p *Processor) SetupEncryption() error {
	return p.SetupEncryptionWithIdentities(nil)
}

// SetupEncryptionWithIdentities prepares the processor for encryption with optional identities
// If identities is nil, it will try to load them from environment/default location
func (p *Processor) SetupEncryptionWithIdentities(identities []age.Identity) error {
	// Get recipients
	recipients, err := p.config.GetRecipients()
	if err != nil {
		return err
	}
	p.recipients = recipients

	// Check if we already have an AES key (from existing .confcrypt section)
	// If so, we MUST reuse it to avoid breaking already-encrypted values
	if p.config.HasSecrets() {
		// Load identities to decrypt the existing key if not provided
		if identities == nil && p.identityLoader != nil {
			identities, err = p.identityLoader()
			if err != nil {
				return fmt.Errorf("cannot decrypt existing AES key: %w", err)
			}
		}

		if len(identities) > 0 {
			for _, entry := range p.config.Confcrypt.Store {
				key, err := crypto.DecryptWithIdentities([]byte(entry.Secret), identities)
				if err == nil {
					p.aesKey = key
					p.identities = identities
					p.encryptionReady = true
					return nil
				}
			}
		}
		// If we have existing secrets but can't decrypt them, that's an error
		// because we'd generate a new key and break existing encrypted values
		return fmt.Errorf("cannot decrypt existing AES key from .confcrypt section; ensure your age private key is available")
	}

	// No existing secrets - generate new AES key
	key, err := crypto.GenerateAESKey()
	if err != nil {
		return err
	}
	p.aesKey = key
	p.encryptionReady = true

	return nil
}

func (p *Processor) ensureEncryptionSetup() error {
	if p.encryptionReady {
		return nil
	}
	return p.SetupEncryption()
}

// SetupDecryption prepares the processor for decryption.
// Returns the public key of the recipient that was used for decryption.
func (p *Processor) SetupDecryption(identities []age.Identity) (string, error) {
	p.identities = identities

	if !p.config.HasSecrets() {
		return "", fmt.Errorf("no encrypted secrets found in .confcrypt section")
	}

	// Find and decrypt the AES key
	for _, entry := range p.config.Confcrypt.Store {
		key, err := crypto.DecryptWithIdentities([]byte(entry.Secret), identities)
		if err == nil {
			p.aesKey = key
			return entry.Recipient, nil
		}
	}

	return "", fmt.Errorf("could not decrypt AES key with provided identities")
}

// loadAltKeys decrypts all store entries with the current identities and
// collects any AES keys that differ from the primary key. The store normally
// wraps a single key, but during an interrupted rekey it transitionally holds
// the old and the new key; trial decryption with all candidates makes that
// state fully recoverable. Loaded lazily so the common single-key case never
// touches the store (or hardware identities) more than once.
func (p *Processor) loadAltKeys() {
	if p.altKeysLoaded {
		return
	}
	p.altKeysLoaded = true

	if len(p.identities) == 0 || p.config.Confcrypt == nil {
		return
	}

	for _, entry := range p.config.Confcrypt.Store {
		key, err := crypto.DecryptWithIdentities([]byte(entry.Secret), p.identities)
		if err != nil || bytes.Equal(key, p.aesKey) {
			continue
		}
		known := false
		for _, k := range p.altKeys {
			if bytes.Equal(k, key) {
				known = true
				break
			}
		}
		if !known {
			p.altKeys = append(p.altKeys, key)
		}
	}
}

// decryptAESGCM decrypts with the primary AES key, falling back to any other
// keys present in the store (AES-GCM authentication reliably rejects a wrong
// key, so trial decryption cannot produce garbage).
func (p *Processor) decryptAESGCM(data, iv, tag []byte) ([]byte, error) {
	plaintext, err := crypto.DecryptAESGCM(p.aesKey, data, iv, tag)
	if err == nil {
		return plaintext, nil
	}

	p.loadAltKeys()
	for _, key := range p.altKeys {
		if pt, altErr := crypto.DecryptAESGCM(key, data, iv, tag); altErr == nil {
			return pt, nil
		}
	}

	return nil, err
}

// EncryptStoreEntries wraps the current AES key for every configured
// recipient and returns the entries as a pubkey -> encrypted secret map.
// Recipients listed in exclude are skipped (used for hand-added recipients
// whose access has not been granted; see cmd/grant.go).
func (p *Processor) EncryptStoreEntries(exclude ...string) (map[string]string, error) {
	secrets := make(map[string]string)
	excluded := make(map[string]bool, len(exclude))
	for _, k := range exclude {
		excluded[k] = true
	}

	for _, r := range p.config.Recipients {
		pubKey := r.GetPublicKey()
		if pubKey == "" {
			return nil, fmt.Errorf("recipient %q has no public key", r.Name)
		}
		if excluded[pubKey] {
			continue
		}

		recipient, err := crypto.ParseRecipient(pubKey)
		if err != nil {
			return nil, err
		}

		encrypted, err := crypto.EncryptForRecipients(p.aesKey, []age.Recipient{recipient})
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt secret for %s: %w", pubKey, err)
		}

		secrets[pubKey] = string(encrypted)
	}

	return secrets, nil
}

// AddStoreRecipients wraps the current AES key for the given configured
// recipients and appends those entries to the store, leaving existing
// entries untouched (stale entries are preserved, never pruned, since
// dropping them does not actually revoke access without a rekey).
// Recipients that already have a store entry are skipped.
// ensureEncryptionSetup loads identities to decrypt the existing key, which
// may prompt a hardware key, but only if setup has not already happened.
// The config is mutated in memory; the caller is responsible for saving.
// Returns the public keys that were added.
func (p *Processor) AddStoreRecipients(pubKeys []string) ([]string, error) {
	if len(pubKeys) == 0 {
		return nil, nil
	}
	if err := p.ensureEncryptionSetup(); err != nil {
		return nil, err
	}

	inStore := make(map[string]bool)
	if p.config.Confcrypt != nil {
		for _, entry := range p.config.Confcrypt.Store {
			inStore[entry.Recipient] = true
		}
	}
	configured := make(map[string]bool)
	for _, r := range p.config.Recipients {
		if pubKey := r.GetPublicKey(); pubKey != "" {
			configured[pubKey] = true
		}
	}

	secrets := make(map[string]string)
	var added []string
	for _, pubKey := range pubKeys {
		if inStore[pubKey] {
			continue
		}
		if !configured[pubKey] {
			return nil, fmt.Errorf("recipient %s is not configured", pubKey)
		}

		recipient, err := crypto.ParseRecipient(pubKey)
		if err != nil {
			return nil, err
		}

		encrypted, err := crypto.EncryptForRecipients(p.aesKey, []age.Recipient{recipient})
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt secret for %s: %w", pubKey, err)
		}

		secrets[pubKey] = string(encrypted)
		added = append(added, pubKey)
		inStore[pubKey] = true
	}

	if len(secrets) > 0 {
		p.config.AddSecrets(secrets)
	}

	return added, nil
}

// SaveEncryptedSecrets encrypts the AES key for all recipients (except the
// excluded ones) and saves to config
func (p *Processor) SaveEncryptedSecrets(exclude ...string) error {
	secrets, err := p.EncryptStoreEntries(exclude...)
	if err != nil {
		return err
	}

	p.config.SetSecrets(secrets)
	return p.config.Save()
}

// ProcessFile processes a single file for encryption or decryption
// The optional formatOverride parameter can be used to force a specific format
func (p *Processor) ProcessFile(filePath string, encrypt bool, formatOverride ...string) ([]byte, bool, error) {
	var override string
	if len(formatOverride) > 0 {
		override = formatOverride[0]
	}
	fileFormat := DetectFormat(filePath, override)

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read file: %w", err)
	}

	return p.ProcessContent(content, filePath, encrypt, fileFormat)
}

// ProcessContent processes content with a specific format for encryption or decryption
func (p *Processor) ProcessContent(content []byte, filePath string, encrypt bool, fileFormat FileFormat) ([]byte, bool, error) {
	var output []byte
	var modified bool
	var err error

	switch fileFormat {
	case FormatYAML:
		// Use node-based processing to preserve comments
		var docs []*yaml.Node
		docs, modified, err = p.processYAMLDocs(content, encrypt)
		if err != nil {
			return nil, false, err
		}
		if !modified {
			return content, false, nil
		}
		output, err = marshalYAMLDocs(docs)
	case FormatJSON:
		var d *doc.JSONDocument
		d, modified, err = p.processJSON(content, encrypt)
		if err != nil {
			return nil, false, err
		}
		if !modified {
			return content, false, nil
		}
		output, err = d.Marshal()
	case FormatEnv:
		var envFile *EnvFile
		envFile, modified, err = p.processEnv(content, encrypt)
		if err != nil {
			return nil, false, err
		}
		if !modified {
			return content, false, nil
		}
		output = envFile.Marshal()
	case FormatFull:
		output, modified, err = p.processFullFile(content, encrypt)
		if err != nil {
			return nil, false, err
		}
		if !modified {
			return content, false, nil
		}
	default:
		return nil, false, fmt.Errorf("unsupported file format")
	}

	if err != nil {
		return nil, false, fmt.Errorf("failed to marshal output: %w", err)
	}

	return output, true, nil
}

// processYAMLDocs processes all documents of a (possibly multi-document)
// YAML stream while preserving comments
func (p *Processor) processYAMLDocs(content []byte, encrypt bool) ([]*yaml.Node, bool, error) {
	docs, err := decodeYAMLDocs(content)
	if err != nil {
		return nil, false, err
	}

	modified := false
	for _, node := range docs {
		// Preserve blank lines from original before any modifications
		preserveBlankLines(node, content)

		// Transform nodes in-place, preserving comments
		m, err := p.transformNode(doc.FromYAML(node), nil, encrypt)
		if err != nil {
			return nil, false, err
		}
		modified = modified || m
	}

	return docs, modified, nil
}

// decodeYAMLDocs parses all documents of a YAML stream into nodes.
// yaml.Unmarshal would silently drop every document after the first.
func decodeYAMLDocs(content []byte) ([]*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	var docs []*yaml.Node
	for {
		var node yaml.Node
		err := decoder.Decode(&node)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
		docs = append(docs, &node)
	}
	return docs, nil
}

// decodeYAMLValues parses all documents of a YAML stream into plain values
func decodeYAMLValues(content []byte) ([]interface{}, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	var values []interface{}
	for {
		var v interface{}
		err := decoder.Decode(&v)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
		values = append(values, v)
	}
	return values, nil
}

// processJSON parses JSON losslessly (key order, formatting and comments are
// kept) and transforms matching values in place
func (p *Processor) processJSON(content []byte, encrypt bool) (*doc.JSONDocument, bool, error) {
	d, err := doc.ParseJSON(content)
	if err != nil {
		return nil, false, err
	}
	modified, err := p.transformNode(d.Root(), nil, encrypt)
	if err != nil {
		return nil, false, err
	}
	return d, modified, nil
}

// processEnv processes .env file content
func (p *Processor) processEnv(content []byte, encrypt bool) (*EnvFile, bool, error) {
	envFile, err := ParseEnvFile(content)
	if err != nil {
		return nil, false, fmt.Errorf("failed to parse .env file: %w", err)
	}
	modified, err := p.transformNode(envDoc(envFile), nil, encrypt)
	if err != nil {
		return nil, false, err
	}
	return envFile, modified, nil
}

// parseRoots parses structured content into document roots (one per YAML
// document, exactly one for JSON and env files)
func parseRoots(content []byte, fileFormat FileFormat) ([]doc.Node, error) {
	switch fileFormat {
	case FormatYAML:
		docs, err := decodeYAMLDocs(content)
		if err != nil {
			return nil, err
		}
		roots := make([]doc.Node, 0, len(docs))
		for _, d := range docs {
			if root := doc.FromYAML(d); root != nil {
				roots = append(roots, root)
			}
		}
		return roots, nil
	case FormatJSON:
		d, err := doc.ParseJSON(content)
		if err != nil {
			return nil, err
		}
		return []doc.Node{d.Root()}, nil
	case FormatEnv:
		envFile, err := ParseEnvFile(content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse .env file: %w", err)
		}
		return []doc.Node{envDoc(envFile)}, nil
	default:
		return nil, fmt.Errorf("unsupported file format")
	}
}

// processFullFile processes a file for full file encryption/decryption
func (p *Processor) processFullFile(content []byte, encrypt bool) ([]byte, bool, error) {
	if encrypt {
		// Check if already encrypted
		if format.IsFullFileEncrypted(content) {
			return content, false, nil
		}

		// Encrypt the entire content
		ev, err := p.encryptPlaintext(nil, content, format.TypeBytes)
		if err != nil {
			return nil, false, fmt.Errorf("failed to encrypt file: %w", err)
		}

		output := format.FormatFullFileEncrypted(ev)
		return []byte(output), true, nil
	}

	// Decrypt
	if !format.IsFullFileEncrypted(content) {
		return content, false, nil
	}

	ev, err := format.ParseFullFileEncrypted(string(content))
	if err != nil {
		return nil, false, fmt.Errorf("failed to parse encrypted file: %w", err)
	}

	plaintext, err := p.decryptAESGCM(ev.Data, ev.IV, ev.Tag)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decrypt file: %w", err)
	}

	return plaintext, true, nil
}

func (p *Processor) encryptPlaintext(path []string, plaintext []byte, valueType format.ValueType) (*format.EncryptedValue, error) {
	return p.encryptPlaintextTagged(path, plaintext, valueType, "")
}

// encryptPlaintextTagged encrypts plaintext with a fresh IV, unless ciphertext
// reuse is enabled and an identical value was decrypted at this path before,
// in which case that ciphertext is returned verbatim (see EnableCiphertextReuse).
func (p *Processor) encryptPlaintextTagged(path []string, plaintext []byte, valueType format.ValueType, yamlTag string) (*format.EncryptedValue, error) {
	if err := p.ensureEncryptionSetup(); err != nil {
		return nil, err
	}

	if ev := p.takeCiphertext(path, valueType, yamlTag, plaintext); ev != nil {
		return ev, nil
	}

	ciphertext, iv, tag, err := crypto.EncryptAESGCM(p.aesKey, plaintext)
	if err != nil {
		return nil, err
	}

	ev := &format.EncryptedValue{
		Data:    ciphertext,
		IV:      iv,
		Tag:     tag,
		Type:    valueType,
		YAMLTag: yamlTag,
	}

	return ev, nil
}

// CheckFile checks a file for unencrypted keys that should be encrypted
// The optional formatOverride parameter can be used to force a specific format
func (p *Processor) CheckFile(filePath string, formatOverride ...string) ([]MatchResult, error) {
	var override string
	if len(formatOverride) > 0 {
		override = formatOverride[0]
	}
	fileFormat := DetectFormat(filePath, override)

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return p.CheckContent(content, fileFormat)
}

// CheckContent checks already-loaded content for unencrypted values that would
// be encrypted by ProcessContent, without initializing encryption keys.
func (p *Processor) CheckContent(content []byte, fileFormat FileFormat) ([]MatchResult, error) {
	// For full file encryption, check if file is already encrypted
	if fileFormat == FormatFull {
		if format.IsFullFileEncrypted(content) {
			return nil, nil // Already encrypted
		}
		// Return a single result indicating the entire file should be encrypted
		return []MatchResult{{
			KeyName:   "(full file)",
			Path:      []string{},
			Encrypted: false,
		}}, nil
	}

	roots, err := parseRoots(content, fileFormat)
	if err != nil {
		return nil, err
	}
	var results []MatchResult
	for _, root := range roots {
		p.collectUnencrypted(root, nil, &results)
	}
	return results, nil
}

// MatchFile returns all keys matching the configured patterns, regardless of encryption state.
func (p *Processor) MatchFile(filePath string, formatOverride ...string) ([]MatchResult, error) {
	var override string
	if len(formatOverride) > 0 {
		override = formatOverride[0]
	}
	fileFormat := DetectFormat(filePath, override)

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	if fileFormat == FormatFull {
		encrypted := format.IsFullFileEncrypted(content)
		return []MatchResult{{
			KeyName:   "(full file)",
			Path:      []string{},
			Encrypted: encrypted,
		}}, nil
	}

	roots, err := parseRoots(content, fileFormat)
	if err != nil {
		return nil, err
	}
	var results []MatchResult
	for _, root := range roots {
		results = append(results, p.matcher.FindMatchingKeys(root)...)
	}
	return results, nil
}

// WriteFile writes content to a file atomically, preserving the permissions
// of an existing target file
func (p *Processor) WriteFile(filePath string, content []byte) error {
	return fileutil.WriteFileAtomic(filePath, content, 0644)
}

// ComputeMAC computes the MAC (SHA256 hash of all encrypted values) for a file
func (p *Processor) ComputeMAC(content []byte, fileFormat FileFormat) ([]byte, error) {
	// For full file encryption, the MAC is the hash of the entire encrypted content
	if fileFormat == FormatFull {
		if !format.IsFullFileEncrypted(content) {
			return nil, fmt.Errorf("file is not encrypted")
		}
		h := sha256.New()
		h.Write(content)
		return h.Sum(nil), nil
	}

	var encryptedValues []string
	if fileFormat == FormatYAML {
		// YAML MACs are computed over the fully resolved values (aliases and
		// merge keys expanded), as they always have been; switching to the
		// node walk would invalidate stored MACs of files using aliases
		values, err := decodeYAMLValues(content)
		if err != nil {
			return nil, err
		}
		encryptedValues = collectEncryptedValues(values, nil)
	} else {
		roots, err := parseRoots(content, fileFormat)
		if err != nil {
			return nil, err
		}
		for _, root := range roots {
			encryptedValues = collectEncryptedNodeValues(root, encryptedValues)
		}
	}

	// Deterministic order
	sort.Strings(encryptedValues)

	// Compute SHA256 hash of concatenated encrypted values
	h := sha256.New()
	for _, v := range encryptedValues {
		h.Write([]byte(v))
	}

	return h.Sum(nil), nil
}

// collectEncryptedValues recursively collects all encrypted values from data
func collectEncryptedValues(data interface{}, values []string) []string {
	switch v := data.(type) {
	case map[string]interface{}:
		for _, val := range v {
			if s, ok := val.(string); ok && format.IsEncrypted(s) {
				values = append(values, s)
			} else {
				values = collectEncryptedValues(val, values)
			}
		}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && format.IsEncrypted(s) {
				values = append(values, s)
			} else {
				values = collectEncryptedValues(item, values)
			}
		}
	}
	return values
}

// EncryptMAC encrypts the MAC hash using AES-GCM
func (p *Processor) EncryptMAC(hash []byte) (string, error) {
	ciphertext, iv, tag, err := crypto.EncryptAESGCM(p.aesKey, hash)
	if err != nil {
		return "", err
	}

	ev := &format.EncryptedValue{
		Data: ciphertext,
		IV:   iv,
		Tag:  tag,
		Type: format.TypeBytes,
	}

	return format.FormatEncryptedValue(ev), nil
}

// VerifyMAC verifies the MAC for a file
// The optional formatOverride parameter can be used to force a specific format
func (p *Processor) VerifyMAC(filePath string, content []byte, formatOverride ...string) error {
	var override string
	if len(formatOverride) > 0 {
		override = formatOverride[0]
	}
	fileFormat := DetectFormat(filePath, override)

	// Get relative path for MAC lookup
	relPath, err := filepath.Rel(p.config.ConfigDir(), filePath)
	if err != nil {
		relPath = filePath
	}

	storedMAC, ok := p.config.GetMAC(relPath)
	if !ok {
		// No MAC stored - skip verification (backwards compatibility)
		return nil
	}

	// Decrypt stored MAC
	ev, err := format.ParseEncryptedValue(storedMAC)
	if err != nil {
		return fmt.Errorf("failed to parse stored MAC: %w", err)
	}

	expectedHash, err := p.decryptAESGCM(ev.Data, ev.IV, ev.Tag)
	if err != nil {
		return fmt.Errorf("failed to decrypt stored MAC: %w", err)
	}

	// Compute current MAC
	currentHash, err := p.ComputeMAC(content, fileFormat)
	if err != nil {
		return fmt.Errorf("failed to compute MAC: %w", err)
	}

	// Compare
	if !bytes.Equal(expectedHash, currentHash) {
		return fmt.Errorf("MAC verification failed - file may have been tampered with")
	}

	return nil
}

// HasEncryptedValues checks if file content contains any encrypted values
// The optional formatOverride parameter can be used to force a specific format
func (p *Processor) HasEncryptedValues(content []byte, filePath string, formatOverride ...string) bool {
	hasEncrypted, err := p.HasEncryptedValuesStrict(content, filePath, formatOverride...)
	return err == nil && hasEncrypted
}

// HasEncryptedValuesStrict checks if file content contains any encrypted values
// and returns parse errors instead of treating them as "no encrypted values".
// The optional formatOverride parameter can be used to force a specific format.
func (p *Processor) HasEncryptedValuesStrict(content []byte, filePath string, formatOverride ...string) (bool, error) {
	var override string
	if len(formatOverride) > 0 {
		override = formatOverride[0]
	}
	fileFormat := DetectFormat(filePath, override)

	// For full file encryption, check for the header
	if fileFormat == FormatFull {
		return format.IsFullFileEncrypted(content), nil
	}

	roots, err := parseRoots(content, fileFormat)
	if err != nil {
		return false, err
	}
	for _, root := range roots {
		if len(collectEncryptedNodeValues(root, nil)) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// HasUnencryptedValues checks if file content contains any unencrypted values that match encryption rules
// The optional formatOverride parameter can be used to force a specific format
func (p *Processor) HasUnencryptedValues(content []byte, filePath string, formatOverride ...string) bool {
	var override string
	if len(formatOverride) > 0 {
		override = formatOverride[0]
	}
	fileFormat := DetectFormat(filePath, override)

	results, err := p.CheckContent(content, fileFormat)
	if err != nil {
		return false
	}
	return len(results) > 0
}

// UpdateMAC computes and stores the MAC for a file
// The optional formatOverride parameter can be used to force a specific format
func (p *Processor) UpdateMAC(filePath string, content []byte, formatOverride ...string) error {
	var override string
	if len(formatOverride) > 0 {
		override = formatOverride[0]
	}
	fileFormat := DetectFormat(filePath, override)

	// Compute MAC
	hash, err := p.ComputeMAC(content, fileFormat)
	if err != nil {
		return err
	}

	// Encrypt MAC
	encryptedMAC, err := p.EncryptMAC(hash)
	if err != nil {
		return err
	}

	// Get relative path for storage
	relPath, err := filepath.Rel(p.config.ConfigDir(), filePath)
	if err != nil {
		relPath = filePath
	}

	p.config.SetMAC(relPath, encryptedMAC)
	return nil
}

// DetectFormat determines the file format from extension and optional override
// The override parameter can be "full", "yaml", "json", or "env" to force a specific format
func DetectFormat(filePath string, override ...string) FileFormat {
	// Check for explicit override
	if len(override) > 0 && override[0] != "" {
		switch strings.ToLower(override[0]) {
		case "full":
			return FormatFull
		case "yaml":
			return FormatYAML
		case "json":
			return FormatJSON
		case "env":
			return FormatEnv
		}
	}

	base := filepath.Base(filePath)
	ext := strings.ToLower(filepath.Ext(filePath))

	// Implicit full encryption for known sensitive file patterns
	// Extension-based: *.key, *.pem, *.p12, *.pfx, *.p8, *.keystore, *.jks
	switch ext {
	case ".key", ".pem", ".p12", ".pfx", ".p8", ".keystore", ".jks":
		return FormatFull
	}

	// SSH keys: id_ed25519*, id_rsa*, id_ecdsa*, id_dsa*
	if strings.HasPrefix(base, "id_ed25519") ||
		strings.HasPrefix(base, "id_rsa") ||
		strings.HasPrefix(base, "id_ecdsa") ||
		strings.HasPrefix(base, "id_dsa") {
		return FormatFull
	}

	// Check for .env files: .env, *.env (e.g., database.env), .env.* (e.g., .env.local)
	if base == ".env" || ext == ".env" || strings.HasPrefix(base, ".env.") {
		return FormatEnv
	}

	switch ext {
	case ".json", ".jsonc":
		return FormatJSON
	case ".yml", ".yaml":
		return FormatYAML
	default:
		return FormatYAML // Default to YAML
	}
}

// marshalYAMLDocs marshals all documents of a YAML stream, preserving
// comments and structure; documents are separated with "---" by the encoder
func marshalYAMLDocs(docs []*yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	for _, node := range docs {
		normalizeMergeKeyTags(node)
		if err := encoder.Encode(node); err != nil {
			encoder.Close()
			return nil, err
		}
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func normalizeMergeKeyTags(node *yaml.Node) {
	if node == nil {
		return
	}

	if node.Kind == yaml.ScalarNode && node.Tag == "!!merge" && node.Value == "<<" {
		node.Tag = "!!str"
		node.Style &^= yaml.TaggedStyle
	}

	for _, child := range node.Content {
		normalizeMergeKeyTags(child)
	}
}

// preserveBlankLines detects gaps in line numbers and adds newlines to HeadComment
// to preserve blank lines from the original YAML file
func preserveBlankLines(node *yaml.Node, content []byte) {
	preserveBlankLinesRecursive(node, 0, strings.Split(string(content), "\n"))
}

// preserveBlankLinesRecursive walks the node tree and adds newlines to HeadComment
// where there are gaps in line numbers between siblings
func preserveBlankLinesRecursive(node *yaml.Node, prevEndLine int, sourceLines []string) int {
	if node == nil {
		return prevEndLine
	}

	// If there's a gap of more than 1 line from previous sibling, add blank lines
	if node.Line > 0 && prevEndLine > 0 {
		// Calculate how many lines the HeadComment takes up
		headCommentLines := 0
		if node.HeadComment != "" {
			// Strip any leading newlines we may have added previously
			comment := strings.TrimLeft(node.HeadComment, "\n")
			headCommentLines = commentLineCount(comment)
			node.HeadComment = comment // Remove accumulated leading newlines
		}

		// Gap should account for HeadComment lines
		gap := node.Line - prevEndLine - 1 - headCommentLines
		if gap > 0 {
			// Add exact number of blank lines
			node.HeadComment = strings.Repeat("\n", gap) + node.HeadComment
		}
	}

	currentEndLine := node.Line

	// Process children - track line numbers across siblings
	childEndLine := 0
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			keyEndLine := preserveBlankLinesRecursive(node.Content[i], childEndLine, sourceLines)
			valueEndLine := keyEndLine
			if i+1 < len(node.Content) {
				valueEndLine = preserveBlankLinesRecursive(node.Content[i+1], keyEndLine, sourceLines)
			}
			if keyEndLine > valueEndLine {
				childEndLine = keyEndLine
			} else {
				childEndLine = valueEndLine
			}
		}
	} else {
		for _, child := range node.Content {
			childEndLine = preserveBlankLinesRecursive(child, childEndLine, sourceLines)
		}
	}

	// The end line is the maximum of current node's line and its children's end line
	if childEndLine > currentEndLine {
		currentEndLine = childEndLine
	}

	if flowEndLine := findFlowCollectionEndLine(node, sourceLines); flowEndLine > currentEndLine {
		currentEndLine = flowEndLine
	}
	if blockScalarEndLine := findBlockScalarEndLine(node, sourceLines); blockScalarEndLine > currentEndLine {
		currentEndLine = blockScalarEndLine
	}

	currentEndLine += commentLineCount(node.FootComment)

	return currentEndLine
}

func findBlockScalarEndLine(node *yaml.Node, sourceLines []string) int {
	if node.Kind != yaml.ScalarNode || (node.Style != yaml.LiteralStyle && node.Style != yaml.FoldedStyle) || node.Line <= 0 {
		return 0
	}

	lineIdx := node.Line
	if lineIdx >= len(sourceLines) {
		return node.Line
	}

	contentIndent := -1
	lastContentLine := node.Line
	pendingBlankLine := 0

	for ; lineIdx < len(sourceLines); lineIdx++ {
		line := sourceLines[lineIdx]
		if strings.TrimSpace(line) == "" {
			if contentIndent >= 0 {
				pendingBlankLine = lineIdx + 1
			}
			continue
		}

		indent := leadingSpaces(line)
		if contentIndent < 0 {
			contentIndent = indent
		}
		if indent < contentIndent {
			break
		}

		if pendingBlankLine > lastContentLine {
			lastContentLine = pendingBlankLine
		}
		lastContentLine = lineIdx + 1
		pendingBlankLine = 0
	}

	return lastContentLine
}

func leadingSpaces(line string) int {
	count := 0
	for _, r := range line {
		if r != ' ' {
			break
		}
		count++
	}
	return count
}

func findFlowCollectionEndLine(node *yaml.Node, sourceLines []string) int {
	if node.Line <= 0 || node.Column <= 0 || node.Style&yaml.FlowStyle == 0 {
		return 0
	}

	var open, close rune
	switch node.Kind {
	case yaml.SequenceNode:
		open, close = '[', ']'
	case yaml.MappingNode:
		open, close = '{', '}'
	default:
		return 0
	}

	lineIdx := node.Line - 1
	if lineIdx >= len(sourceLines) {
		return 0
	}

	depth := 0
	started := false
	inSingleQuote := false
	inDoubleQuote := false
	escaped := false

	for ; lineIdx < len(sourceLines); lineIdx++ {
		line := sourceLines[lineIdx]
		colIdx := 0
		if !started && lineIdx == node.Line-1 {
			colIdx = node.Column - 1
			if colIdx >= len(line) {
				colIdx = len(line)
			}
		}

		for _, r := range line[colIdx:] {
			if inDoubleQuote {
				if escaped {
					escaped = false
					continue
				}
				if r == '\\' {
					escaped = true
					continue
				}
				if r == '"' {
					inDoubleQuote = false
				}
				continue
			}

			if inSingleQuote {
				if r == '\'' {
					inSingleQuote = false
				}
				continue
			}

			switch r {
			case '#':
				goto nextLine
			case '"':
				inDoubleQuote = true
			case '\'':
				inSingleQuote = true
			case open:
				depth++
				started = true
			case close:
				if started {
					depth--
					if depth == 0 {
						return lineIdx + 1
					}
				}
			}
		}

	nextLine:
	}

	return 0
}

func commentLineCount(comment string) int {
	comment = strings.Trim(comment, "\n")
	if comment == "" {
		return 0
	}
	return strings.Count(comment, "\n") + 1
}
