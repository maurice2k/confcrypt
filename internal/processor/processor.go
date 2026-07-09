package processor

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
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
func (p *Processor) EncryptStoreEntries() (map[string]string, error) {
	secrets := make(map[string]string)

	for _, r := range p.config.Recipients {
		pubKey := r.GetPublicKey()
		if pubKey == "" {
			return nil, fmt.Errorf("recipient %q has no public key", r.Name)
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

// AddMissingStoreRecipients wraps the current AES key for every configured
// recipient that is not yet present in the store and appends those entries,
// leaving existing entries untouched (stale entries are preserved, never
// pruned, since dropping them does not actually revoke access without a
// rekey). ensureEncryptionSetup loads identities to decrypt the existing key,
// which may prompt a hardware key, but only if setup has not already happened.
// The config is mutated in memory; the caller is responsible for saving.
// Returns the public keys that were added.
func (p *Processor) AddMissingStoreRecipients() ([]string, error) {
	if err := p.ensureEncryptionSetup(); err != nil {
		return nil, err
	}

	inStore := make(map[string]bool)
	if p.config.Confcrypt != nil {
		for _, entry := range p.config.Confcrypt.Store {
			inStore[entry.Recipient] = true
		}
	}

	secrets := make(map[string]string)
	var added []string
	for _, r := range p.config.Recipients {
		pubKey := r.GetPublicKey()
		if pubKey == "" || inStore[pubKey] {
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
		added = append(added, pubKey)
	}

	if len(secrets) > 0 {
		p.config.AddSecrets(secrets)
	}

	return added, nil
}

// SaveEncryptedSecrets encrypts the AES key for all recipients and saves to config
func (p *Processor) SaveEncryptedSecrets() error {
	secrets, err := p.EncryptStoreEntries()
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
		var data interface{}
		data, modified, err = p.processJSON(content, encrypt)
		if err != nil {
			return nil, false, err
		}
		if !modified {
			return content, false, nil
		}
		output, err = marshalJSON(content, data)
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
		m, err := p.transformYAMLNode(node, nil, encrypt)
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

// transformYAMLNode recursively transforms YAML nodes for encryption/decryption
// It modifies node values in-place, preserving all comments and structure
func (p *Processor) transformYAMLNode(node *yaml.Node, path []string, encrypt bool) (bool, error) {
	modified := false

	switch node.Kind {
	case yaml.DocumentNode:
		// Document node contains the root content
		for _, child := range node.Content {
			childModified, err := p.transformYAMLNode(child, path, encrypt)
			if err != nil {
				return false, err
			}
			if childModified {
				modified = true
			}
		}

	case yaml.MappingNode:
		// Mapping nodes have alternating key/value pairs in Content
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]
			key := keyNode.Value
			currentPath := append(path, key)

			switch {
			case valueNode.Kind == yaml.ScalarNode:
				// Leaf value - check if we should encrypt/decrypt
				if encrypt {
					if p.shouldEncryptString(key, currentPath, valueNode.Value) {
						encrypted, err := p.encryptScalarValue(valueNode.Value, valueNode.Tag)
						if err != nil {
							return false, fmt.Errorf("failed to encrypt %s: %w", strings.Join(currentPath, "."), err)
						}
						valueNode.Value = encrypted
						valueNode.Tag = "!!str"
						valueNode.Style = 0 // Reset style to let encoder choose
						modified = true
					}
				} else {
					// Decrypt if encrypted
					if format.IsEncrypted(valueNode.Value) {
						decrypted, originalTag, err := p.decryptScalarValue(valueNode.Value)
						if err != nil {
							return false, fmt.Errorf("failed to decrypt %s: %w", strings.Join(currentPath, "."), err)
						}
						valueNode.Value = decrypted
						valueNode.Tag = originalTag
						valueNode.Style = 0
						modified = true
					}
				}

			case encrypt && valueNode.Kind == yaml.SequenceNode && p.matcher.ShouldEncrypt(key, currentPath):
				// A matched key whose value is a list: encrypt the scalar items
				childModified, err := p.encryptMatchedYAMLSequence(valueNode, currentPath)
				if err != nil {
					return false, err
				}
				if childModified {
					modified = true
				}

			case encrypt && valueNode.Kind == yaml.AliasNode && valueNode.Alias != nil && p.matcher.ShouldEncrypt(key, currentPath):
				// A matched key referencing an anchor: encrypt the anchor
				// target so the secret doesn't silently stay in plaintext
				// (all aliases share the target, so they stay consistent)
				childModified, err := p.encryptMatchedYAMLTarget(valueNode.Alias, currentPath)
				if err != nil {
					return false, err
				}
				if childModified {
					modified = true
				}

			default:
				// Recurse into nested structures
				childModified, err := p.transformYAMLNode(valueNode, currentPath, encrypt)
				if err != nil {
					return false, err
				}
				if childModified {
					modified = true
				}
			}
		}

	case yaml.SequenceNode:
		// Sequence nodes have items in Content
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode {
				// Scalar list items are encrypted only under a matched key
				// (handled above), but any encrypted item must decrypt here
				if !encrypt && format.IsEncrypted(item.Value) {
					decrypted, originalTag, err := p.decryptScalarValue(item.Value)
					if err != nil {
						return false, fmt.Errorf("failed to decrypt %s: %w", strings.Join(path, "."), err)
					}
					item.Value = decrypted
					item.Tag = originalTag
					item.Style = 0
					modified = true
				}
				continue
			}

			childModified, err := p.transformYAMLNode(item, path, encrypt)
			if err != nil {
				return false, err
			}
			if childModified {
				modified = true
			}
		}
	}

	return modified, nil
}

// encryptMatchedYAMLSequence encrypts the scalar items of a sequence whose
// key matched the encryption rules. Nested sequences inherit the match;
// mappings inside the list are traversed with normal key matching.
func (p *Processor) encryptMatchedYAMLSequence(node *yaml.Node, path []string) (bool, error) {
	modified := false
	for _, item := range node.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			if format.IsEncrypted(item.Value) {
				continue
			}
			encrypted, err := p.encryptScalarValue(item.Value, item.Tag)
			if err != nil {
				return false, fmt.Errorf("failed to encrypt %s: %w", strings.Join(path, "."), err)
			}
			item.Value = encrypted
			item.Tag = "!!str"
			item.Style = 0
			modified = true
		case yaml.SequenceNode:
			childModified, err := p.encryptMatchedYAMLSequence(item, path)
			if err != nil {
				return false, err
			}
			if childModified {
				modified = true
			}
		default:
			childModified, err := p.transformYAMLNode(item, path, true)
			if err != nil {
				return false, err
			}
			if childModified {
				modified = true
			}
		}
	}
	return modified, nil
}

// encryptMatchedYAMLTarget encrypts the target node of an alias whose
// referencing key matched the encryption rules
func (p *Processor) encryptMatchedYAMLTarget(target *yaml.Node, path []string) (bool, error) {
	switch target.Kind {
	case yaml.ScalarNode:
		if format.IsEncrypted(target.Value) {
			return false, nil
		}
		encrypted, err := p.encryptScalarValue(target.Value, target.Tag)
		if err != nil {
			return false, fmt.Errorf("failed to encrypt %s: %w", strings.Join(path, "."), err)
		}
		target.Value = encrypted
		target.Tag = "!!str"
		target.Style = 0
		return true, nil
	case yaml.SequenceNode:
		return p.encryptMatchedYAMLSequence(target, path)
	default:
		return p.transformYAMLNode(target, path, true)
	}
}

// encryptScalarValue encrypts a scalar YAML value
func (p *Processor) encryptScalarValue(value string, tag string) (string, error) {
	// Determine value type from YAML tag
	valueType := format.TypeString
	switch tag {
	case "!!int":
		valueType = format.TypeInt
	case "!!float":
		valueType = format.TypeFloat
	case "!!bool":
		valueType = format.TypeBool
	case "!!null":
		valueType = format.TypeNull
	}

	ev, err := p.encryptPlaintext([]byte(value), valueType)
	if err != nil {
		return "", err
	}

	// Preserve tags that cannot be reconstructed from the portable value type.
	// This keeps timestamps, binary scalars, and application-specific tags exact
	// while retaining the old ENC format for common scalar types.
	switch tag {
	case "", "!!str", "!!int", "!!float", "!!bool", "!!null":
	default:
		ev.YAMLTag = tag
	}

	return format.FormatEncryptedValue(ev), nil
}

// decryptScalarValue decrypts an ENC[...] value and returns the plaintext and original YAML tag
func (p *Processor) decryptScalarValue(encStr string) (string, string, error) {
	ev, err := format.ParseEncryptedValue(encStr)
	if err != nil {
		return "", "", err
	}

	plaintext, err := p.decryptAESGCM(ev.Data, ev.IV, ev.Tag)
	if err != nil {
		return "", "", err
	}

	// Prefer the exact YAML tag stored by newer ciphertexts. Older ciphertexts
	// reconstruct the tag from their portable value type as before.
	if ev.YAMLTag != "" {
		return string(plaintext), ev.YAMLTag, nil
	}

	// Determine YAML tag from stored type
	tag := "!!str"
	switch ev.Type {
	case format.TypeInt:
		tag = "!!int"
	case format.TypeFloat:
		tag = "!!float"
	case format.TypeBool:
		tag = "!!bool"
	case format.TypeNull:
		tag = "!!null"
	}

	return string(plaintext), tag, nil
}

// decodeJSON parses JSON content with numbers kept as json.Number, so large
// integers and exact decimal representations survive a re-marshal verbatim
// instead of being corrupted by a float64 round-trip
func decodeJSON(content []byte) (interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	var data interface{}
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return data, nil
}

// processJSON processes JSON content
func (p *Processor) processJSON(content []byte, encrypt bool) (interface{}, bool, error) {
	data, err := decodeJSON(content)
	if err != nil {
		return nil, false, err
	}

	modified, err := p.transformData(&data, nil, encrypt)
	if err != nil {
		return nil, false, err
	}

	return data, modified, nil
}

// processEnv processes .env file content
func (p *Processor) processEnv(content []byte, encrypt bool) (*EnvFile, bool, error) {
	envFile, err := ParseEnvFile(content)
	if err != nil {
		return nil, false, fmt.Errorf("failed to parse .env file: %w", err)
	}

	modified := false

	for i, line := range envFile.Lines {
		if line.Type != EnvLineKeyValue {
			continue
		}

		key := line.Key
		path := []string{key} // Flat structure - key is at root level

		if encrypt {
			if p.shouldEncryptString(key, path, line.Value) {
				// Encrypt raw value (including quotes if present)
				ev, err := p.encryptPlaintext([]byte(line.Value), format.TypeString)
				if err != nil {
					return nil, false, fmt.Errorf("failed to encrypt %s: %w", key, err)
				}

				envFile.Lines[i].Value = format.FormatEncryptedValue(ev)
				modified = true
			}
		} else {
			// Decrypt if encrypted
			if format.IsEncrypted(line.Value) {
				ev, err := format.ParseEncryptedValue(line.Value)
				if err != nil {
					return nil, false, fmt.Errorf("failed to parse encrypted value for %s: %w", key, err)
				}

				plaintext, err := p.decryptAESGCM(ev.Data, ev.IV, ev.Tag)
				if err != nil {
					return nil, false, fmt.Errorf("failed to decrypt %s: %w", key, err)
				}

				// Decrypted value includes original quotes if they were present
				envFile.Lines[i].Value = string(plaintext)
				modified = true
			}
		}
	}

	return envFile, modified, nil
}

// processFullFile processes a file for full file encryption/decryption
func (p *Processor) processFullFile(content []byte, encrypt bool) ([]byte, bool, error) {
	if encrypt {
		// Check if already encrypted
		if format.IsFullFileEncrypted(content) {
			return content, false, nil
		}

		// Encrypt the entire content
		ev, err := p.encryptPlaintext(content, format.TypeBytes)
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

// transformData recursively transforms data for encryption/decryption
func (p *Processor) transformData(data *interface{}, path []string, encrypt bool) (bool, error) {
	modified := false

	switch v := (*data).(type) {
	case map[string]interface{}:
		for key, val := range v {
			currentPath := append(path, key)

			if IsLeafValue(val) {
				if encrypt {
					// Check if should encrypt and not already encrypted
					if p.shouldEncryptValue(key, currentPath, val) {
						encrypted, err := p.encryptValue(val)
						if err != nil {
							return false, fmt.Errorf("failed to encrypt %s: %w", strings.Join(currentPath, "."), err)
						}
						v[key] = encrypted
						modified = true
					}
				} else {
					// Decrypt if encrypted
					if s, ok := val.(string); ok && format.IsEncrypted(s) {
						decrypted, err := p.decryptValue(s)
						if err != nil {
							return false, fmt.Errorf("failed to decrypt %s: %w", strings.Join(currentPath, "."), err)
						}
						v[key] = decrypted
						modified = true
					}
				}
			} else if arr, ok := val.([]interface{}); ok && encrypt && p.matcher.ShouldEncrypt(key, currentPath) {
				// A matched key whose value is a list: encrypt the leaf items
				childModified, err := p.encryptMatchedSlice(arr, currentPath)
				if err != nil {
					return false, err
				}
				if childModified {
					modified = true
				}
			} else {
				// Recurse into nested structures
				childModified, err := p.transformData(&val, currentPath, encrypt)
				if err != nil {
					return false, err
				}
				if childModified {
					v[key] = val
					modified = true
				}
			}
		}

	case []interface{}:
		for i := range v {
			// Leaf list items are encrypted only under a matched key
			// (handled above), but any encrypted item must decrypt here
			if !encrypt {
				if s, ok := v[i].(string); ok && format.IsEncrypted(s) {
					decrypted, err := p.decryptValue(s)
					if err != nil {
						return false, fmt.Errorf("failed to decrypt %s: %w", strings.Join(path, "."), err)
					}
					v[i] = decrypted
					modified = true
					continue
				}
			}

			childModified, err := p.transformData(&v[i], path, encrypt)
			if err != nil {
				return false, err
			}
			if childModified {
				modified = true
			}
		}
	}

	return modified, nil
}

// encryptMatchedSlice encrypts the leaf items of a list whose key matched
// the encryption rules. Nested lists inherit the match; maps inside the
// list are traversed with normal key matching.
func (p *Processor) encryptMatchedSlice(arr []interface{}, path []string) (bool, error) {
	modified := false
	for i := range arr {
		switch item := arr[i].(type) {
		case []interface{}:
			childModified, err := p.encryptMatchedSlice(item, path)
			if err != nil {
				return false, err
			}
			if childModified {
				modified = true
			}
		case map[string]interface{}:
			childModified, err := p.transformData(&arr[i], path, true)
			if err != nil {
				return false, err
			}
			if childModified {
				modified = true
			}
		default:
			if s, ok := item.(string); ok && format.IsEncrypted(s) {
				continue
			}
			encrypted, err := p.encryptValue(item)
			if err != nil {
				return false, fmt.Errorf("failed to encrypt %s: %w", strings.Join(path, "."), err)
			}
			arr[i] = encrypted
			modified = true
		}
	}
	return modified, nil
}

// encryptValue encrypts a single value
func (p *Processor) encryptValue(val interface{}) (string, error) {
	valueType := format.DetectValueType(val)
	plaintext := format.ValueToString(val)

	ev, err := p.encryptPlaintext([]byte(plaintext), valueType)
	if err != nil {
		return "", err
	}

	return format.FormatEncryptedValue(ev), nil
}

func (p *Processor) encryptPlaintext(plaintext []byte, valueType format.ValueType) (*format.EncryptedValue, error) {
	if err := p.ensureEncryptionSetup(); err != nil {
		return nil, err
	}

	ciphertext, iv, tag, err := crypto.EncryptAESGCM(p.aesKey, plaintext)
	if err != nil {
		return nil, err
	}

	ev := &format.EncryptedValue{
		Data: ciphertext,
		IV:   iv,
		Tag:  tag,
		Type: valueType,
	}

	return ev, nil
}

// decryptValue decrypts a single ENC[...] value
func (p *Processor) decryptValue(encStr string) (interface{}, error) {
	ev, err := format.ParseEncryptedValue(encStr)
	if err != nil {
		return nil, err
	}

	plaintext, err := p.decryptAESGCM(ev.Data, ev.IV, ev.Tag)
	if err != nil {
		return nil, err
	}

	return format.StringToValue(string(plaintext), ev.Type)
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

	switch fileFormat {
	case FormatYAML:
		docs, err := decodeYAMLDocs(content)
		if err != nil {
			return nil, err
		}
		var results []MatchResult
		for _, node := range docs {
			p.collectUnencryptedYAMLNode(node, nil, &results)
		}
		return results, nil

	case FormatJSON:
		data, err := decodeJSON(content)
		if err != nil {
			return nil, err
		}
		var results []MatchResult
		p.collectUnencryptedData(data, nil, &results)
		return results, nil

	case FormatEnv:
		envFile, err := ParseEnvFile(content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse .env file: %w", err)
		}
		var results []MatchResult
		for _, line := range envFile.Lines {
			if line.Type != EnvLineKeyValue {
				continue
			}
			path := []string{line.Key}
			if p.shouldEncryptString(line.Key, path, line.Value) {
				results = append(results, MatchResult{
					Path:      path,
					KeyName:   line.Key,
					Value:     line.Value,
					Encrypted: false,
				})
			}
		}
		return results, nil

	default:
		return nil, fmt.Errorf("unsupported file format")
	}
}

func (p *Processor) collectUnencryptedYAMLNode(node *yaml.Node, path []string, results *[]MatchResult) {
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			p.collectUnencryptedYAMLNode(child, path, results)
		}

	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]
			key := keyNode.Value
			currentPath := clonePath(path, key)

			switch {
			case valueNode.Kind == yaml.ScalarNode:
				if p.shouldEncryptString(key, currentPath, valueNode.Value) {
					*results = append(*results, MatchResult{
						Path:      currentPath,
						KeyName:   key,
						Value:     valueNode.Value,
						Encrypted: false,
					})
				}

			case valueNode.Kind == yaml.SequenceNode && p.matcher.ShouldEncrypt(key, currentPath):
				p.collectUnencryptedMatchedYAMLSequence(valueNode, path, key, results)

			case valueNode.Kind == yaml.AliasNode && valueNode.Alias != nil && p.matcher.ShouldEncrypt(key, currentPath):
				if valueNode.Alias.Kind == yaml.ScalarNode && !format.IsEncrypted(valueNode.Alias.Value) {
					*results = append(*results, MatchResult{
						Path:      currentPath,
						KeyName:   key,
						Value:     valueNode.Alias.Value,
						Encrypted: false,
					})
				}

			default:
				p.collectUnencryptedYAMLNode(valueNode, currentPath, results)
			}
		}

	case yaml.SequenceNode:
		for _, item := range node.Content {
			p.collectUnencryptedYAMLNode(item, path, results)
		}
	}
}

// collectUnencryptedMatchedYAMLSequence reports unencrypted scalar items of
// a sequence whose key matched the encryption rules
func (p *Processor) collectUnencryptedMatchedYAMLSequence(node *yaml.Node, parentPath []string, key string, results *[]MatchResult) {
	for i, item := range node.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			if !format.IsEncrypted(item.Value) {
				*results = append(*results, MatchResult{
					Path:      clonePath(parentPath, fmt.Sprintf("%s[%d]", key, i)),
					KeyName:   key,
					Value:     item.Value,
					Encrypted: false,
				})
			}
		case yaml.SequenceNode:
			p.collectUnencryptedMatchedYAMLSequence(item, parentPath, fmt.Sprintf("%s[%d]", key, i), results)
		default:
			p.collectUnencryptedYAMLNode(item, clonePath(parentPath, key), results)
		}
	}
}

func (p *Processor) collectUnencryptedData(data interface{}, path []string, results *[]MatchResult) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, val := range v {
			currentPath := clonePath(path, key)

			if IsLeafValue(val) {
				if p.shouldEncryptValue(key, currentPath, val) {
					*results = append(*results, MatchResult{
						Path:      currentPath,
						KeyName:   key,
						Value:     val,
						Encrypted: false,
					})
				}
				continue
			}

			if arr, ok := val.([]interface{}); ok && p.matcher.ShouldEncrypt(key, currentPath) {
				p.collectUnencryptedMatchedSlice(arr, path, key, results)
				continue
			}

			p.collectUnencryptedData(val, currentPath, results)
		}

	case []interface{}:
		for _, item := range v {
			p.collectUnencryptedData(item, path, results)
		}
	}
}

// collectUnencryptedMatchedSlice reports unencrypted leaf items of a list
// whose key matched the encryption rules
func (p *Processor) collectUnencryptedMatchedSlice(arr []interface{}, parentPath []string, key string, results *[]MatchResult) {
	for i, item := range arr {
		switch nested := item.(type) {
		case []interface{}:
			p.collectUnencryptedMatchedSlice(nested, parentPath, fmt.Sprintf("%s[%d]", key, i), results)
		case map[string]interface{}:
			p.collectUnencryptedData(nested, clonePath(parentPath, key), results)
		default:
			if s, ok := item.(string); ok && format.IsEncrypted(s) {
				continue
			}
			*results = append(*results, MatchResult{
				Path:      clonePath(parentPath, fmt.Sprintf("%s[%d]", key, i)),
				KeyName:   key,
				Value:     item,
				Encrypted: false,
			})
		}
	}
}

func (p *Processor) shouldEncryptString(keyName string, path []string, value string) bool {
	return p.matcher.ShouldEncrypt(keyName, path) && !format.IsEncrypted(value)
}

func (p *Processor) shouldEncryptValue(keyName string, path []string, val interface{}) bool {
	if !p.matcher.ShouldEncrypt(keyName, path) {
		return false
	}
	if s, ok := val.(string); ok && format.IsEncrypted(s) {
		return false
	}
	return true
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

	var data interface{}

	switch fileFormat {
	case FormatYAML:
		values, err := decodeYAMLValues(content)
		if err != nil {
			return nil, err
		}
		data = values
	case FormatJSON:
		decoded, err := decodeJSON(content)
		if err != nil {
			return nil, err
		}
		data = decoded
	case FormatEnv:
		envFile, err := ParseEnvFile(content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse .env file: %w", err)
		}
		m := make(map[string]interface{})
		for _, line := range envFile.Lines {
			if line.Type == EnvLineKeyValue {
				m[line.Key] = line.Value
			}
		}
		data = m
	default:
		return nil, fmt.Errorf("unsupported file format")
	}

	return p.matcher.FindMatchingKeys(data), nil
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

	var data interface{}

	switch fileFormat {
	case FormatYAML:
		values, err := decodeYAMLValues(content)
		if err != nil {
			return nil, err
		}
		data = values
	case FormatJSON:
		decoded, err := decodeJSON(content)
		if err != nil {
			return nil, err
		}
		data = decoded
	case FormatEnv:
		envFile, err := ParseEnvFile(content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse .env file: %w", err)
		}
		// Convert to map[string]interface{} for collectEncryptedValues
		m := make(map[string]interface{})
		for _, line := range envFile.Lines {
			if line.Type == EnvLineKeyValue {
				m[line.Key] = line.Value
			}
		}
		data = m
	default:
		return nil, fmt.Errorf("unsupported file format")
	}

	// Collect all encrypted values in deterministic order
	encryptedValues := collectEncryptedValues(data, nil)
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

	var data interface{}
	switch fileFormat {
	case FormatYAML:
		values, err := decodeYAMLValues(content)
		if err != nil {
			return false, err
		}
		data = values
	case FormatJSON:
		decoded, err := decodeJSON(content)
		if err != nil {
			return false, err
		}
		data = decoded
	case FormatEnv:
		envFile, err := ParseEnvFile(content)
		if err != nil {
			return false, fmt.Errorf("failed to parse .env file: %w", err)
		}
		m := make(map[string]interface{})
		for _, line := range envFile.Lines {
			if line.Type == EnvLineKeyValue {
				m[line.Key] = line.Value
			}
		}
		data = m
	default:
		return false, fmt.Errorf("unsupported file format")
	}

	values := collectEncryptedValues(data, nil)
	return len(values) > 0, nil
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
	case ".json":
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

// marshalJSON marshals data to JSON, preserving indentation style from original
func marshalJSON(original []byte, data interface{}) ([]byte, error) {
	// Detect indentation from original
	indent := "  " // Default 2 spaces
	lines := strings.Split(string(original), "\n")
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if len(trimmed) > 0 && len(trimmed) < len(line) {
			indent = line[:len(line)-len(trimmed)]
			break
		}
	}

	output, err := json.MarshalIndent(data, "", indent)
	if err != nil {
		return nil, err
	}

	// Add trailing newline if original had one
	if len(original) > 0 && original[len(original)-1] == '\n' {
		output = append(output, '\n')
	}

	return output, nil
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
