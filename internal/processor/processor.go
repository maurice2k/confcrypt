package processor

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"gopkg.in/yaml.v3"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/crypto"
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
	config         *config.Config
	matcher        *Matcher
	aesKey         []byte
	recipients     []age.Recipient
	identities     []age.Identity
	identityLoader IdentityLoader
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

	return nil
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

// SaveEncryptedSecrets encrypts the AES key for all recipients and saves to config
func (p *Processor) SaveEncryptedSecrets() error {
	secrets := make(map[string]string)

	for _, r := range p.config.Recipients {
		pubKey := r.GetPublicKey()
		if pubKey == "" {
			return fmt.Errorf("recipient %q has no public key", r.Name)
		}

		recipient, err := crypto.ParseRecipient(pubKey)
		if err != nil {
			return err
		}

		encrypted, err := crypto.EncryptForRecipients(p.aesKey, []age.Recipient{recipient})
		if err != nil {
			return fmt.Errorf("failed to encrypt secret for %s: %w", pubKey, err)
		}

		secrets[pubKey] = string(encrypted)
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
		var node *yaml.Node
		node, modified, err = p.processYAMLNode(content, encrypt)
		if err != nil {
			return nil, false, err
		}
		if !modified {
			return content, false, nil
		}
		output, err = marshalYAMLNode(node)
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

// processYAMLNode processes YAML content while preserving comments
func (p *Processor) processYAMLNode(content []byte, encrypt bool) (*yaml.Node, bool, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(content, &node); err != nil {
		return nil, false, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Preserve blank lines from original before any modifications
	preserveBlankLines(&node)

	// Transform nodes in-place, preserving comments
	modified, err := p.transformYAMLNode(&node, nil, encrypt)
	if err != nil {
		return nil, false, err
	}

	return &node, modified, nil
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

			if valueNode.Kind == yaml.ScalarNode {
				// Leaf value - check if we should encrypt/decrypt
				if encrypt {
					if p.matcher.ShouldEncrypt(key, currentPath) {
						if !format.IsEncrypted(valueNode.Value) {
							encrypted, err := p.encryptScalarValue(valueNode.Value, valueNode.Tag)
							if err != nil {
								return false, fmt.Errorf("failed to encrypt %s: %w", strings.Join(currentPath, "."), err)
							}
							valueNode.Value = encrypted
							valueNode.Tag = "!!str"
							valueNode.Style = 0 // Reset style to let encoder choose
							modified = true
						}
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
			} else {
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
	}

	ciphertext, iv, tagBytes, err := crypto.EncryptAESGCM(p.aesKey, []byte(value))
	if err != nil {
		return "", err
	}

	ev := &format.EncryptedValue{
		Data: ciphertext,
		IV:   iv,
		Tag:  tagBytes,
		Type: valueType,
	}

	return format.FormatEncryptedValue(ev), nil
}

// decryptScalarValue decrypts an ENC[...] value and returns the plaintext and original YAML tag
func (p *Processor) decryptScalarValue(encStr string) (string, string, error) {
	ev, err := format.ParseEncryptedValue(encStr)
	if err != nil {
		return "", "", err
	}

	plaintext, err := crypto.DecryptAESGCM(p.aesKey, ev.Data, ev.IV, ev.Tag)
	if err != nil {
		return "", "", err
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
	}

	return string(plaintext), tag, nil
}

// processJSON processes JSON content
func (p *Processor) processJSON(content []byte, encrypt bool) (interface{}, bool, error) {
	var data interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		return nil, false, fmt.Errorf("failed to parse JSON: %w", err)
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
			if p.matcher.ShouldEncrypt(key, path) {
				if !format.IsEncrypted(line.Value) {
					// Encrypt raw value (including quotes if present)
					ciphertext, iv, tag, err := crypto.EncryptAESGCM(p.aesKey, []byte(line.Value))
					if err != nil {
						return nil, false, fmt.Errorf("failed to encrypt %s: %w", key, err)
					}

					ev := &format.EncryptedValue{
						Data: ciphertext,
						IV:   iv,
						Tag:  tag,
						Type: format.TypeString,
					}

					envFile.Lines[i].Value = format.FormatEncryptedValue(ev)
					modified = true
				}
			}
		} else {
			// Decrypt if encrypted
			if format.IsEncrypted(line.Value) {
				ev, err := format.ParseEncryptedValue(line.Value)
				if err != nil {
					return nil, false, fmt.Errorf("failed to parse encrypted value for %s: %w", key, err)
				}

				plaintext, err := crypto.DecryptAESGCM(p.aesKey, ev.Data, ev.IV, ev.Tag)
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
		ciphertext, iv, tag, err := crypto.EncryptAESGCM(p.aesKey, content)
		if err != nil {
			return nil, false, fmt.Errorf("failed to encrypt file: %w", err)
		}

		ev := &format.EncryptedValue{
			Data: ciphertext,
			IV:   iv,
			Tag:  tag,
			Type: format.TypeBytes,
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

	plaintext, err := crypto.DecryptAESGCM(p.aesKey, ev.Data, ev.IV, ev.Tag)
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
					if p.matcher.ShouldEncrypt(key, currentPath) {
						if s, ok := val.(string); ok && format.IsEncrypted(s) {
							continue // Already encrypted
						}
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

// encryptValue encrypts a single value
func (p *Processor) encryptValue(val interface{}) (string, error) {
	valueType := format.DetectValueType(val)
	plaintext := format.ValueToString(val)

	ciphertext, iv, tag, err := crypto.EncryptAESGCM(p.aesKey, []byte(plaintext))
	if err != nil {
		return "", err
	}

	ev := &format.EncryptedValue{
		Data: ciphertext,
		IV:   iv,
		Tag:  tag,
		Type: valueType,
	}

	return format.FormatEncryptedValue(ev), nil
}

// decryptValue decrypts a single ENC[...] value
func (p *Processor) decryptValue(encStr string) (interface{}, error) {
	ev, err := format.ParseEncryptedValue(encStr)
	if err != nil {
		return nil, err
	}

	plaintext, err := crypto.DecryptAESGCM(p.aesKey, ev.Data, ev.IV, ev.Tag)
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

	var data interface{}

	switch fileFormat {
	case FormatYAML:
		if err := yaml.Unmarshal(content, &data); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	case FormatJSON:
		if err := json.Unmarshal(content, &data); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	case FormatEnv:
		envFile, err := ParseEnvFile(content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse .env file: %w", err)
		}
		// Convert to map[string]interface{} for matcher
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

	results := p.matcher.FindMatchingKeys(data)

	// Filter to only unencrypted
	var unencrypted []MatchResult
	for _, r := range results {
		if !r.Encrypted {
			unencrypted = append(unencrypted, r)
		}
	}

	return unencrypted, nil
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
		if err := yaml.Unmarshal(content, &data); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	case FormatJSON:
		if err := json.Unmarshal(content, &data); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
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

// WriteFile writes content to a file
func (p *Processor) WriteFile(filePath string, content []byte) error {
	return os.WriteFile(filePath, content, 0644)
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
		if err := yaml.Unmarshal(content, &data); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	case FormatJSON:
		if err := json.Unmarshal(content, &data); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
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
			values = collectEncryptedValues(item, values)
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

	expectedHash, err := crypto.DecryptAESGCM(p.aesKey, ev.Data, ev.IV, ev.Tag)
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
		if err := yaml.Unmarshal(content, &data); err != nil {
			return false, fmt.Errorf("failed to parse YAML: %w", err)
		}
	case FormatJSON:
		if err := json.Unmarshal(content, &data); err != nil {
			return false, fmt.Errorf("failed to parse JSON: %w", err)
		}
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

	// For full file encryption, check if NOT encrypted (entire file should be encrypted)
	if fileFormat == FormatFull {
		return !format.IsFullFileEncrypted(content)
	}

	var data interface{}
	switch fileFormat {
	case FormatYAML:
		if err := yaml.Unmarshal(content, &data); err != nil {
			return false
		}
	case FormatJSON:
		if err := json.Unmarshal(content, &data); err != nil {
			return false
		}
	case FormatEnv:
		envFile, err := ParseEnvFile(content)
		if err != nil {
			return false
		}
		m := make(map[string]interface{})
		for _, line := range envFile.Lines {
			if line.Type == EnvLineKeyValue {
				m[line.Key] = line.Value
			}
		}
		data = m
	default:
		return false
	}

	return p.hasUnencryptedValuesRecursive(data, nil)
}

// hasUnencryptedValuesRecursive recursively checks for unencrypted values matching encryption rules
func (p *Processor) hasUnencryptedValuesRecursive(data interface{}, path []string) bool {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, val := range v {
			newPath := append(path, key)
			if p.hasUnencryptedValuesRecursive(val, newPath) {
				return true
			}
		}
	case []interface{}:
		for i, val := range v {
			newPath := append(path, fmt.Sprintf("[%d]", i))
			if p.hasUnencryptedValuesRecursive(val, newPath) {
				return true
			}
		}
	case string:
		// Check if this value should be encrypted but isn't
		keyName := ""
		if len(path) > 0 {
			keyName = path[len(path)-1]
		}
		if p.matcher.ShouldEncrypt(keyName, path) && !format.IsEncrypted(v) {
			return true
		}
	}
	return false
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

// marshalYAMLNode marshals a yaml.Node to YAML, preserving comments and structure
func marshalYAMLNode(node *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(node); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
func preserveBlankLines(node *yaml.Node) {
	preserveBlankLinesRecursive(node, 0)
}

// preserveBlankLinesRecursive walks the node tree and adds newlines to HeadComment
// where there are gaps in line numbers between siblings
func preserveBlankLinesRecursive(node *yaml.Node, prevEndLine int) int {
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
			keyEndLine := preserveBlankLinesRecursive(node.Content[i], childEndLine)
			valueEndLine := keyEndLine
			if i+1 < len(node.Content) {
				valueEndLine = preserveBlankLinesRecursive(node.Content[i+1], keyEndLine)
			}
			if keyEndLine > valueEndLine {
				childEndLine = keyEndLine
			} else {
				childEndLine = valueEndLine
			}
		}
	} else {
		for _, child := range node.Content {
			childEndLine = preserveBlankLinesRecursive(child, childEndLine)
		}
	}

	// The end line is the maximum of current node's line and its children's end line
	if childEndLine > currentEndLine {
		currentEndLine = childEndLine
	}

	currentEndLine += commentLineCount(node.FootComment)

	return currentEndLine
}

func commentLineCount(comment string) int {
	comment = strings.Trim(comment, "\n")
	if comment == "" {
		return 0
	}
	return strings.Count(comment, "\n") + 1
}
