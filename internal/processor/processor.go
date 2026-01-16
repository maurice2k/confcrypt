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

// SetupDecryption prepares the processor for decryption
func (p *Processor) SetupDecryption(identities []age.Identity) error {
	p.identities = identities

	if !p.config.HasSecrets() {
		return fmt.Errorf("no encrypted secrets found in .confcrypt section")
	}

	// Find and decrypt the AES key
	for _, entry := range p.config.Confcrypt.Store {
		key, err := crypto.DecryptWithIdentities([]byte(entry.Secret), identities)
		if err == nil {
			p.aesKey = key
			return nil
		}
	}

	return fmt.Errorf("could not decrypt AES key with provided identities")
}

// SaveEncryptedSecrets encrypts the AES key for all recipients and saves to config
func (p *Processor) SaveEncryptedSecrets() error {
	secrets := make(map[string]string)

	for _, r := range p.config.Recipients {
		recipient, err := crypto.ParseAgeRecipient(r.Age)
		if err != nil {
			return err
		}

		encrypted, err := crypto.EncryptForRecipients(p.aesKey, []age.Recipient{recipient})
		if err != nil {
			return fmt.Errorf("failed to encrypt secret for %s: %w", r.Age, err)
		}

		secrets[r.Age] = string(encrypted)
	}

	p.config.SetSecrets(secrets)
	return p.config.Save()
}

// ProcessFile processes a single file for encryption or decryption
func (p *Processor) ProcessFile(filePath string, encrypt bool) ([]byte, bool, error) {
	fileFormat := DetectFormat(filePath)

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read file: %w", err)
	}

	var data interface{}
	var modified bool

	switch fileFormat {
	case FormatYAML:
		data, modified, err = p.processYAML(content, encrypt)
	case FormatJSON:
		data, modified, err = p.processJSON(content, encrypt)
	default:
		return nil, false, fmt.Errorf("unsupported file format")
	}

	if err != nil {
		return nil, false, err
	}

	if !modified {
		return content, false, nil
	}

	var output []byte
	switch fileFormat {
	case FormatYAML:
		output, err = marshalYAML(data)
	case FormatJSON:
		output, err = marshalJSON(content, data)
	}

	if err != nil {
		return nil, false, fmt.Errorf("failed to marshal output: %w", err)
	}

	return output, true, nil
}

// processYAML processes YAML content
func (p *Processor) processYAML(content []byte, encrypt bool) (interface{}, bool, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(content, &node); err != nil {
		return nil, false, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Convert to map for processing
	var data interface{}
	if err := node.Decode(&data); err != nil {
		return nil, false, fmt.Errorf("failed to decode YAML: %w", err)
	}

	modified, err := p.transformData(&data, nil, encrypt)
	if err != nil {
		return nil, false, err
	}

	return data, modified, nil
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
func (p *Processor) CheckFile(filePath string) ([]MatchResult, error) {
	fileFormat := DetectFormat(filePath)

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
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

// WriteFile writes content to a file
func (p *Processor) WriteFile(filePath string, content []byte) error {
	return os.WriteFile(filePath, content, 0644)
}

// ComputeMAC computes the MAC (SHA256 hash of all encrypted values) for a file
func (p *Processor) ComputeMAC(content []byte, fileFormat FileFormat) ([]byte, error) {
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
func (p *Processor) VerifyMAC(filePath string, content []byte) error {
	fileFormat := DetectFormat(filePath)

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
func (p *Processor) HasEncryptedValues(content []byte, filePath string) bool {
	fileFormat := DetectFormat(filePath)

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
	default:
		return false
	}

	values := collectEncryptedValues(data, nil)
	return len(values) > 0
}

// UpdateMAC computes and stores the MAC for a file
func (p *Processor) UpdateMAC(filePath string, content []byte) error {
	fileFormat := DetectFormat(filePath)

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

// DetectFormat determines the file format from extension
func DetectFormat(filePath string) FileFormat {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".json":
		return FormatJSON
	case ".yml", ".yaml":
		return FormatYAML
	default:
		return FormatYAML // Default to YAML
	}
}

// marshalYAML marshals data to YAML
func marshalYAML(data interface{}) ([]byte, error) {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(data); err != nil {
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
