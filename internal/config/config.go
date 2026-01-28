package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"gopkg.in/yaml.v3"

	"github.com/maurice2k/confcrypt/internal/crypto"
)

// Version is the current tool/config format version
var Version = "1.0.0" // Set by main package at startup

// Config represents the .confcrypt.yml configuration file
type Config struct {
	Recipients  []RecipientConfig  `yaml:"recipients"`
	Files       []string           `yaml:"files"`
	RenameFiles *RenameFilesConfig `yaml:"rename_files,omitempty"`
	KeysInclude []interface{}      `yaml:"keys_include"` // Can be string or KeyRule
	KeysExclude []interface{}      `yaml:"keys_exclude"` // Can be string or KeyRule
	Confcrypt   *ConfcryptSection  `yaml:".confcrypt,omitempty"`

	// Internal fields (not serialized)
	configPath string
	configDir  string
	rawNode    *yaml.Node // Preserve original YAML structure with comments
}

// RenameFilesConfig represents file renaming rules for encrypt/decrypt
type RenameFilesConfig struct {
	Encrypt []string `yaml:"encrypt,omitempty"`
	Decrypt []string `yaml:"decrypt,omitempty"`
}

// ConfcryptSection represents the .confcrypt metadata section
type ConfcryptSection struct {
	Version   string            `yaml:"version"`
	UpdatedAt string            `yaml:"updated_at"`
	Store     []SecretEntry     `yaml:"store"`
	MACs      map[string]string `yaml:"macs,omitempty"` // file path -> encrypted MAC
}

// RecipientConfig represents a recipient in the config
type RecipientConfig struct {
	Name    string `yaml:"name,omitempty"`
	Age     string `yaml:"age,omitempty"`     // Native age X25519 public key
	SSH     string `yaml:"ssh,omitempty"`     // SSH public key (ed25519, RSA)
	YubiKey string `yaml:"yubikey,omitempty"` // YubiKey-derived age key (age1yubikey1...)
	FIDO2   string `yaml:"fido2,omitempty"`   // FIDO2-derived age key (age1fido21...)
}

// SecretEntry represents an encrypted secret for a recipient
type SecretEntry struct {
	Recipient string `yaml:"recipient"`
	Secret    string `yaml:"secret"`
}

// KeyRule represents an explicit key matching rule
type KeyRule struct {
	Key     string `yaml:"key"`
	Type    string `yaml:"type"`              // "exact", "regex", "path"
	Options string `yaml:"options,omitempty"` // "-i" for case-sensitive regex (default is case-insensitive)
}

const DefaultConfigName = ".confcrypt.yml"

// Load loads the configuration from the specified path or searches for it
func Load(configPath string) (*Config, error) {
	if configPath == "" {
		// Search for config in current directory and parents
		var err error
		configPath, err = findConfig()
		if err != nil {
			return nil, err
		}
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", configPath, err)
	}

	// Parse as yaml.Node to preserve comments
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("failed to parse config file %q: %w", configPath, err)
	}

	// Decode into struct for easy access
	var config Config
	if err := node.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config file %q: %w", configPath, err)
	}

	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	config.configPath = absPath
	config.configDir = filepath.Dir(absPath)
	config.rawNode = &node

	return &config, nil
}

// findConfig searches for .confcrypt.yml in current directory and parents
func findConfig() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %w", err)
	}

	for {
		configPath := filepath.Join(dir, DefaultConfigName)
		if _, err := os.Stat(configPath); err == nil {
			return configPath, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("no %s found in current directory or any parent", DefaultConfigName)
}

// Save writes the config back to disk, preserving comments
func (c *Config) Save() error {
	// If we have the original node, sync changes and preserve comments
	if c.rawNode != nil {
		if err := c.syncToNode(); err != nil {
			return fmt.Errorf("failed to sync config to node: %w", err)
		}

		var buf strings.Builder
		encoder := yaml.NewEncoder(&buf)
		encoder.SetIndent(2)
		if err := encoder.Encode(c.rawNode); err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}
		encoder.Close()

		if err := os.WriteFile(c.configPath, []byte(buf.String()), 0644); err != nil {
			return fmt.Errorf("failed to write config file: %w", err)
		}
		return nil
	}

	// Fallback: no rawNode (e.g., newly created config), use standard marshal
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(c.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// syncToNode syncs the Config struct changes back into the rawNode
func (c *Config) syncToNode() error {
	if c.rawNode == nil {
		return nil
	}

	root := c.rawNode
	// Document nodes have content
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}

	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("expected mapping node at root")
	}

	// Sync recipients section
	if err := c.syncRecipientsSection(root); err != nil {
		return err
	}

	// Sync .confcrypt section
	if c.Confcrypt != nil {
		confcryptNode := findOrCreateMapKey(root, ".confcrypt")
		if confcryptNode == nil {
			return fmt.Errorf("failed to find/create .confcrypt section")
		}
		if err := c.syncConfcryptSection(confcryptNode); err != nil {
			return err
		}
	}

	return nil
}

// syncRecipientsSection syncs the Recipients list to the yaml.Node
func (c *Config) syncRecipientsSection(root *yaml.Node) error {
	recipientsNode := findOrCreateMapKey(root, "recipients")
	if recipientsNode == nil {
		return fmt.Errorf("failed to find/create recipients section")
	}

	recipientsNode.Kind = yaml.SequenceNode
	recipientsNode.Tag = "!!seq"
	recipientsNode.Content = nil

	for _, r := range c.Recipients {
		entryNode := &yaml.Node{
			Kind: yaml.MappingNode,
			Tag:  "!!map",
		}
		if r.Name != "" {
			setMapValue(entryNode, "name", r.Name)
		}
		if r.Age != "" {
			setMapValue(entryNode, "age", r.Age)
		}
		if r.SSH != "" {
			setMapValue(entryNode, "ssh", r.SSH)
		}
		if r.YubiKey != "" {
			setMapValue(entryNode, "yubikey", r.YubiKey)
		}
		if r.FIDO2 != "" {
			setMapValue(entryNode, "fido2", r.FIDO2)
		}
		recipientsNode.Content = append(recipientsNode.Content, entryNode)
	}

	return nil
}

// syncConfcryptSection syncs the Confcrypt struct to its yaml.Node
func (c *Config) syncConfcryptSection(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		// Convert to mapping node
		node.Kind = yaml.MappingNode
		node.Content = nil
	}

	// Update version
	setMapValue(node, "version", c.Confcrypt.Version)

	// Update updated_at
	setMapValue(node, "updated_at", c.Confcrypt.UpdatedAt)

	// Sync store (list of recipient/secret pairs)
	storeNode := findOrCreateMapKey(node, "store")
	if storeNode != nil {
		storeNode.Kind = yaml.SequenceNode
		storeNode.Tag = "!!seq"
		storeNode.Content = nil
		for _, entry := range c.Confcrypt.Store {
			entryNode := &yaml.Node{
				Kind: yaml.MappingNode,
				Tag:  "!!map",
			}
			setMapValue(entryNode, "recipient", entry.Recipient)
			setMapValue(entryNode, "secret", entry.Secret)
			storeNode.Content = append(storeNode.Content, entryNode)
		}
	}

	// Sync MACs
	if len(c.Confcrypt.MACs) > 0 {
		macsNode := findOrCreateMapKey(node, "macs")
		if macsNode != nil {
			macsNode.Kind = yaml.MappingNode
			macsNode.Tag = "!!map"
			macsNode.Content = nil
			for path, mac := range c.Confcrypt.MACs {
				keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: path}
				valNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: mac}
				macsNode.Content = append(macsNode.Content, keyNode, valNode)
			}
		}
	} else {
		// Remove macs section if empty
		removeMapKey(node, "macs")
	}

	return nil
}

// findOrCreateMapKey finds a key in a mapping node or creates it
func findOrCreateMapKey(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}

	// Search for existing key
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}

	// Create new key-value pair
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	node.Content = append(node.Content, keyNode, valNode)
	return valNode
}

// setMapValue sets a scalar value in a mapping node
// Automatically handles binary data by using !!binary tag with base64 encoding
func setMapValue(node *yaml.Node, key, value string) {
	if node.Kind != yaml.MappingNode {
		return
	}

	// Determine if value is valid UTF-8, if not use binary encoding
	tag := "!!str"
	nodeValue := value
	style := yaml.Style(0)

	if !utf8.ValidString(value) {
		// Binary data - use base64 encoding
		tag = "!!binary"
		nodeValue = base64.StdEncoding.EncodeToString([]byte(value))
		style = yaml.LiteralStyle // Use block style for readability
	}

	// Search for existing key
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			node.Content[i+1].Value = nodeValue
			node.Content[i+1].Kind = yaml.ScalarNode
			node.Content[i+1].Tag = tag
			node.Content[i+1].Style = style
			return
		}
	}

	// Create new key-value pair
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: nodeValue, Style: style}
	node.Content = append(node.Content, keyNode, valNode)
}

// removeMapKey removes a key from a mapping node
func removeMapKey(node *yaml.Node, key string) {
	if node.Kind != yaml.MappingNode {
		return
	}

	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			// Remove key and value
			node.Content = append(node.Content[:i], node.Content[i+2:]...)
			return
		}
	}
}

// GetRecipients returns parsed recipients (age or SSH keys)
func (c *Config) GetRecipients() ([]age.Recipient, error) {
	var recipients []age.Recipient
	for _, r := range c.Recipients {
		pubKey := r.GetPublicKey()
		if pubKey == "" {
			return nil, fmt.Errorf("recipient %q has no public key (age or ssh)", r.Name)
		}
		recipient, err := crypto.ParseRecipient(pubKey)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, recipient)
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipients configured")
	}
	return recipients, nil
}

// GetPublicKey returns the public key from either Age, YubiKey, FIDO2, or SSH field
func (r *RecipientConfig) GetPublicKey() string {
	if r.Age != "" {
		return r.Age
	}
	if r.YubiKey != "" {
		return r.YubiKey
	}
	if r.FIDO2 != "" {
		return r.FIDO2
	}
	return r.SSH
}

// GetKeyType returns the type of key configured for this recipient
func (r *RecipientConfig) GetKeyType() crypto.KeyType {
	if r.Age != "" {
		return crypto.KeyTypeAge
	}
	if r.YubiKey != "" {
		return crypto.KeyTypeYubiKey
	}
	if r.FIDO2 != "" {
		return crypto.KeyTypeFIDO2
	}
	if r.SSH != "" {
		return crypto.DetectKeyType(r.SSH)
	}
	return crypto.KeyTypeUnknown
}

// GetMatchingFiles returns all files matching the configured patterns
func (c *Config) GetMatchingFiles() ([]string, error) {
	var files []string
	seen := make(map[string]bool)

	for _, pattern := range c.Files {
		// Walk the config directory and match files
		err := filepath.Walk(c.configDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}

			// Skip the config file itself
			if path == c.configPath {
				return nil
			}

			// Skip any .confcrypt.yml or .confcrypt.yaml files
			filename := filepath.Base(path)
			if filename == ".confcrypt.yml" || filename == ".confcrypt.yaml" {
				return nil
			}

			// Get relative path from config dir
			relPath, err := filepath.Rel(c.configDir, path)
			if err != nil {
				return err
			}

			// Match against pattern
			matched, err := matchPattern(pattern, relPath)
			if err != nil {
				return fmt.Errorf("invalid pattern %q: %w", pattern, err)
			}

			if matched && !seen[path] {
				seen[path] = true
				files = append(files, path)
			}

			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return files, nil
}

// matchPattern checks if a file path matches a glob pattern
// Supports patterns like "*.yml" which match any yml file in any subdirectory
func matchPattern(pattern, path string) (bool, error) {
	// If pattern starts with *, it should match in any directory
	if len(pattern) > 0 && pattern[0] == '*' {
		// Match against filename only
		filename := filepath.Base(path)
		return filepath.Match(pattern, filename)
	}

	// Otherwise, match against full relative path
	return filepath.Match(pattern, path)
}

// GetSecretForRecipient returns the encrypted secret for a specific recipient
func (c *Config) GetSecretForRecipient(pubKey string) (string, bool) {
	if c.Confcrypt == nil {
		return "", false
	}
	for _, entry := range c.Confcrypt.Store {
		if entry.Recipient == pubKey {
			return entry.Secret, true
		}
	}
	return "", false
}

// FindRecipientByKey finds a recipient config by their public key (age, ssh, yubikey, or fido2)
func (c *Config) FindRecipientByKey(pubKey string) *RecipientConfig {
	for i := range c.Recipients {
		if c.Recipients[i].Age == pubKey || c.Recipients[i].SSH == pubKey || c.Recipients[i].YubiKey == pubKey || c.Recipients[i].FIDO2 == pubKey {
			return &c.Recipients[i]
		}
	}
	return nil
}

// SetSecrets updates the encrypted secrets for all recipients
func (c *Config) SetSecrets(secrets map[string]string) {
	if c.Confcrypt == nil {
		c.Confcrypt = &ConfcryptSection{}
	}
	c.Confcrypt.Version = Version
	c.Confcrypt.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	c.Confcrypt.Store = nil
	for pubKey, secret := range secrets {
		c.Confcrypt.Store = append(c.Confcrypt.Store, SecretEntry{
			Recipient: pubKey,
			Secret:    secret,
		})
	}
}

// GetMAC returns the MAC for a specific file
func (c *Config) GetMAC(filePath string) (string, bool) {
	if c.Confcrypt == nil || c.Confcrypt.MACs == nil {
		return "", false
	}
	mac, ok := c.Confcrypt.MACs[filePath]
	return mac, ok
}

// SetMAC sets the MAC for a specific file
func (c *Config) SetMAC(filePath, mac string) {
	if c.Confcrypt == nil {
		c.Confcrypt = &ConfcryptSection{}
	}
	c.Confcrypt.Version = Version
	if c.Confcrypt.MACs == nil {
		c.Confcrypt.MACs = make(map[string]string)
	}
	c.Confcrypt.MACs[filePath] = mac
}

// RemoveMAC removes the MAC for a specific file
func (c *Config) RemoveMAC(filePath string) {
	if c.Confcrypt == nil || c.Confcrypt.MACs == nil {
		return
	}
	delete(c.Confcrypt.MACs, filePath)
}

// HasSecrets returns true if there are encrypted secrets stored
func (c *Config) HasSecrets() bool {
	return c.Confcrypt != nil && len(c.Confcrypt.Store) > 0
}

// ClearSecrets removes all encrypted secrets from the store.
// This triggers a fresh AES key generation on the next encryption.
func (c *Config) ClearSecrets() {
	if c.Confcrypt != nil {
		c.Confcrypt.Store = nil
	}
}

// ConfigDir returns the directory containing the config file
func (c *Config) ConfigDir() string {
	return c.configDir
}

// ConfigPath returns the path to the config file
func (c *Config) ConfigPath() string {
	return c.configPath
}

// ParseKeyRules parses the keys_include or keys_exclude into KeyRule structs
func ParseKeyRules(rules []interface{}) ([]KeyRule, error) {
	var result []KeyRule

	for _, r := range rules {
		switch v := r.(type) {
		case string:
			// Auto-detect type based on format
			rule := KeyRule{Key: v}
			if len(v) >= 2 && v[0] == '/' && v[len(v)-1] == '/' {
				rule.Type = "regex"
			} else if len(v) > 0 && v[0] == '$' {
				rule.Type = "path"
			} else {
				rule.Type = "exact"
			}
			result = append(result, rule)

		case map[string]interface{}:
			// Explicit rule with key and type
			keyVal, ok := v["key"].(string)
			if !ok {
				return nil, fmt.Errorf("key rule missing 'key' field")
			}

			rule := KeyRule{Key: keyVal}

			if typeVal, ok := v["type"].(string); ok {
				rule.Type = typeVal
				// Validate type matches format when explicitly specified
				if err := validateKeyRuleType(rule); err != nil {
					return nil, err
				}
			} else {
				// Auto-detect if type not specified
				if len(keyVal) >= 2 && keyVal[0] == '/' && keyVal[len(keyVal)-1] == '/' {
					rule.Type = "regex"
				} else if len(keyVal) > 0 && keyVal[0] == '$' {
					rule.Type = "path"
				} else {
					rule.Type = "exact"
				}
			}

			// Parse options if present
			if optVal, ok := v["options"].(string); ok {
				rule.Options = optVal
			}

			result = append(result, rule)

		default:
			return nil, fmt.Errorf("invalid key rule type: %T", r)
		}
	}

	return result, nil
}

// validateKeyRuleType validates that explicit type matches the key format
func validateKeyRuleType(rule KeyRule) error {
	switch rule.Type {
	case "exact":
		// No validation needed - any key can be exact
		return nil
	case "regex":
		// Must be surrounded by /
		if len(rule.Key) < 2 || rule.Key[0] != '/' || rule.Key[len(rule.Key)-1] != '/' {
			return fmt.Errorf("key %q with type 'regex' must be surrounded by /", rule.Key)
		}
		return nil
	case "path":
		// Must start with $
		if len(rule.Key) == 0 || rule.Key[0] != '$' {
			return fmt.Errorf("key %q with type 'path' must start with $", rule.Key)
		}
		return nil
	default:
		return fmt.Errorf("invalid key rule type: %q (must be exact, regex, or path)", rule.Type)
	}
}

// ParseRenameRule parses a rename rule in /pattern/replacement/ format
// Returns the compiled regex and replacement string
func ParseRenameRule(rule string) (*regexp.Regexp, string, error) {
	if len(rule) < 3 || rule[0] != '/' {
		return nil, "", fmt.Errorf("rename rule must be in /pattern/replacement/ format")
	}

	// Find the second slash (end of pattern)
	// Handle escaped slashes in pattern
	patternEnd := -1
	for i := 1; i < len(rule); i++ {
		if rule[i] == '/' && (i == 1 || rule[i-1] != '\\') {
			patternEnd = i
			break
		}
	}

	if patternEnd == -1 {
		return nil, "", fmt.Errorf("rename rule must be in /pattern/replacement/ format: missing second /")
	}

	// Find the third slash (end of replacement)
	replacementEnd := -1
	for i := patternEnd + 1; i < len(rule); i++ {
		if rule[i] == '/' && (i == patternEnd+1 || rule[i-1] != '\\') {
			replacementEnd = i
			break
		}
	}

	if replacementEnd == -1 {
		return nil, "", fmt.Errorf("rename rule must be in /pattern/replacement/ format: missing third /")
	}

	pattern := rule[1:patternEnd]
	replacement := rule[patternEnd+1 : replacementEnd]

	// Compile the regex
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, "", fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
	}

	// Convert \1, \2 etc. to $1, $2 for Go's regexp replacement
	replacement = convertBackreferences(replacement)

	return re, replacement, nil
}

// convertBackreferences converts \1, \2, etc. to $1, $2 for Go regexp
func convertBackreferences(s string) string {
	result := strings.Builder{}
	i := 0
	for i < len(s) {
		if i+1 < len(s) && s[i] == '\\' {
			next := s[i+1]
			if next >= '0' && next <= '9' {
				// Convert \N to $N
				result.WriteByte('$')
				result.WriteByte(next)
				i += 2
				continue
			} else if next == '\\' {
				// Escaped backslash
				result.WriteByte('\\')
				i += 2
				continue
			}
		}
		result.WriteByte(s[i])
		i++
	}
	return result.String()
}

// ApplyRenameRules applies a list of rename rules to a filename
// Returns the renamed filename (rules are applied in order, first match wins)
func ApplyRenameRules(filename string, rules []string) (string, error) {
	for _, rule := range rules {
		re, replacement, err := ParseRenameRule(rule)
		if err != nil {
			return "", err
		}

		if re.MatchString(filename) {
			return re.ReplaceAllString(filename, replacement), nil
		}
	}
	return filename, nil
}

// GetEncryptRename returns the renamed path for encryption
// Applies rename_files.encrypt rules to the filename (basename only)
func (c *Config) GetEncryptRename(filePath string) (string, error) {
	if c.RenameFiles == nil || len(c.RenameFiles.Encrypt) == 0 {
		return filePath, nil
	}

	dir := filepath.Dir(filePath)
	base := filepath.Base(filePath)

	newBase, err := ApplyRenameRules(base, c.RenameFiles.Encrypt)
	if err != nil {
		return "", err
	}

	if newBase == base {
		return filePath, nil
	}

	return filepath.Join(dir, newBase), nil
}

// GetDecryptRename returns the renamed path for decryption
// Applies rename_files.decrypt rules to the filename (basename only)
func (c *Config) GetDecryptRename(filePath string) (string, error) {
	if c.RenameFiles == nil || len(c.RenameFiles.Decrypt) == 0 {
		return filePath, nil
	}

	dir := filepath.Dir(filePath)
	base := filepath.Base(filePath)

	newBase, err := ApplyRenameRules(base, c.RenameFiles.Decrypt)
	if err != nil {
		return "", err
	}

	if newBase == base {
		return filePath, nil
	}

	return filepath.Join(dir, newBase), nil
}
