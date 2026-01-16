package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"gopkg.in/yaml.v3"

	"github.com/maurice2k/confcrypt/internal/crypto"
)

// Version is the config format version
const Version = "1.0.0"

// Config represents the .confcrypt.yml configuration file
type Config struct {
	Recipients  []RecipientConfig `yaml:"recipients"`
	Files       []string          `yaml:"files"`
	KeysInclude []interface{}     `yaml:"keys_include"` // Can be string or KeyRule
	KeysExclude []interface{}     `yaml:"keys_exclude"` // Can be string or KeyRule
	Confcrypt   *ConfcryptSection `yaml:".confcrypt,omitempty"`

	// Internal fields (not serialized)
	configPath string
	configDir  string
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
	Name string `yaml:"name,omitempty"`
	Age  string `yaml:"age"`
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

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %q: %w", configPath, err)
	}

	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	config.configPath = absPath
	config.configDir = filepath.Dir(absPath)

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

// Save writes the config back to disk
func (c *Config) Save() error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(c.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetRecipients returns parsed age recipients
func (c *Config) GetRecipients() ([]age.Recipient, error) {
	var recipients []age.Recipient
	for _, r := range c.Recipients {
		recipient, err := crypto.ParseAgeRecipient(r.Age)
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

// SetSecrets updates the encrypted secrets for all recipients
func (c *Config) SetSecrets(secrets map[string]string) {
	if c.Confcrypt == nil {
		c.Confcrypt = &ConfcryptSection{
			Version: Version,
		}
	}
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
		c.Confcrypt = &ConfcryptSection{
			Version: Version,
		}
	}
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
