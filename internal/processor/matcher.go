package processor

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/doc"
	"github.com/maurice2k/confcrypt/internal/format"
)

// Matcher handles key matching logic for encryption
type Matcher struct {
	includeRules []compiledRule
	excludeRules []compiledRule
}

// compiledRule is a pre-compiled matching rule
type compiledRule struct {
	original      config.KeyRule
	regex         *regexp.Regexp // For regex type
	path          []string       // For path type (split segments)
	absolute      bool           // For path type: true if starts with $.
	caseSensitive bool           // For regex type: true if options contains "-i"
}

// NewMatcher creates a new Matcher from include and exclude rules
func NewMatcher(include, exclude []config.KeyRule) (*Matcher, error) {
	m := &Matcher{}

	for _, rule := range include {
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("invalid include rule %q: %w", rule.Key, err)
		}
		m.includeRules = append(m.includeRules, compiled)
	}

	for _, rule := range exclude {
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude rule %q: %w", rule.Key, err)
		}
		m.excludeRules = append(m.excludeRules, compiled)
	}

	return m, nil
}

// compileRule compiles a KeyRule into a compiledRule
func compileRule(rule config.KeyRule) (compiledRule, error) {
	compiled := compiledRule{original: rule}

	switch rule.Type {
	case "exact":
		// No compilation needed
		return compiled, nil

	case "regex":
		// Extract pattern from /pattern/
		if len(rule.Key) < 2 || rule.Key[0] != '/' || rule.Key[len(rule.Key)-1] != '/' {
			return compiled, fmt.Errorf("regex pattern must be surrounded by /")
		}
		pattern := rule.Key[1 : len(rule.Key)-1]

		// Check if case-sensitive mode is requested via options: "-i"
		// Default is case-insensitive (prepend (?i) to pattern)
		caseSensitive := strings.Contains(rule.Options, "-i")
		compiled.caseSensitive = caseSensitive

		if !caseSensitive {
			pattern = "(?i)" + pattern
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			return compiled, fmt.Errorf("invalid regex: %w", err)
		}
		compiled.regex = re
		return compiled, nil

	case "path":
		// Parse path like $db.password or $.db.password
		if len(rule.Key) == 0 || rule.Key[0] != '$' {
			return compiled, fmt.Errorf("path must start with $")
		}

		pathStr := rule.Key[1:] // Remove leading $
		if strings.HasPrefix(pathStr, ".") {
			compiled.absolute = true
			pathStr = pathStr[1:] // Remove leading .
		}

		if pathStr == "" {
			return compiled, fmt.Errorf("path cannot be empty")
		}

		compiled.path = strings.Split(pathStr, ".")
		return compiled, nil

	default:
		return compiled, fmt.Errorf("unknown rule type: %q", rule.Type)
	}
}

// ShouldEncrypt checks if a key at the given path should be encrypted
// keyName is the name of the key being checked
// path is the full path to the key (e.g., ["db", "connection", "password"])
func (m *Matcher) ShouldEncrypt(keyName string, path []string) bool {
	// Check if any include rule matches
	included := false
	for _, rule := range m.includeRules {
		if matchRule(rule, keyName, path) {
			included = true
			break
		}
	}

	if !included {
		return false
	}

	// Check if any exclude rule matches (exclude takes precedence)
	for _, rule := range m.excludeRules {
		if matchRule(rule, keyName, path) {
			return false
		}
	}

	return true
}

// matchRule checks if a single rule matches the key
func matchRule(rule compiledRule, keyName string, path []string) bool {
	switch rule.original.Type {
	case "exact":
		return keyName == rule.original.Key

	case "regex":
		return rule.regex.MatchString(keyName)

	case "path":
		return matchPath(rule.path, rule.absolute, path)

	default:
		return false
	}
}

// matchPath checks if a path pattern matches the actual path
// pattern: the path segments to match (e.g., ["db", "password"])
// absolute: if true, pattern must match from root; if false, can match anywhere
// path: the actual path to the key (e.g., ["api", "db", "password"])
func matchPath(pattern []string, absolute bool, path []string) bool {
	if len(pattern) > len(path) {
		return false
	}

	if absolute {
		// Must match from the beginning
		if len(pattern) != len(path) {
			return false
		}
		for i, p := range pattern {
			if p != path[i] {
				return false
			}
		}
		return true
	}

	// Relative: find pattern as a suffix of path
	// e.g., pattern ["db", "password"] matches path ["api", "db", "password"]
	offset := len(path) - len(pattern)
	for i, p := range pattern {
		if p != path[offset+i] {
			return false
		}
	}
	return true
}

// MatchResult represents the result of checking a value for encryption
type MatchResult struct {
	Path      []string // Full path to the key
	KeyName   string   // Name of the key
	Value     string   // Textual value (empty for containers)
	Encrypted bool     // Whether the value is already encrypted
}

// FindMatchingKeys walks a document and reports every value the rules
// select, encrypted or not. Aliases are only followed when their key
// matched, mirroring the encryption walk.
func (m *Matcher) FindMatchingKeys(root doc.Node) []MatchResult {
	var results []MatchResult
	m.traverse(root, nil, &results)
	return results
}

func (m *Matcher) traverse(node doc.Node, path []string, results *[]MatchResult) {
	if node == nil {
		return
	}
	switch node.Kind() {
	case doc.Mapping:
		for i := 0; i < node.Len(); i++ {
			key := node.Key(i)
			value := node.Item(i)
			currentPath := clonePath(path, key)
			matched := m.ShouldEncrypt(key, currentPath)

			if value.IsAlias() {
				if !matched {
					continue
				}
				value = value.Target()
			}

			switch {
			case value.Kind() == doc.Scalar:
				if matched {
					*results = append(*results, MatchResult{
						Path:      currentPath,
						KeyName:   key,
						Value:     value.Value(),
						Encrypted: format.IsEncrypted(value.Value()),
					})
				}
			case matched && value.Kind() == doc.Sequence:
				// A matched key whose value is a list: report the leaf items
				m.traverseMatchedSequence(value, path, key, results)
			default:
				m.traverse(value, currentPath, results)
			}
		}

	case doc.Sequence:
		for i := 0; i < node.Len(); i++ {
			item := node.Item(i)
			if item.IsAlias() {
				continue
			}
			// Lists don't add to the path, but mappings inside them are visited
			m.traverse(item, path, results)
		}
	}
}

// traverseMatchedSequence reports the leaf items of a list whose key matched
func (m *Matcher) traverseMatchedSequence(node doc.Node, parentPath []string, key string, results *[]MatchResult) {
	for i := 0; i < node.Len(); i++ {
		item := node.Item(i)
		if item.IsAlias() {
			continue
		}
		switch item.Kind() {
		case doc.Sequence:
			m.traverseMatchedSequence(item, parentPath, fmt.Sprintf("%s[%d]", key, i), results)
		case doc.Mapping:
			m.traverse(item, clonePath(parentPath, key), results)
		default:
			*results = append(*results, MatchResult{
				Path:      clonePath(parentPath, fmt.Sprintf("%s[%d]", key, i)),
				KeyName:   key,
				Value:     item.Value(),
				Encrypted: format.IsEncrypted(item.Value()),
			})
		}
	}
}

// clonePath appends a path element without aliasing the parent's backing array
func clonePath(path []string, key string) []string {
	currentPath := make([]string, len(path)+1)
	copy(currentPath, path)
	currentPath[len(path)] = key
	return currentPath
}
