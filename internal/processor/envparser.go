package processor

import (
	"strings"
)

// EnvLine represents a single line in an .env file
type EnvLine struct {
	Type    EnvLineType
	Key     string // For key-value pairs
	Value   string // Raw value after = (may include quotes)
	Raw     string // Original line content
	Comment string // Inline comment (not encrypted)
	Export  bool   // Whether line had "export " prefix
}

// EnvLineType represents the type of line in an .env file
type EnvLineType int

const (
	EnvLineBlank EnvLineType = iota
	EnvLineComment
	EnvLineKeyValue
)

// EnvFile represents a parsed .env file preserving structure
type EnvFile struct {
	Lines []EnvLine
}

// ParseEnvFile parses .env file content preserving structure
func ParseEnvFile(content []byte) (*EnvFile, error) {
	lines := strings.Split(string(content), "\n")
	envFile := &EnvFile{
		Lines: make([]EnvLine, 0, len(lines)),
	}

	for _, line := range lines {
		envLine := parseLine(line)
		envFile.Lines = append(envFile.Lines, envLine)
	}

	return envFile, nil
}

// parseLine parses a single .env line
func parseLine(line string) EnvLine {
	raw := line
	trimmed := strings.TrimSpace(line)

	// Empty line
	if trimmed == "" {
		return EnvLine{Type: EnvLineBlank, Raw: raw}
	}

	// Comment line
	if strings.HasPrefix(trimmed, "#") {
		return EnvLine{Type: EnvLineComment, Raw: raw, Comment: trimmed}
	}

	// Key-value pair
	workLine := trimmed
	hasExport := false

	// Handle "export " prefix
	if strings.HasPrefix(workLine, "export ") {
		hasExport = true
		workLine = strings.TrimPrefix(workLine, "export ")
		workLine = strings.TrimSpace(workLine)
	}

	// Find the = separator
	eqIdx := strings.Index(workLine, "=")
	if eqIdx == -1 {
		// No = found, treat as comment/invalid
		return EnvLine{Type: EnvLineComment, Raw: raw, Comment: trimmed}
	}

	key := strings.TrimSpace(workLine[:eqIdx])
	rawValue := workLine[eqIdx+1:]

	// Find inline comment (quote-aware)
	value, inlineComment := splitValueAndComment(rawValue)

	return EnvLine{
		Type:    EnvLineKeyValue,
		Key:     key,
		Value:   value,
		Raw:     raw,
		Export:  hasExport,
		Comment: inlineComment,
	}
}

// splitValueAndComment splits a raw value from its inline comment
// It's quote-aware: # inside quotes is not a comment
func splitValueAndComment(s string) (value, comment string) {
	if len(s) == 0 {
		return "", ""
	}

	// Check if value starts with a quote
	if s[0] == '"' || s[0] == '\'' {
		quote := s[0]
		// Find closing quote (handle escaped quotes for double quotes)
		for i := 1; i < len(s); i++ {
			if s[i] == quote {
				// For double quotes, check if escaped
				if quote == '"' && i > 0 && s[i-1] == '\\' {
					continue
				}
				// Found closing quote
				// Everything up to and including closing quote is the value
				// Check for inline comment after
				rest := s[i+1:]
				restTrimmed := strings.TrimSpace(rest)
				if strings.HasPrefix(restTrimmed, "#") {
					// Find where the comment starts in rest
					commentStart := strings.Index(rest, "#")
					return s[:i+1], rest[commentStart:]
				}
				return s[:i+1], ""
			}
		}
		// No closing quote found - take entire string as value
		return s, ""
	}

	// Unquoted value - look for # comment marker
	// Check for " #" first (space before #)
	if idx := strings.Index(s, " #"); idx >= 0 {
		return strings.TrimRight(s[:idx], " \t"), s[idx+1:]
	}

	// Check for "#" without space (less common)
	if idx := strings.Index(s, "#"); idx > 0 {
		return strings.TrimRight(s[:idx], " \t"), s[idx:]
	}

	return s, ""
}

// Get returns the value for a key, or empty string if not found
func (e *EnvFile) Get(key string) (string, bool) {
	for _, line := range e.Lines {
		if line.Type == EnvLineKeyValue && line.Key == key {
			return line.Value, true
		}
	}
	return "", false
}

// Set updates the value for a key
func (e *EnvFile) Set(key, value string) bool {
	for i, line := range e.Lines {
		if line.Type == EnvLineKeyValue && line.Key == key {
			e.Lines[i].Value = value
			return true
		}
	}
	return false
}

// Marshal converts the EnvFile back to bytes, preserving structure
func (e *EnvFile) Marshal() []byte {
	var lines []string

	for _, line := range e.Lines {
		switch line.Type {
		case EnvLineBlank, EnvLineComment:
			lines = append(lines, line.Raw)
		case EnvLineKeyValue:
			lines = append(lines, formatEnvLine(line))
		}
	}

	return []byte(strings.Join(lines, "\n"))
}

// formatEnvLine formats a key-value line back to string
func formatEnvLine(line EnvLine) string {
	var sb strings.Builder

	// Preserve leading whitespace from original
	if idx := strings.Index(line.Raw, strings.TrimSpace(line.Raw)); idx > 0 {
		sb.WriteString(line.Raw[:idx])
	}

	if line.Export {
		sb.WriteString("export ")
	}

	sb.WriteString(line.Key)
	sb.WriteString("=")
	sb.WriteString(line.Value)

	// Add inline comment if present
	if line.Comment != "" {
		sb.WriteString(" ")
		sb.WriteString(line.Comment)
	}

	return sb.String()
}

// Keys returns all key names in the file (in order)
func (e *EnvFile) Keys() []string {
	var keys []string
	for _, line := range e.Lines {
		if line.Type == EnvLineKeyValue {
			keys = append(keys, line.Key)
		}
	}
	return keys
}

// ToMap returns a map of all key-value pairs
func (e *EnvFile) ToMap() map[string]string {
	m := make(map[string]string)
	for _, line := range e.Lines {
		if line.Type == EnvLineKeyValue {
			m[line.Key] = line.Value
		}
	}
	return m
}
