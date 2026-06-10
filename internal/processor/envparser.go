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

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// A quoted value whose closing quote is not on the same line spans
		// multiple physical lines; merge them into one logical line so the
		// whole value is treated (and encrypted) as a unit instead of
		// leaving the continuation lines in plaintext
		if rawValue, ok := keyValueRawValue(line); ok && hasUnterminatedQuote(rawValue) {
			merged := line
			mergedValue := rawValue
			closed := false
			j := i
			for j+1 < len(lines) {
				j++
				merged += "\n" + lines[j]
				mergedValue += "\n" + lines[j]
				if !hasUnterminatedQuote(mergedValue) {
					closed = true
					break
				}
			}
			if closed {
				envFile.Lines = append(envFile.Lines, parseLine(merged))
				i = j
				continue
			}
			// No closing quote anywhere in the file - fall through and
			// treat the line as a single-line value
		}

		envFile.Lines = append(envFile.Lines, parseLine(line))
	}

	return envFile, nil
}

// keyValueRawValue extracts the raw value part of a key-value line, applying
// the same prefix handling as parseLine. Returns false for blank/comment or
// malformed lines.
func keyValueRawValue(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", false
	}

	workLine := trimmed
	if strings.HasPrefix(workLine, "export ") {
		workLine = strings.TrimSpace(strings.TrimPrefix(workLine, "export "))
	}

	eqIdx := strings.Index(workLine, "=")
	if eqIdx == -1 {
		return "", false
	}

	return workLine[eqIdx+1:], true
}

// hasUnterminatedQuote reports whether a raw value starts with a quote that
// is never closed (escaped double quotes don't count as closing)
func hasUnterminatedQuote(rawValue string) bool {
	if len(rawValue) == 0 || (rawValue[0] != '"' && rawValue[0] != '\'') {
		return false
	}
	quote := rawValue[0]
	for i := 1; i < len(rawValue); i++ {
		if rawValue[i] == quote {
			if quote == '"' && rawValue[i-1] == '\\' {
				continue
			}
			return false
		}
	}
	return true
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

	// Unquoted value - a comment starts only at a # preceded by whitespace;
	// a # embedded in the value (e.g. p@ss#w0rd) is part of the value
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			return strings.TrimRight(s[:i], " \t"), s[i:]
		}
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
