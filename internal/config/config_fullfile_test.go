package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFilePattern(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		wantPattern string
		wantFormat  string
	}{
		{
			name:        "simple pattern",
			pattern:     "*.yml",
			wantPattern: "*.yml",
			wantFormat:  "",
		},
		{
			name:        "pattern with full format",
			pattern:     "*.txt:full",
			wantPattern: "*.txt",
			wantFormat:  "full",
		},
		{
			name:        "pattern with yaml format",
			pattern:     "config.txt:yaml",
			wantPattern: "config.txt",
			wantFormat:  "yaml",
		},
		{
			name:        "pattern with json format",
			pattern:     "*.dat:json",
			wantPattern: "*.dat",
			wantFormat:  "json",
		},
		{
			name:        "pattern with env format",
			pattern:     "*.cfg:env",
			wantPattern: "*.cfg",
			wantFormat:  "env",
		},
		{
			name:        "uppercase format normalized",
			pattern:     "*.txt:FULL",
			wantPattern: "*.txt",
			wantFormat:  "full",
		},
		{
			name:        "unknown format suffix treated as pattern",
			pattern:     "*.txt:unknown",
			wantPattern: "*.txt:unknown",
			wantFormat:  "",
		},
		{
			name:        "no colon",
			pattern:     "config.yaml",
			wantPattern: "config.yaml",
			wantFormat:  "",
		},
		{
			name:        "colon at start (drive letter on Windows)",
			pattern:     "C:*.yml",
			wantPattern: "C:*.yml",
			wantFormat:  "",
		},
		{
			name:        "multiple colons",
			pattern:     "path:to:file.txt:full",
			wantPattern: "path:to:file.txt",
			wantFormat:  "full",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := ParseFilePattern(tt.pattern)
			if fp.Pattern != tt.wantPattern {
				t.Errorf("Pattern = %q, want %q", fp.Pattern, tt.wantPattern)
			}
			if fp.Format != tt.wantFormat {
				t.Errorf("Format = %q, want %q", fp.Format, tt.wantFormat)
			}
		})
	}
}

func TestFormatOverridePrecedence(t *testing.T) {
	// Test that explicit format overrides take precedence regardless of pattern order
	dir := t.TempDir()

	// Create test files
	if err := os.WriteFile(filepath.Join(dir, "config.yml"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "release.yml"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		patterns    []string
		file        string
		wantFormat  string
		wantMatched bool
	}{
		{
			name:        "generic pattern first, specific with format second",
			patterns:    []string{"*.yml", "release.yml:full"},
			file:        "release.yml",
			wantFormat:  "full",
			wantMatched: true,
		},
		{
			name:        "specific with format first, generic second",
			patterns:    []string{"release.yml:full", "*.yml"},
			file:        "release.yml",
			wantFormat:  "full",
			wantMatched: true,
		},
		{
			name:        "file only matches generic pattern",
			patterns:    []string{"*.yml", "release.yml:full"},
			file:        "config.yml",
			wantFormat:  "",
			wantMatched: true,
		},
		{
			name:        "multiple format overrides - last one wins",
			patterns:    []string{"*.yml:yaml", "release.yml:full"},
			file:        "release.yml",
			wantFormat:  "full",
			wantMatched: true,
		},
		{
			name:        "no match",
			patterns:    []string{"*.yml"},
			file:        "data.json",
			wantFormat:  "",
			wantMatched: false,
		},
		{
			name:        "json with format override",
			patterns:    []string{"*.json", "data.json:full"},
			file:        "data.json",
			wantFormat:  "full",
			wantMatched: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create config with test patterns
			configContent := "recipients:\n  - name: Test\n    age: age1test\nfiles:\n"
			for _, p := range tt.patterns {
				configContent += "  - '" + p + "'\n"
			}
			configContent += "keys_include:\n  - password\n"

			configPath := filepath.Join(dir, ".confcrypt.yml")
			if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
				t.Fatal(err)
			}

			cfg, err := Load(configPath)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			filePath := filepath.Join(dir, tt.file)
			format, matched, err := cfg.MatchesFileWithFormat(filePath)
			if err != nil {
				t.Fatalf("MatchesFileWithFormat error: %v", err)
			}

			if matched != tt.wantMatched {
				t.Errorf("matched = %v, want %v", matched, tt.wantMatched)
			}
			if format != tt.wantFormat {
				t.Errorf("format = %q, want %q", format, tt.wantFormat)
			}
		})
	}
}

func TestConfcryptYmlNeverMatched(t *testing.T) {
	// Test that .confcrypt.yml is NEVER matched, even with patterns that would match it
	dir := t.TempDir()

	// Create test files including .confcrypt.yml
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".hidden.yml"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		patterns []string
	}{
		{
			name:     "wildcard yml",
			patterns: []string{"*.yml"},
		},
		{
			name:     "dot star yml",
			patterns: []string{".*.yml"},
		},
		{
			name:     "explicit confcrypt pattern",
			patterns: []string{".confcrypt.yml"},
		},
		{
			name:     "explicit confcrypt yaml",
			patterns: []string{".confcrypt.yaml"},
		},
		{
			name:     "star pattern",
			patterns: []string{"*"},
		},
		{
			name:     "dot star pattern",
			patterns: []string{".*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create config with test patterns
			configContent := "recipients:\n  - name: Test\n    age: age1test\nfiles:\n"
			for _, p := range tt.patterns {
				configContent += "  - '" + p + "'\n"
			}
			configContent += "keys_include:\n  - password\n"

			configPath := filepath.Join(dir, ".confcrypt.yml")
			if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
				t.Fatal(err)
			}

			cfg, err := Load(configPath)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			// Test MatchesFileWithFormat - should never match .confcrypt.yml
			_, matched, err := cfg.MatchesFileWithFormat(configPath)
			if err != nil {
				t.Fatalf("MatchesFileWithFormat error: %v", err)
			}
			if matched {
				t.Errorf("MatchesFileWithFormat matched .confcrypt.yml with pattern %v - this should NEVER happen", tt.patterns)
			}

			// Also test .confcrypt.yaml
			yamlPath := filepath.Join(dir, ".confcrypt.yaml")
			if err := os.WriteFile(yamlPath, []byte("test"), 0644); err != nil {
				t.Fatal(err)
			}
			_, matched, err = cfg.MatchesFileWithFormat(yamlPath)
			if err != nil {
				t.Fatalf("MatchesFileWithFormat error: %v", err)
			}
			if matched {
				t.Errorf("MatchesFileWithFormat matched .confcrypt.yaml with pattern %v - this should NEVER happen", tt.patterns)
			}

			// Test GetMatchingFilesWithFormat - should never include .confcrypt.yml
			files, err := cfg.GetMatchingFilesWithFormat()
			if err != nil {
				t.Fatalf("GetMatchingFilesWithFormat error: %v", err)
			}
			for _, f := range files {
				base := filepath.Base(f.Path)
				if base == ".confcrypt.yml" || base == ".confcrypt.yaml" {
					t.Errorf("GetMatchingFilesWithFormat returned %s with pattern %v - this should NEVER happen", base, tt.patterns)
				}
			}
		})
	}
}

func TestGetMatchingFilesWithFormatPrecedence(t *testing.T) {
	dir := t.TempDir()

	// Create test files
	if err := os.WriteFile(filepath.Join(dir, "config.yml"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "release.yml"), []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret.key"), []byte("key"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create config: *.yml matches first, release.yml:full should override
	configContent := `recipients:
  - name: Test
    age: age1test
files:
  - '*.yml'
  - 'release.yml:full'
  - '*.key'
keys_include:
  - password
`
	configPath := filepath.Join(dir, ".confcrypt.yml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	files, err := cfg.GetMatchingFilesWithFormat()
	if err != nil {
		t.Fatalf("GetMatchingFilesWithFormat error: %v", err)
	}

	// Build map for easier testing
	fileFormats := make(map[string]string)
	for _, f := range files {
		rel, _ := filepath.Rel(dir, f.Path)
		fileFormats[rel] = f.Format
	}

	// Check results
	if fileFormats["config.yml"] != "" {
		t.Errorf("config.yml format = %q, want empty", fileFormats["config.yml"])
	}
	if fileFormats["release.yml"] != "full" {
		t.Errorf("release.yml format = %q, want \"full\"", fileFormats["release.yml"])
	}
	if fileFormats["secret.key"] != "" {
		t.Errorf("secret.key format = %q, want empty", fileFormats["secret.key"])
	}
}
