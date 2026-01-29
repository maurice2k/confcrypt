package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/maurice2k/confcrypt/internal/config"
)

func TestResolveTarget_File(t *testing.T) {
	// Create temp directory structure:
	// tmpdir/
	//   .confcrypt.yml
	//   subdir/
	//     config.yml
	dir := t.TempDir()

	// Create config at root
	configPath := filepath.Join(dir, config.DefaultConfigName)
	configContent := `recipients:
  - name: test
    age: age1test123
files:
  - "*.yml"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Create subdir and file
	subdir := filepath.Join(dir, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("Failed to create subdir: %v", err)
	}

	testFile := filepath.Join(subdir, "config.yml")
	if err := os.WriteFile(testFile, []byte("key: value"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Test: file argument finds config upward
	gotConfigPath, gotSingleFile, err := ResolveTarget(testFile)
	if err != nil {
		t.Fatalf("ResolveTarget() error: %v", err)
	}

	if gotConfigPath != configPath {
		t.Errorf("ResolveTarget() configPath = %q, want %q", gotConfigPath, configPath)
	}

	// singleFile should be the absolute path to the file
	absTestFile, _ := filepath.Abs(testFile)
	if gotSingleFile != absTestFile {
		t.Errorf("ResolveTarget() singleFile = %q, want %q", gotSingleFile, absTestFile)
	}
}

func TestResolveTarget_Folder(t *testing.T) {
	// Create temp directory with config
	dir := t.TempDir()

	configPath := filepath.Join(dir, config.DefaultConfigName)
	configContent := `recipients:
  - name: test
    age: age1test123
files:
  - "*.yml"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Test: folder with config
	gotConfigPath, gotSingleFile, err := ResolveTarget(dir)
	if err != nil {
		t.Fatalf("ResolveTarget() error: %v", err)
	}

	if gotConfigPath != configPath {
		t.Errorf("ResolveTarget() configPath = %q, want %q", gotConfigPath, configPath)
	}

	if gotSingleFile != "" {
		t.Errorf("ResolveTarget() singleFile = %q, want empty string for folder", gotSingleFile)
	}
}

func TestResolveTarget_FolderNoConfig(t *testing.T) {
	// Create temp directory WITHOUT config
	dir := t.TempDir()

	// Test: folder without config should error
	_, _, err := ResolveTarget(dir)
	if err == nil {
		t.Errorf("ResolveTarget() expected error for folder without config, got nil")
	}
}

func TestResolveTarget_FileNotFound(t *testing.T) {
	// Test: non-existent file should error
	_, _, err := ResolveTarget("/nonexistent/path/file.yml")
	if err == nil {
		t.Errorf("ResolveTarget() expected error for non-existent file, got nil")
	}
}

func TestResolveTarget_FileNoConfig(t *testing.T) {
	// Create temp directory with file but no config
	dir := t.TempDir()

	testFile := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(testFile, []byte("key: value"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Test: file with no config in path should error
	_, _, err := ResolveTarget(testFile)
	if err == nil {
		t.Errorf("ResolveTarget() expected error when no config in path, got nil")
	}
}

func TestResolveTarget_NestedFolder(t *testing.T) {
	// Create structure:
	// tmpdir/
	//   .confcrypt.yml  <- root config
	//   subdir/
	//     .confcrypt.yml  <- subdir has its own config
	dir := t.TempDir()

	// Root config
	rootConfigPath := filepath.Join(dir, config.DefaultConfigName)
	if err := os.WriteFile(rootConfigPath, []byte("recipients: []\nfiles: []\n"), 0644); err != nil {
		t.Fatalf("Failed to write root config: %v", err)
	}

	// Subdir with its own config
	subdir := filepath.Join(dir, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("Failed to create subdir: %v", err)
	}

	subdirConfigPath := filepath.Join(subdir, config.DefaultConfigName)
	if err := os.WriteFile(subdirConfigPath, []byte("recipients: []\nfiles: []\n"), 0644); err != nil {
		t.Fatalf("Failed to write subdir config: %v", err)
	}

	// Test: targeting subdir should use subdir's config (not root)
	gotConfigPath, _, err := ResolveTarget(subdir)
	if err != nil {
		t.Fatalf("ResolveTarget() error: %v", err)
	}

	if gotConfigPath != subdirConfigPath {
		t.Errorf("ResolveTarget() should use subdir config, got %q, want %q", gotConfigPath, subdirConfigPath)
	}
}

func TestResolveTarget_FileInNestedDir(t *testing.T) {
	// Create structure:
	// tmpdir/
	//   .confcrypt.yml
	//   a/
	//     b/
	//       c/
	//         file.yml
	dir := t.TempDir()

	configPath := filepath.Join(dir, config.DefaultConfigName)
	if err := os.WriteFile(configPath, []byte("recipients: []\nfiles: []\n"), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	deepDir := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(deepDir, 0755); err != nil {
		t.Fatalf("Failed to create deep dir: %v", err)
	}

	testFile := filepath.Join(deepDir, "file.yml")
	if err := os.WriteFile(testFile, []byte("key: value"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Test: file deep in tree should find root config
	gotConfigPath, gotSingleFile, err := ResolveTarget(testFile)
	if err != nil {
		t.Fatalf("ResolveTarget() error: %v", err)
	}

	if gotConfigPath != configPath {
		t.Errorf("ResolveTarget() configPath = %q, want %q", gotConfigPath, configPath)
	}

	absTestFile, _ := filepath.Abs(testFile)
	if gotSingleFile != absTestFile {
		t.Errorf("ResolveTarget() singleFile = %q, want %q", gotSingleFile, absTestFile)
	}
}
