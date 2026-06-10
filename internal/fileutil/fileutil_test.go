package fileutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicCreatesWithDefaultMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.txt")

	if err := WriteFileAtomic(path, []byte("hello"), 0644); err != nil {
		t.Fatalf("WriteFileAtomic failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("Expected content %q, got %q", "hello", string(data))
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if fi.Mode().Perm() != 0644 {
		t.Errorf("Expected mode 0644, got %o", fi.Mode().Perm())
	}
}

func TestWriteFileAtomicPreservesExistingMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")

	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := WriteFileAtomic(path, []byte("new"), 0644); err != nil {
		t.Fatalf("WriteFileAtomic failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(data) != "new" {
		t.Errorf("Expected content %q, got %q", "new", string(data))
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("Expected mode 0600 to be preserved, got %o", fi.Mode().Perm())
	}
}

func TestWriteFileAtomicLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	if err := WriteFileAtomic(path, []byte("data"), 0644); err != nil {
		t.Fatalf("WriteFileAtomic failed: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "out.txt" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("Expected only out.txt in dir, got %v", names)
	}
}
