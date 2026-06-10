// Package fileutil provides crash-safe file write helpers.
package fileutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to filePath atomically by writing to a
// temporary file in the same directory, syncing it, and renaming it over
// the target. If the target already exists its permissions are preserved;
// otherwise defaultMode is used. A crash mid-write can never leave a
// truncated or partially written target file.
func WriteFileAtomic(filePath string, data []byte, defaultMode os.FileMode) error {
	mode := defaultMode
	if fi, err := os.Stat(filePath); err == nil {
		mode = fi.Mode().Perm()
	}

	dir := filepath.Dir(filePath)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(filePath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	cleanup := func() {
		tmp.Close()
		os.Remove(tmpPath)
	}

	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return fmt.Errorf("failed to set permissions on temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("failed to sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}
	return nil
}
