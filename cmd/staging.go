package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/processor"
)

// stagedWrite is one fully processed output file, held in memory until the
// key store has been persisted. Staging all outputs before touching the
// working tree guarantees that no ciphertext ever reaches disk while the key
// that produced it exists only in memory, and that a failure mid-run leaves
// the tree untouched instead of half-processed.
type stagedWrite struct {
	originalPath string
	outputPath   string // equals originalPath unless a rename rule applies
	content      []byte
	format       string
}

// stageMACs records the MAC for every staged output in the in-memory config,
// so MACs can be persisted together with (or before) the file writes.
func stageMACs(proc *processor.Processor, stages []stagedWrite) error {
	for _, s := range stages {
		if err := proc.UpdateMAC(s.outputPath, s.content, s.format); err != nil {
			return fmt.Errorf("updating MAC for %s: %w", s.outputPath, err)
		}
	}
	return nil
}

// writeStagedFiles writes all staged outputs atomically and removes renamed
// originals only after their replacement is on disk. onWritten, if non-nil,
// is called after each successful write (for progress output).
func writeStagedFiles(proc *processor.Processor, stages []stagedWrite, onWritten func(stagedWrite)) error {
	for _, s := range stages {
		if err := proc.WriteFile(s.outputPath, s.content); err != nil {
			return fmt.Errorf("writing %s: %w", s.outputPath, err)
		}
		if s.outputPath != s.originalPath {
			if err := os.Remove(s.originalPath); err != nil {
				return fmt.Errorf("removing original file %s: %w", s.originalPath, err)
			}
		}
		if onWritten != nil {
			onWritten(s)
		}
	}
	return nil
}

// cleanupStaleMACs removes MACs of files that will no longer exist once the
// staged writes (including renames) are applied. Returns true if any MAC was
// removed; the caller is responsible for saving the config.
func cleanupStaleMACs(cfg *config.Config, stages []stagedWrite) bool {
	if cfg.Confcrypt == nil || cfg.Confcrypt.MACs == nil {
		return false
	}

	allMatchingFiles, err := cfg.GetMatchingFiles()
	if err != nil {
		return false
	}

	validPaths := make(map[string]bool)
	for _, absPath := range allMatchingFiles {
		relPath, _ := filepath.Rel(cfg.ConfigDir(), absPath)
		if relPath != "" {
			validPaths[relPath] = true
		}
	}

	// Account for staged renames that are not on disk yet
	for _, s := range stages {
		if s.outputPath == s.originalPath {
			continue
		}
		if origRel, _ := filepath.Rel(cfg.ConfigDir(), s.originalPath); origRel != "" {
			delete(validPaths, origRel)
		}
		if outRel, _ := filepath.Rel(cfg.ConfigDir(), s.outputPath); outRel != "" {
			validPaths[outRel] = true
		}
	}

	removed := false
	for macPath := range cfg.Confcrypt.MACs {
		if !validPaths[macPath] {
			cfg.RemoveMAC(macPath)
			removed = true
		}
	}
	return removed
}

// performRekey rotates the AES key: it decrypts all encrypted files in
// memory, generates a fresh key, persists a transitional store containing
// both the old and the new key, then atomically rewrites all files and
// finally drops the old key from the store. An interruption at any point
// leaves every file decryptable with one of the keys on disk; re-running
// rekey (or decrypt) recovers automatically. Plaintext is never written to
// disk. Returns the config-relative paths of the rekeyed files.
func performRekey(cfg *config.Config, identities []age.Identity) ([]string, error) {
	identityLoader := func() ([]age.Identity, error) {
		return LoadDecryptionIdentity(cfg, "", "", false, false)
	}

	proc, err := processor.NewProcessor(cfg, identityLoader)
	if err != nil {
		return nil, err
	}

	if _, err := proc.SetupDecryption(identities); err != nil {
		return nil, fmt.Errorf("setting up decryption: %w", err)
	}

	filesWithFormat, err := cfg.GetMatchingFilesWithFormat()
	if err != nil {
		return nil, err
	}

	// Decrypt all encrypted files in memory
	type rekeyFile struct {
		path      string
		format    string
		plaintext []byte
	}
	var rekeyFiles []rekeyFile
	for _, f := range filesWithFormat {
		content, err := os.ReadFile(f.Path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f.Path, err)
		}

		if !proc.HasEncryptedValues(content, f.Path, f.Format) {
			continue
		}

		fileFormat := processor.DetectFormat(f.Path, f.Format)
		plaintext, _, err := proc.ProcessContent(content, f.Path, false, fileFormat)
		if err != nil {
			return nil, fmt.Errorf("decrypting %s: %w", f.Path, err)
		}
		rekeyFiles = append(rekeyFiles, rekeyFile{path: f.Path, format: f.Format, plaintext: plaintext})
	}

	// Generate the new key on a fresh processor (an empty store forces key
	// generation; the old entries are restored below for the transition)
	oldStore := cfg.Confcrypt.Store
	cfg.Confcrypt.Store = nil
	proc2, err := processor.NewProcessor(cfg, identityLoader)
	if err != nil {
		cfg.Confcrypt.Store = oldStore
		return nil, err
	}
	if err := proc2.SetupEncryption(); err != nil {
		cfg.Confcrypt.Store = oldStore
		return nil, fmt.Errorf("setting up encryption with new key: %w", err)
	}
	newSecrets, err := proc2.EncryptStoreEntries()
	if err != nil {
		cfg.Confcrypt.Store = oldStore
		return nil, err
	}

	if len(rekeyFiles) == 0 {
		// Nothing on disk uses the old key; switch to the new key directly
		cfg.SetSecrets(newSecrets)
		if err := cfg.Save(); err != nil {
			return nil, fmt.Errorf("saving config: %w", err)
		}
		return nil, nil
	}

	// Re-encrypt in memory and stage all writes
	var stages []stagedWrite
	for _, rf := range rekeyFiles {
		fileFormat := processor.DetectFormat(rf.path, rf.format)
		output, _, err := proc2.ProcessContent(rf.plaintext, rf.path, true, fileFormat)
		if err != nil {
			cfg.Confcrypt.Store = oldStore
			return nil, fmt.Errorf("re-encrypting %s: %w", rf.path, err)
		}
		stages = append(stages, stagedWrite{
			originalPath: rf.path,
			outputPath:   rf.path,
			content:      output,
			format:       rf.format,
		})
	}

	if err := stageMACs(proc2, stages); err != nil {
		cfg.Confcrypt.Store = oldStore
		return nil, err
	}

	// Persist the transitional store (old + new key) and the new MACs
	// before any file is rewritten
	cfg.Confcrypt.Store = oldStore
	cfg.AddSecrets(newSecrets)
	if err := cfg.Save(); err != nil {
		return nil, fmt.Errorf("saving transitional key store: %w", err)
	}

	relPaths := make([]string, 0, len(stages))
	if err := writeStagedFiles(proc2, stages, func(s stagedWrite) {
		relPath, _ := filepath.Rel(cfg.ConfigDir(), s.outputPath)
		if relPath == "" {
			relPath = s.outputPath
		}
		relPaths = append(relPaths, relPath)
	}); err != nil {
		return relPaths, err
	}

	// All files now use the new key; drop the old key from the store
	cfg.SetSecrets(newSecrets)
	if err := cfg.Save(); err != nil {
		return relPaths, fmt.Errorf("saving config: %w", err)
	}

	return relPaths, nil
}
