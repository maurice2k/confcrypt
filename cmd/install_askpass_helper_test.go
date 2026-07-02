package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/maurice2k/confcrypt/internal/askpasshelper"
)

func TestResolveAskpassInstallPath_ExplicitFile(t *testing.T) {
	path, err := resolveAskpassInstallPath([]string{"/tmp/my-askpass"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/tmp/my-askpass" {
		t.Fatalf("expected explicit path to be used as-is, got %q", path)
	}
}

func TestResolveAskpassInstallPath_ExplicitDir(t *testing.T) {
	dir := t.TempDir()
	path, err := resolveAskpassInstallPath([]string{dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(dir, askpasshelper.ScriptName)
	if path != want {
		t.Fatalf("expected %q, got %q", want, path)
	}
}

func TestResolveAskpassInstallPath_DefaultsNextToBinary(t *testing.T) {
	path, err := resolveAskpassInstallPath(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filepath.Base(path) != askpasshelper.ScriptName {
		t.Fatalf("expected default path to end in %q, got %q", askpasshelper.ScriptName, path)
	}
	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("unexpected error resolving executable: %v", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		t.Fatalf("unexpected error resolving symlinks: %v", err)
	}
	if filepath.Dir(path) != filepath.Dir(exePath) {
		t.Fatalf("expected default path directory %q to match binary directory %q", filepath.Dir(path), filepath.Dir(exePath))
	}
}

func TestInstallAskpassScript_IsEmbedded(t *testing.T) {
	if len(askpasshelper.Script) == 0 {
		t.Fatal("expected embedded askpass script to be non-empty")
	}
	if got := string(askpasshelper.Script[:2]); got != "#!" {
		t.Fatalf("expected embedded script to start with a shebang, got %q", got)
	}
}
