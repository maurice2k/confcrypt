package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeAskpassScript writes a shell script that prints the given value
// followed by a newline, ignoring its argv[1] prompt, and returns its path.
func writeAskpassScript(t *testing.T, value string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("askpass scripts require a POSIX shell")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "askpass.sh")
	script := "#!/bin/sh\necho '" + value + "'\n"
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write askpass script: %v", err)
	}
	return path
}

func clearAskpassEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"CONFCRYPT_ASKPASS", "CONFCRYPT_ASKPASS_REQUIRE", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE"} {
		old, had := os.LookupEnv(key)
		os.Unsetenv(key)
		t.Cleanup(func() {
			if had {
				os.Setenv(key, old)
			}
		})
	}
	// Isolate from whatever confcrypt-askpass may or may not be installed on
	// the machine running the tests; individual tests opt back in via
	// stubWellKnownAskpass.
	stubWellKnownAskpass(t, "")
}

// stubWellKnownAskpass overrides the well-known confcrypt-askpass resolver
// for the duration of the test.
func stubWellKnownAskpass(t *testing.T, path string) {
	t.Helper()
	original := wellKnownAskpassResolver
	wellKnownAskpassResolver = func() string { return path }
	t.Cleanup(func() { wellKnownAskpassResolver = original })
}

// go test's stdin is not a TTY, so isNonInteractive() is true throughout
// this test binary - which is exactly the condition we need to exercise.

func TestIsNonInteractive_UnderGoTest(t *testing.T) {
	if !isNonInteractive() {
		t.Fatal("expected isNonInteractive() to be true when running under `go test`")
	}
}

func TestResolveAskpassProgram_NonInteractiveUsesConfcryptAskpass(t *testing.T) {
	clearAskpassEnv(t)
	os.Setenv("CONFCRYPT_ASKPASS", "/path/to/confcrypt-askpass")

	if got := resolveAskpassProgram(); got != "/path/to/confcrypt-askpass" {
		t.Fatalf("expected CONFCRYPT_ASKPASS to be used, got %q", got)
	}
}

func TestResolveAskpassProgram_FallsBackToSSHAskpass(t *testing.T) {
	clearAskpassEnv(t)
	os.Setenv("SSH_ASKPASS", "/path/to/ssh-askpass")

	if got := resolveAskpassProgram(); got != "/path/to/ssh-askpass" {
		t.Fatalf("expected SSH_ASKPASS fallback to be used, got %q", got)
	}
}

func TestResolveAskpassProgram_ConfcryptTakesPriorityOverSSH(t *testing.T) {
	clearAskpassEnv(t)
	os.Setenv("CONFCRYPT_ASKPASS", "/path/to/confcrypt-askpass")
	os.Setenv("SSH_ASKPASS", "/path/to/ssh-askpass")

	if got := resolveAskpassProgram(); got != "/path/to/confcrypt-askpass" {
		t.Fatalf("expected CONFCRYPT_ASKPASS to take priority, got %q", got)
	}
}

func TestResolveAskpassProgram_NoneSetReturnsEmpty(t *testing.T) {
	clearAskpassEnv(t)

	if got := resolveAskpassProgram(); got != "" {
		t.Fatalf("expected no askpass program, got %q", got)
	}
}

func TestResolveAskpassProgram_SSHRequireForceIgnoredWithoutSSHAskpass(t *testing.T) {
	clearAskpassEnv(t)
	os.Setenv("SSH_ASKPASS_REQUIRE", "force")

	if got := resolveAskpassProgram(); got != "" {
		t.Fatalf("expected no askpass program when SSH_ASKPASS is unset, got %q", got)
	}
}

func TestResolveAskpassProgram_NonInteractiveUsesWellKnownScript(t *testing.T) {
	clearAskpassEnv(t)
	stubWellKnownAskpass(t, "/path/to/confcrypt-askpass")

	if got := resolveAskpassProgram(); got != "/path/to/confcrypt-askpass" {
		t.Fatalf("expected well-known confcrypt-askpass to be used, got %q", got)
	}
}

func TestResolveAskpassProgram_ConfcryptAskpassTakesPriorityOverWellKnownScript(t *testing.T) {
	clearAskpassEnv(t)
	os.Setenv("CONFCRYPT_ASKPASS", "/path/to/confcrypt-askpass-env")
	stubWellKnownAskpass(t, "/path/to/confcrypt-askpass")

	if got := resolveAskpassProgram(); got != "/path/to/confcrypt-askpass-env" {
		t.Fatalf("expected CONFCRYPT_ASKPASS to take priority over well-known script, got %q", got)
	}
}

func TestResolveAskpassProgram_WellKnownScriptTakesPriorityOverSSHAskpass(t *testing.T) {
	clearAskpassEnv(t)
	os.Setenv("SSH_ASKPASS", "/path/to/ssh-askpass")
	stubWellKnownAskpass(t, "/path/to/confcrypt-askpass")

	if got := resolveAskpassProgram(); got != "/path/to/confcrypt-askpass" {
		t.Fatalf("expected well-known script to take priority over SSH_ASKPASS, got %q", got)
	}
}

func TestResolveAskpassProgram_ConfcryptRequireForceFallsBackToWellKnownScript(t *testing.T) {
	clearAskpassEnv(t)
	os.Setenv("CONFCRYPT_ASKPASS_REQUIRE", "force")
	stubWellKnownAskpass(t, "/path/to/confcrypt-askpass")

	if got := resolveAskpassProgram(); got != "/path/to/confcrypt-askpass" {
		t.Fatalf("expected CONFCRYPT_ASKPASS_REQUIRE=force to fall back to the well-known script, got %q", got)
	}
}

func TestResolveAskpassProgram_ConfcryptRequireForcePrefersExplicitAskpassOverWellKnownScript(t *testing.T) {
	clearAskpassEnv(t)
	os.Setenv("CONFCRYPT_ASKPASS", "/path/to/confcrypt-askpass-env")
	os.Setenv("CONFCRYPT_ASKPASS_REQUIRE", "force")
	stubWellKnownAskpass(t, "/path/to/confcrypt-askpass")

	if got := resolveAskpassProgram(); got != "/path/to/confcrypt-askpass-env" {
		t.Fatalf("expected explicit CONFCRYPT_ASKPASS to win under force, got %q", got)
	}
}

func TestResolveAskpassProgram_ConfcryptRequireForceWithoutAnyAskpassFallsThrough(t *testing.T) {
	clearAskpassEnv(t)
	os.Setenv("CONFCRYPT_ASKPASS_REQUIRE", "force")
	os.Setenv("SSH_ASKPASS", "/path/to/ssh-askpass")

	if got := resolveAskpassProgram(); got != "/path/to/ssh-askpass" {
		t.Fatalf("expected fall-through to SSH_ASKPASS when force can't be satisfied by confcrypt, got %q", got)
	}
}

func TestResolveAskpassProgram_SSHRequireForceWinsOverWellKnownScript(t *testing.T) {
	clearAskpassEnv(t)
	os.Setenv("SSH_ASKPASS", "/path/to/ssh-askpass")
	os.Setenv("SSH_ASKPASS_REQUIRE", "force")
	stubWellKnownAskpass(t, "/path/to/confcrypt-askpass")

	if got := resolveAskpassProgram(); got != "/path/to/ssh-askpass" {
		t.Fatalf("expected SSH_ASKPASS_REQUIRE=force to win over the well-known script, got %q", got)
	}
}

func TestRunAskpass_ReturnsTrimmedStdout(t *testing.T) {
	script := writeAskpassScript(t, "s3cr3t-pin")

	value, err := runAskpass(script, "Enter PIN: ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "s3cr3t-pin" {
		t.Fatalf("expected trimmed value %q, got %q", "s3cr3t-pin", value)
	}
}

func TestRunAskpass_FailingProgramReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fail.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	if _, err := runAskpass(path, "Enter PIN: "); err == nil {
		t.Fatal("expected error from failing askpass program")
	}
}

func TestAskSecret_UsesAskpassWhenConfigured(t *testing.T) {
	clearAskpassEnv(t)
	script := writeAskpassScript(t, "hunter2")
	os.Setenv("CONFCRYPT_ASKPASS", script)

	value, handled, err := askSecret("Enter passphrase: ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !handled {
		t.Fatal("expected askSecret to report handled=true")
	}
	if value != "hunter2" {
		t.Fatalf("expected %q, got %q", "hunter2", value)
	}
}

func TestAskSecret_NotHandledWithoutAskpass(t *testing.T) {
	clearAskpassEnv(t)

	_, handled, err := askSecret("Enter passphrase: ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handled {
		t.Fatal("expected askSecret to report handled=false when no askpass is configured")
	}
}

func TestPromptPassphrase_NonInteractiveWithoutAskpassFails(t *testing.T) {
	clearAskpassEnv(t)

	_, err := promptPassphrase("/tmp/id_ed25519")
	if err == nil {
		t.Fatal("expected error in non-interactive mode without any askpass configured")
	}
}

func TestPromptPassphrase_UsesConfcryptAskpass(t *testing.T) {
	clearAskpassEnv(t)
	script := writeAskpassScript(t, "my-passphrase")
	os.Setenv("CONFCRYPT_ASKPASS", script)

	passphrase, err := promptPassphrase("/tmp/id_ed25519")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(passphrase) != "my-passphrase" {
		t.Fatalf("expected %q, got %q", "my-passphrase", string(passphrase))
	}
}

func TestPromptPassphrase_FallsBackToSSHAskpass(t *testing.T) {
	clearAskpassEnv(t)
	script := writeAskpassScript(t, "ssh-fallback-pass")
	os.Setenv("SSH_ASKPASS", script)

	passphrase, err := promptPassphrase("/tmp/id_ed25519")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(passphrase) != "ssh-fallback-pass" {
		t.Fatalf("expected %q, got %q", "ssh-fallback-pass", string(passphrase))
	}
}
