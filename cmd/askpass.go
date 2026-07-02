package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/maurice2k/confcrypt/internal/askpasshelper"
)

// isNonInteractive reports whether stdin is not a terminal, meaning
// interactive prompts (PIN/passphrase) cannot be read from the keyboard.
func isNonInteractive() bool {
	return !term.IsTerminal(int(os.Stdin.Fd()))
}

// wellKnownAskpassResolver is overridable in tests.
var wellKnownAskpassResolver = resolveWellKnownAskpassScript

// resolveWellKnownAskpassScript looks for a confcrypt-askpass helper
// installed via `confcrypt install-askpass-helper`: first on PATH, then next
// to the currently running confcrypt binary (its default install location).
// Returns "" if none is found.
func resolveWellKnownAskpassScript() string {
	if path, err := exec.LookPath(askpasshelper.ScriptName); err == nil {
		return path
	}
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return ""
	}
	candidate := filepath.Join(filepath.Dir(exePath), askpasshelper.ScriptName)
	info, err := os.Stat(candidate)
	if err != nil || info.IsDir() || info.Mode()&0111 == 0 {
		return ""
	}
	return candidate
}

// resolveAskpassProgram determines which askpass helper program (if any)
// should be used for a secret prompt. It supports CONFCRYPT_ASKPASS, then the
// bundled confcrypt-askpass helper if installed, then falls back to
// SSH_ASKPASS, mirroring ssh(1)'s SSH_ASKPASS/SSH_ASKPASS_REQUIRE semantics:
//
//  1. CONFCRYPT_ASKPASS_REQUIRE=force: always used, regardless of
//     interactivity - CONFCRYPT_ASKPASS if set, else the installed
//     confcrypt-askpass helper (see resolveWellKnownAskpassScript) if found.
//  2. SSH_ASKPASS_REQUIRE=force + SSH_ASKPASS set (and no CONFCRYPT_ASKPASS):
//     always used (regardless of the well-known helper or interactivity).
//  3. Otherwise, only in non-interactive mode, in order: CONFCRYPT_ASKPASS,
//     then the installed confcrypt-askpass helper, then SSH_ASKPASS.
func resolveAskpassProgram() string {
	confcryptAskpass := os.Getenv("CONFCRYPT_ASKPASS")
	confcryptForce := os.Getenv("CONFCRYPT_ASKPASS_REQUIRE") == "force"
	sshAskpass := os.Getenv("SSH_ASKPASS")
	sshForce := os.Getenv("SSH_ASKPASS_REQUIRE") == "force"

	if confcryptForce {
		if confcryptAskpass != "" {
			return confcryptAskpass
		}
		if wellKnown := wellKnownAskpassResolver(); wellKnown != "" {
			return wellKnown
		}
	}
	if confcryptAskpass == "" && sshForce && sshAskpass != "" {
		return sshAskpass
	}
	if isNonInteractive() {
		if confcryptAskpass != "" {
			return confcryptAskpass
		}
		if wellKnown := wellKnownAskpassResolver(); wellKnown != "" {
			return wellKnown
		}
		if sshAskpass != "" {
			return sshAskpass
		}
	}
	return ""
}

// runAskpass invokes the askpass program with the given prompt as argv[1]
// (the SSH_ASKPASS convention) and returns its trimmed stdout as the secret.
func runAskpass(program, prompt string) (string, error) {
	cmd := exec.Command(program, prompt)
	cmd.Stdin = nil
	cmd.Stderr = os.Stderr
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("askpass program %q failed: %w", program, err)
	}
	return strings.TrimRight(out.String(), "\r\n"), nil
}

// askSecret resolves a secret (PIN/passphrase) via an askpass program if one
// applies (forced, or as a non-interactive fallback). handled=false means no
// askpass program applies and the caller should fall back to its normal
// terminal prompt (or fail if non-interactive).
func askSecret(prompt string) (value string, handled bool, err error) {
	program := resolveAskpassProgram()
	if program == "" {
		return "", false, nil
	}
	value, err = runAskpass(program, prompt)
	return value, true, err
}
