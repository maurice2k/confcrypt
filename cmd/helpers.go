package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/yubikey"
)

// displayPath returns a path for console output, relative to the current
// working directory when the file is inside it, otherwise the absolute path.
func displayPath(p string) string {
	abs := p
	if !filepath.IsAbs(abs) {
		if a, err := filepath.Abs(abs); err == nil {
			abs = a
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return p
	}
	rel, err := filepath.Rel(cwd, abs)
	if err != nil || rel == "" || strings.HasPrefix(rel, "..") {
		return abs
	}
	return rel
}

// printConfigInUse reports which .confcrypt config file is being used.
// Writes to stderr when stdout must stay clean (e.g. --stdout/--json output).
func printConfigInUse(cfg *config.Config, toStderr bool) {
	if quiet >= 2 {
		return
	}
	w := os.Stdout
	if toStderr {
		w = os.Stderr
	}
	fmt.Fprintf(w, "Using config: %s\n", displayPath(cfg.ConfigPath()))
}

// loadYubiKeyIdentities loads identities from YubiKey recipients in the config
func loadYubiKeyIdentities(cfg *config.Config) ([]age.Identity, error) {
	var identities []age.Identity

	for _, recipient := range cfg.Recipients {
		pubKey := recipient.GetPublicKey()
		if !yubikey.IsYubiKeyRecipient(pubKey) {
			continue
		}

		// Decode the YubiKey recipient
		ykIdentity, err := yubikey.DecodeRecipient(pubKey)
		if err != nil {
			continue
		}

		// Check if this YubiKey is connected
		_, err = yubikey.FindYubiKeyBySerial(ykIdentity.Serial)
		if err != nil {
			// YubiKey not connected, skip
			continue
		}

		// YubiKey is connected - derive the identity
		fmt.Fprintf(os.Stderr, "Found YubiKey %d for recipient %q\n", ykIdentity.Serial, recipient.Name)
		fmt.Fprintln(os.Stderr, "Touch your YubiKey to decrypt...")

		ageIdentity, err := ykIdentity.ToAgeIdentity()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to derive key from YubiKey: %v\n", err)
			continue
		}

		identities = append(identities, ageIdentity)
	}

	return identities, nil
}
