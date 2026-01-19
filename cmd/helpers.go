package cmd

import (
	"fmt"
	"os"

	"filippo.io/age"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/yubikey"
)

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
