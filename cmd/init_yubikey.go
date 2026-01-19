package cmd

import (
	"fmt"
	"os"

	"github.com/maurice2k/confcrypt/internal/crypto"
	"github.com/maurice2k/confcrypt/internal/yubikey"
)

var (
	initYubiKeyFlag bool
	initYubiKeySlot int
)

func init() {
	initCmd.Flags().BoolVar(&initYubiKeyFlag, "yubikey-key", false, "Generate a YubiKey-derived key")
	initCmd.Flags().IntVar(&initYubiKeySlot, "yubikey-slot", yubikey.DefaultSlot, "YubiKey HMAC slot to use (1 or 2)")
}

// IsYubiKeyAvailable checks if a YubiKey is connected
func IsYubiKeyAvailable() bool {
	_, err := yubikey.GetFirstYubiKey()
	return err == nil
}

// generateYubiKeyRecipient generates a YubiKey-derived recipient
func generateYubiKeyRecipient() (string, crypto.KeyType, error) {
	// Validate slot
	if initYubiKeySlot != 1 && initYubiKeySlot != 2 {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("YubiKey slot must be 1 or 2")
	}

	fmt.Fprintln(os.Stderr, "Detecting YubiKey...")

	// Find YubiKey
	yk, err := yubikey.GetFirstYubiKey()
	if err != nil {
		if err == yubikey.ErrNoYubiKey {
			return "", crypto.KeyTypeUnknown, fmt.Errorf("no YubiKey detected; make sure your YubiKey is connected")
		}
		if err == yubikey.ErrYkmanNotFound {
			return "", crypto.KeyTypeUnknown, fmt.Errorf("ykman not found; install yubikey-manager: pip install yubikey-manager")
		}
		return "", crypto.KeyTypeUnknown, err
	}

	fmt.Fprintf(os.Stderr, "Found YubiKey with serial: %d\n", yk.Serial)
	fmt.Fprintf(os.Stderr, "Using HMAC slot %d\n", initYubiKeySlot)

	// Check if HMAC is configured
	configured, err := yubikey.IsHMACConfigured(yk.Serial, uint8(initYubiKeySlot))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not check HMAC configuration: %v\n", err)
	} else if !configured {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("HMAC challenge-response not configured on slot %d; configure it with: ykman otp chalresp --generate %d --touch", initYubiKeySlot, initYubiKeySlot)
	}

	fmt.Fprintln(os.Stderr, "\nTouch your YubiKey...")

	// Generate identity
	identity, err := yubikey.GenerateIdentity(yk.Serial, uint8(initYubiKeySlot))
	if err != nil {
		if err == yubikey.ErrHMACNotConfigured {
			return "", crypto.KeyTypeUnknown, fmt.Errorf("HMAC challenge-response not configured on slot %d; configure it with: ykman otp chalresp --generate %d --touch", initYubiKeySlot, initYubiKeySlot)
		}
		return "", crypto.KeyTypeUnknown, fmt.Errorf("failed to generate YubiKey identity: %w", err)
	}

	// Encode to recipient string
	recipient, err := yubikey.EncodeRecipient(identity)
	if err != nil {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("failed to encode YubiKey recipient: %w", err)
	}

	return recipient, crypto.KeyTypeYubiKey, nil
}
