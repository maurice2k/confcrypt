//go:build cgo

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"golang.org/x/term"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/crypto"
	"github.com/maurice2k/confcrypt/internal/fido2"
)

// IsFIDO2Available checks if a FIDO2 device is connected
func IsFIDO2Available() bool {
	_, err := fido2.GetFirstDevice()
	return err == nil
}

// loadFIDO2Identities loads identities from FIDO2 recipients in the config
func loadFIDO2Identities(cfg *config.Config) ([]age.Identity, error) {
	var identities []age.Identity

	for _, recipient := range cfg.Recipients {
		pubKey := recipient.GetPublicKey()
		if !fido2.IsFIDO2Recipient(pubKey) {
			continue
		}

		// Decode the FIDO2 recipient
		fido2Identity, err := fido2.DecodeRecipient(pubKey)
		if err != nil {
			continue
		}

		// Identify the exact device that owns this credential (no touch). The
		// credential probe distinguishes two same-model keys; AAGUID narrows it to
		// the right model first.
		device, err := fido2.FindDeviceByCredential(fido2Identity.CredentialID, fido2Identity.RPID, fido2Identity.AAGUID)
		if err != nil {
			// No matching device connected
			continue
		}

		// Device is connected - get PIN if needed and derive the identity
		fmt.Fprintf(os.Stderr, "Found FIDO2 device %s for recipient %q\n", device.ProductInfo, recipient.Name)

		var pin string
		if fido2.DeviceRequiresPIN(device.Path) {
			var err error
			pin, err = readFIDO2PIN()
			if err != nil {
				return nil, err
			}
		}

		fmt.Fprintln(os.Stderr, "Decrypting (touch your security key when it blinks)...")

		ageIdentity, err := fido2Identity.ToAgeIdentity(device.Path, pin)
		if err != nil {
			if stopErr := fido2PINError(err, device.Path); stopErr != nil {
				return nil, stopErr
			}
			fmt.Fprintf(os.Stderr, "Warning: failed to derive key from FIDO2 device: %v\n", err)
			continue
		}

		identities = append(identities, ageIdentity)
	}

	return identities, nil
}

// findFIDO2IdentityImpl checks if connected FIDO2 device matches any store recipient
func findFIDO2IdentityImpl(storeRecipients []string) ([]age.Identity, error) {
	for _, recipient := range storeRecipients {
		if !fido2.IsFIDO2Recipient(recipient) {
			continue
		}

		fido2Identity, err := fido2.DecodeRecipient(recipient)
		if err != nil {
			continue
		}

		// Identify the exact device that owns this credential (no touch required).
		// The credential probe distinguishes two same-model keys; AAGUID narrows
		// it to the right model first.
		device, err := fido2.FindDeviceByCredential(fido2Identity.CredentialID, fido2Identity.RPID, fido2Identity.AAGUID)
		if err != nil {
			continue
		}

		// Device is connected - get PIN if needed
		fmt.Fprintf(os.Stderr, "Found FIDO2 device %s\n", device.ProductInfo)

		var pin string
		if fido2.DeviceRequiresPIN(device.Path) {
			var err error
			pin, err = readFIDO2PIN()
			if err != nil {
				return nil, err
			}
		}

		fmt.Fprintln(os.Stderr, "Decrypting (touch your security key when it blinks)...")

		identity, err := fido2Identity.ToAgeIdentity(device.Path, pin)
		if err != nil {
			if stopErr := fido2PINError(err, device.Path); stopErr != nil {
				return nil, stopErr
			}
			continue
		}
		return []age.Identity{identity}, nil
	}
	return nil, fmt.Errorf("no matching FIDO2 device found")
}

// fido2PINError maps a wrong/blocked PIN error into a user-facing fatal error
// (with remaining attempts) that should stop the recipient loop. Returns nil for
// other errors, which the caller treats as "try the next recipient".
func fido2PINError(err error, devicePath string) error {
	switch {
	case errors.Is(err, fido2.ErrWrongPIN):
		msg := "incorrect PIN"
		if n, e := fido2.PINRetriesRemaining(devicePath); e == nil {
			msg += fmt.Sprintf(" (%d attempt(s) left before the key locks)", n)
		}
		return errors.New(msg)
	case errors.Is(err, fido2.ErrPINBlocked):
		return errors.New("FIDO2 PIN is blocked; reinsert the key or reset the PIN")
	}
	return nil
}

// generateFIDO2Recipient generates a FIDO2-derived recipient with user interaction
func generateFIDO2Recipient() (string, crypto.KeyType, error) {
	fmt.Fprintln(os.Stderr, "Detecting FIDO2 device...")

	// Find device
	device, err := fido2.GetFirstDevice()
	if err != nil {
		if err == fido2.ErrNoDevice {
			return "", crypto.KeyTypeUnknown, fmt.Errorf("no FIDO2 device detected; make sure your security key is connected")
		}
		return "", crypto.KeyTypeUnknown, err
	}

	// Get all device info in one call
	devInfo, err := fido2.GetDeviceInfo(device.Path)
	if err != nil {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("failed to check device: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Found device: %s", device.ProductInfo)
	if devInfo.Serial != "" {
		fmt.Fprintf(os.Stderr, " (AAGUID: %s)", devInfo.Serial)
	}
	fmt.Fprintln(os.Stderr)

	if !devInfo.SupportsHMAC {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("device does not support hmac-secret extension")
	}

	// Get PIN if device requires it
	var pin string
	if devInfo.RequiresPIN {
		var err error
		pin, err = readFIDO2PIN()
		if err != nil {
			return "", crypto.KeyTypeUnknown, err
		}
	}

	// Step 1: Create credential (PIN verified first, then touch required)
	fmt.Fprintln(os.Stderr, "\nCreating credential (touch your security key when it blinks)...")

	partial, err := fido2.CreateCredentialStep1(device.Path, fido2.DefaultRPID, pin)
	if err != nil {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("failed to create credential: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Credential created.")

	// Step 2: Derive key (requires another touch)
	fmt.Fprintln(os.Stderr, "Touch your security key again to derive key...")

	identity, err := fido2.CreateCredentialStep2(device.Path, partial, pin)
	if err != nil {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("failed to derive key: %w", err)
	}

	// Encode to recipient string
	recipient, err := fido2.EncodeRecipient(identity)
	if err != nil {
		return "", crypto.KeyTypeUnknown, fmt.Errorf("failed to encode FIDO2 recipient: %w", err)
	}

	return recipient, crypto.KeyTypeFIDO2, nil
}

// readFIDO2PIN prompts for and reads a FIDO2 PIN securely. In non-interactive
// mode (no TTY on stdin) it uses CONFCRYPT_ASKPASS (falling back to
// SSH_ASKPASS) to obtain the PIN, or fails with an error if neither is set.
func readFIDO2PIN() (string, error) {
	prompt := "Enter PIN for FIDO2 device: "

	if value, handled, err := askSecret(prompt); handled {
		if err != nil {
			return "", err
		}
		if value == "" {
			return "", fmt.Errorf("PIN cannot be empty (askpass returned empty value)")
		}
		return value, nil
	}

	if isNonInteractive() {
		return "", fmt.Errorf("cannot read FIDO2 PIN: no TTY available; set CONFCRYPT_ASKPASS (or SSH_ASKPASS) to a helper program")
	}

	fmt.Fprint(os.Stderr, prompt)
	pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("error reading PIN: %w", err)
	}
	pin := strings.TrimSpace(string(pinBytes))
	if pin == "" {
		return "", fmt.Errorf("PIN cannot be empty")
	}
	return pin, nil
}
