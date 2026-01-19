//go:build cgo

package cmd

import (
	"bufio"
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

		// Find a device with matching AAGUID
		device, err := fido2.FindDeviceByAAGUID(fido2Identity.AAGUID)
		if err != nil {
			// No matching device connected
			continue
		}

		// Device is connected - get PIN if needed and derive the identity
		fmt.Fprintf(os.Stderr, "Found FIDO2 device %s for recipient %q\n", device.ProductInfo, recipient.Name)

		var pin string
		if fido2.DeviceRequiresPIN(device.Path) {
			pin = readFIDO2PIN()
		}

		fmt.Fprintln(os.Stderr, "Decrypting (touch your security key when it blinks)...")

		ageIdentity, err := fido2Identity.ToAgeIdentity(device.Path, pin)
		if err != nil {
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

		// Check if device with matching AAGUID is connected (no touch required)
		device, err := fido2.FindDeviceByAAGUID(fido2Identity.AAGUID)
		if err != nil {
			continue
		}

		// Device is connected - get PIN if needed
		fmt.Fprintf(os.Stderr, "Found FIDO2 device %s\n", device.ProductInfo)

		var pin string
		if fido2.DeviceRequiresPIN(device.Path) {
			pin = readFIDO2PIN()
		}

		fmt.Fprintln(os.Stderr, "Decrypting (touch your security key when it blinks)...")

		identity, err := fido2Identity.ToAgeIdentity(device.Path, pin)
		if err != nil {
			continue
		}
		return []age.Identity{identity}, nil
	}
	return nil, fmt.Errorf("no matching FIDO2 device found")
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
		pin = readFIDO2PIN()
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

// readFIDO2PIN prompts for and reads a FIDO2 PIN securely
func readFIDO2PIN() string {
	fmt.Fprint(os.Stderr, "Enter PIN: ")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading PIN: %v\n", err)
			os.Exit(1)
		}
		pin := strings.TrimSpace(string(pinBytes))
		if pin == "" {
			fmt.Fprintln(os.Stderr, "Error: PIN cannot be empty")
			os.Exit(1)
		}
		return pin
	}
	reader := bufio.NewReader(os.Stdin)
	pin, _ := reader.ReadString('\n')
	pin = strings.TrimSpace(pin)
	if pin == "" {
		fmt.Fprintln(os.Stderr, "Error: PIN cannot be empty")
		os.Exit(1)
	}
	return pin
}
