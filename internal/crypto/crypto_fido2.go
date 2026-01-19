//go:build cgo

package crypto

import (
	"fmt"

	"filippo.io/age"

	"github.com/maurice2k/confcrypt/internal/fido2"
)

// ParseFIDO2Recipient parses a FIDO2 recipient string into an age.Recipient
func ParseFIDO2Recipient(pubKey string) (age.Recipient, error) {
	if !fido2.IsFIDO2Recipient(pubKey) {
		return nil, fmt.Errorf("not a FIDO2 recipient: %s", pubKey)
	}

	identity, err := fido2.DecodeRecipient(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse FIDO2 recipient %q: %w", pubKey, err)
	}

	return identity.ToAgeRecipient(), nil
}

// IsFIDO2Recipient checks if a string is a FIDO2 recipient
func IsFIDO2Recipient(pubKey string) bool {
	return fido2.IsFIDO2Recipient(pubKey)
}

func init() {
	// Register FIDO2 recipient parser
	registerFIDO2Parser()
}

// registerFIDO2Parser registers the FIDO2 recipient parser
func registerFIDO2Parser() {
	// This is called at init time to ensure FIDO2 support is available
	// when built with CGO
}
