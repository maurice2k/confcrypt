//go:build !cgo

package cmd

import (
	"fmt"

	"filippo.io/age"

	"github.com/maurice2k/confcrypt/internal/crypto"
)

// IsFIDO2Available returns false for non-CGO builds
func IsFIDO2Available() bool {
	return false
}

// generateFIDO2Recipient is a stub for non-CGO builds
func generateFIDO2Recipient() (string, crypto.KeyType, error) {
	return "", crypto.KeyTypeUnknown, fmt.Errorf("FIDO2 support requires CGO; rebuild with CGO_ENABLED=1")
}

// findFIDO2IdentityImpl is a stub for non-CGO builds
func findFIDO2IdentityImpl(storeRecipients []string) ([]age.Identity, error) {
	return nil, fmt.Errorf("FIDO2 support requires CGO; rebuild with CGO_ENABLED=1")
}
