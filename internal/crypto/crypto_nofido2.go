//go:build !cgo

package crypto

import (
	"fmt"
	"strings"

	"filippo.io/age"
)

const fido2RecipientPrefix = "age1fido21"

// ParseFIDO2Recipient returns an error for non-CGO builds since FIDO2 requires CGO
func ParseFIDO2Recipient(pubKey string) (age.Recipient, error) {
	return nil, fmt.Errorf("FIDO2 recipients require CGO; rebuild with CGO_ENABLED=1")
}

// IsFIDO2Recipient returns true if the string looks like a FIDO2 recipient
func IsFIDO2Recipient(pubKey string) bool {
	return strings.HasPrefix(strings.ToLower(pubKey), fido2RecipientPrefix)
}
