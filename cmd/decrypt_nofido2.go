//go:build !cgo

package cmd

import (
	"filippo.io/age"

	"github.com/maurice2k/confcrypt/internal/config"
)

// loadFIDO2Identities is a stub for non-CGO builds
func loadFIDO2Identities(cfg *config.Config) ([]age.Identity, error) {
	return nil, nil
}
