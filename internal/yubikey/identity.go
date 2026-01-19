package yubikey

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// x25519Identity implements age.Identity for YubiKey-derived keys
type x25519Identity struct {
	privateKey []byte
	publicKey  []byte
}

// Unwrap implements age.Identity
func (i *x25519Identity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, s := range stanzas {
		if s.Type != "X25519" {
			continue
		}
		if len(s.Args) != 1 {
			continue
		}

		// Decode ephemeral public key from stanza
		ephemeralPub, err := decodePublicKey(s.Args[0])
		if err != nil {
			continue
		}

		// Perform X25519 key agreement
		sharedSecret, err := curve25519.X25519(i.privateKey, ephemeralPub)
		if err != nil {
			continue
		}

		// Derive file key using HKDF
		salt := make([]byte, 0, len(ephemeralPub)+len(i.publicKey))
		salt = append(salt, ephemeralPub...)
		salt = append(salt, i.publicKey...)

		h := hkdf.New(sha256.New, sharedSecret, salt, []byte("age-encryption.org/v1/X25519"))
		wrappingKey := make([]byte, chacha20poly1305.KeySize)
		if _, err := io.ReadFull(h, wrappingKey); err != nil {
			continue
		}

		// Decrypt the file key
		aead, err := chacha20poly1305.New(wrappingKey)
		if err != nil {
			continue
		}

		nonce := make([]byte, chacha20poly1305.NonceSize)
		fileKey, err := aead.Open(nil, nonce, s.Body, nil)
		if err != nil {
			continue
		}

		return fileKey, nil
	}

	return nil, age.ErrIncorrectIdentity
}

// x25519Recipient implements age.Recipient for YubiKey-derived keys
type x25519Recipient struct {
	publicKey []byte
}

// Wrap implements age.Recipient
func (r *x25519Recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	// Generate ephemeral key pair
	ephemeralPriv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(ephemeralPriv); err != nil {
		return nil, err
	}

	ephemeralPub, err := curve25519.X25519(ephemeralPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	// Perform X25519 key agreement
	sharedSecret, err := curve25519.X25519(ephemeralPriv, r.publicKey)
	if err != nil {
		return nil, err
	}

	// Derive wrapping key using HKDF
	salt := make([]byte, 0, len(ephemeralPub)+len(r.publicKey))
	salt = append(salt, ephemeralPub...)
	salt = append(salt, r.publicKey...)

	h := hkdf.New(sha256.New, sharedSecret, salt, []byte("age-encryption.org/v1/X25519"))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	// Encrypt the file key
	aead, err := chacha20poly1305.New(wrappingKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	wrappedKey := aead.Seal(nil, nonce, fileKey, nil)

	// Encode ephemeral public key
	ephemeralPubStr := encodePublicKey(ephemeralPub)

	return []*age.Stanza{{
		Type: "X25519",
		Args: []string{ephemeralPubStr},
		Body: wrappedKey,
	}}, nil
}

// encodePublicKey encodes a public key to base64 (raw, no padding)
func encodePublicKey(key []byte) string {
	return base64.RawStdEncoding.EncodeToString(key)
}

// decodePublicKey decodes a base64-encoded public key
func decodePublicKey(s string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(s)
}
