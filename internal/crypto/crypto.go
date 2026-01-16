package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
)

// GenerateAESKey generates a random 256-bit AES key
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}
	return key, nil
}

// EncryptAESGCM encrypts plaintext using AES-256-GCM
// Returns ciphertext, iv, and tag separately
func EncryptAESGCM(key, plaintext []byte) (ciphertext, iv, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	iv = make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// GCM appends the tag to the ciphertext
	sealed := gcm.Seal(nil, iv, plaintext, nil)

	// Split ciphertext and tag (tag is last 16 bytes)
	tagSize := gcm.Overhead() // 16 bytes
	ciphertext = sealed[:len(sealed)-tagSize]
	tag = sealed[len(sealed)-tagSize:]

	return ciphertext, iv, tag, nil
}

// DecryptAESGCM decrypts ciphertext using AES-256-GCM
func DecryptAESGCM(key, ciphertext, iv, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Reconstruct sealed data (ciphertext + tag)
	sealed := append(ciphertext, tag...)

	plaintext, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptForRecipients encrypts data for multiple age recipients
func EncryptForRecipients(data []byte, recipients []age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("failed to create age encryptor: %w", err)
	}

	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write to age encryptor: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to close age encryptor: %w", err)
	}

	return buf.Bytes(), nil
}

// DecryptWithIdentities decrypts age-encrypted data using provided identities
func DecryptWithIdentities(data []byte, identities []age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(data), identities...)
	if err != nil {
		return nil, fmt.Errorf("failed to create age decryptor: %w", err)
	}

	decrypted, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	return decrypted, nil
}

// ParseAgeRecipient parses an age public key string into a Recipient
func ParseAgeRecipient(pubKey string) (age.Recipient, error) {
	pubKey = strings.TrimSpace(pubKey)
	recipient, err := age.ParseX25519Recipient(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse age recipient %q: %w", pubKey, err)
	}
	return recipient, nil
}

// ParseAgeIdentity parses an age private key string into an Identity
func ParseAgeIdentity(privKey string) (age.Identity, error) {
	privKey = strings.TrimSpace(privKey)
	identity, err := age.ParseX25519Identity(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse age identity: %w", err)
	}
	return identity, nil
}

// ParseAgeIdentities parses multiple age private keys (newline-separated) into Identities
func ParseAgeIdentities(privKeys string) ([]age.Identity, error) {
	var identities []age.Identity
	for _, line := range strings.Split(privKeys, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		identity, err := ParseAgeIdentity(line)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("no valid age identities found")
	}
	return identities, nil
}

// GenerateAgeKeypair generates a new age X25519 keypair
func GenerateAgeKeypair() (*age.X25519Identity, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("failed to generate age keypair: %w", err)
	}
	return identity, nil
}
