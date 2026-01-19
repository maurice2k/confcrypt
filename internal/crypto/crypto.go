package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"

	"github.com/maurice2k/confcrypt/internal/yubikey"
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

// ParseRecipient parses a public key string into a Recipient.
// Supports native age X25519 keys, SSH keys (ed25519, RSA), YubiKey, and FIDO2 recipients.
func ParseRecipient(pubKey string) (age.Recipient, error) {
	pubKey = strings.TrimSpace(pubKey)

	// Try YubiKey recipient first (starts with "age1yubikey")
	if yubikey.IsYubiKeyRecipient(pubKey) {
		identity, err := yubikey.DecodeRecipient(pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse YubiKey recipient %q: %w", pubKey, err)
		}
		return identity.ToAgeRecipient()
	}

	// Try FIDO2 recipient (starts with "age1fido2")
	if IsFIDO2Recipient(pubKey) {
		recipient, err := ParseFIDO2Recipient(pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse FIDO2 recipient %q: %w", pubKey, err)
		}
		return recipient, nil
	}

	// Try SSH key (starts with "ssh-")
	if strings.HasPrefix(pubKey, "ssh-") || strings.HasPrefix(pubKey, "ecdsa-") {
		recipient, err := agessh.ParseRecipient(pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SSH recipient %q: %w", pubKey, err)
		}
		return recipient, nil
	}

	// Fall back to native age X25519
	recipient, err := age.ParseX25519Recipient(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse age recipient %q: %w", pubKey, err)
	}
	return recipient, nil
}

// ParseAgeRecipient parses an age public key string into a Recipient
// Deprecated: Use ParseRecipient instead which supports both age and SSH keys
func ParseAgeRecipient(pubKey string) (age.Recipient, error) {
	return ParseRecipient(pubKey)
}

// ParseIdentity parses a private key string into an Identity.
// Supports both native age X25519 keys and SSH keys (ed25519, RSA).
func ParseIdentity(privKey string) (age.Identity, error) {
	privKey = strings.TrimSpace(privKey)

	// Try native age X25519 first (starts with AGE-SECRET-KEY-)
	if strings.HasPrefix(privKey, "AGE-SECRET-KEY-") {
		identity, err := age.ParseX25519Identity(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse age identity: %w", err)
		}
		return identity, nil
	}

	// Try SSH private key
	identity, err := agessh.ParseIdentity([]byte(privKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH identity: %w", err)
	}
	return identity, nil
}

// ParseAgeIdentity parses an age private key string into an Identity
// Deprecated: Use ParseIdentity instead which supports both age and SSH keys
func ParseAgeIdentity(privKey string) (age.Identity, error) {
	return ParseIdentity(privKey)
}

// PassphraseFunc is a callback to get a passphrase for encrypted SSH keys.
// The keyPath parameter indicates which key file needs the passphrase.
type PassphraseFunc func(keyPath string) ([]byte, error)

// ParseIdentities parses private keys from file content into Identities.
// Supports both native age X25519 keys (newline-separated) and SSH private keys.
// For passphrase-protected SSH keys, use ParseIdentitiesWithPassphrase instead.
func ParseIdentities(content string) ([]age.Identity, error) {
	return ParseIdentitiesWithPassphrase(content, "", nil)
}

// ParseIdentitiesWithPassphrase parses private keys with optional passphrase support.
// If the SSH key is passphrase-protected and passphraseFunc is provided, it will be
// called to get the passphrase. If passphraseFunc is nil, an error is returned for
// passphrase-protected keys.
func ParseIdentitiesWithPassphrase(content, keyPath string, passphraseFunc PassphraseFunc) ([]age.Identity, error) {
	content = strings.TrimSpace(content)

	// Check if it looks like an SSH private key
	if strings.HasPrefix(content, "-----BEGIN") {
		return parseSSHIdentityWithPassphrase([]byte(content), keyPath, passphraseFunc)
	}

	// Parse as age identities (newline-separated)
	var identities []age.Identity
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		identity, err := age.ParseX25519Identity(line)
		if err != nil {
			return nil, fmt.Errorf("failed to parse age identity: %w", err)
		}
		identities = append(identities, identity)
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("no valid identities found")
	}
	return identities, nil
}

// parseSSHIdentityWithPassphrase parses an SSH private key, handling passphrase-protected keys.
func parseSSHIdentityWithPassphrase(pemBytes []byte, keyPath string, passphraseFunc PassphraseFunc) ([]age.Identity, error) {
	// First, try to parse without passphrase
	identity, err := agessh.ParseIdentity(pemBytes)
	if err == nil {
		return []age.Identity{identity}, nil
	}

	// Check if it's a passphrase-protected key
	var missingErr *ssh.PassphraseMissingError
	if !isPassphraseError(err, &missingErr) {
		return nil, fmt.Errorf("failed to parse SSH identity: %w", err)
	}

	// Key is passphrase-protected
	if passphraseFunc == nil {
		return nil, fmt.Errorf("SSH key is passphrase-protected but no passphrase callback provided")
	}

	// Get public key from the error (OpenSSH format includes it)
	pubKey := missingErr.PublicKey
	if pubKey == nil {
		return nil, fmt.Errorf("SSH key is passphrase-protected and public key could not be extracted; provide a .pub file")
	}

	// Create an encrypted identity that will prompt for passphrase when needed
	encIdentity, err := agessh.NewEncryptedSSHIdentity(pubKey, pemBytes, func() ([]byte, error) {
		return passphraseFunc(keyPath)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypted SSH identity: %w", err)
	}

	return []age.Identity{encIdentity}, nil
}

// isPassphraseError checks if the error indicates a passphrase-protected key.
func isPassphraseError(err error, missingErr **ssh.PassphraseMissingError) bool {
	if err == nil {
		return false
	}
	// Check for PassphraseMissingError
	var pme *ssh.PassphraseMissingError
	if errors.As(err, &pme) {
		*missingErr = pme
		return true
	}
	// Also check error message for older formats
	errStr := err.Error()
	return strings.Contains(errStr, "passphrase") ||
		strings.Contains(errStr, "encrypted") ||
		strings.Contains(errStr, "ENCRYPTED")
}

// ParseAgeIdentities parses multiple age private keys (newline-separated) into Identities
// Deprecated: Use ParseIdentities instead which supports both age and SSH keys
func ParseAgeIdentities(privKeys string) ([]age.Identity, error) {
	return ParseIdentities(privKeys)
}

// GenerateAgeKeypair generates a new age X25519 keypair
func GenerateAgeKeypair() (*age.X25519Identity, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("failed to generate age keypair: %w", err)
	}
	return identity, nil
}

// KeyType represents the type of a public key
type KeyType string

const (
	KeyTypeAge        KeyType = "age"
	KeyTypeYubiKey    KeyType = "yubikey"
	KeyTypeFIDO2      KeyType = "fido2"
	KeyTypeSSHEd25519 KeyType = "ssh-ed25519"
	KeyTypeSSHRSA     KeyType = "ssh-rsa"
	KeyTypeSSHECDSA   KeyType = "ecdsa"
	KeyTypeUnknown    KeyType = "unknown"
)

// DetectKeyType detects the type of a public key string
func DetectKeyType(pubKey string) KeyType {
	pubKey = strings.TrimSpace(pubKey)
	switch {
	case yubikey.IsYubiKeyRecipient(pubKey):
		return KeyTypeYubiKey
	case IsFIDO2Recipient(pubKey):
		return KeyTypeFIDO2
	case strings.HasPrefix(pubKey, "age1"):
		return KeyTypeAge
	case strings.HasPrefix(pubKey, "ssh-ed25519"):
		return KeyTypeSSHEd25519
	case strings.HasPrefix(pubKey, "ssh-rsa"):
		return KeyTypeSSHRSA
	case strings.HasPrefix(pubKey, "ecdsa-"):
		return KeyTypeSSHECDSA
	default:
		return KeyTypeUnknown
	}
}

// IsSSHKey returns true if the key is an SSH key
func IsSSHKey(pubKey string) bool {
	keyType := DetectKeyType(pubKey)
	return keyType == KeyTypeSSHEd25519 || keyType == KeyTypeSSHRSA || keyType == KeyTypeSSHECDSA
}

// IsYubiKeyRecipient returns true if the string is a YubiKey recipient
func IsYubiKeyRecipient(pubKey string) bool {
	return yubikey.IsYubiKeyRecipient(pubKey)
}
