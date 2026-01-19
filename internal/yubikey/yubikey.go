// Package yubikey provides YubiKey HMAC challenge-response support for deriving age keys.
package yubikey

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/curve25519"
)

const (
	// DefaultSlot is the default HMAC slot (slot 2 is typically used for challenge-response)
	DefaultSlot = 2

	// ChallengeSize is the size of the random challenge in bytes
	ChallengeSize = 32

	// HMACResponseSize is the size of the HMAC-SHA1 response in bytes
	HMACResponseSize = 20
)

var (
	// ErrNoYubiKey is returned when no YubiKey is detected
	ErrNoYubiKey = errors.New("no YubiKey detected")

	// ErrYkmanNotFound is returned when ykman is not installed
	ErrYkmanNotFound = errors.New("ykman not found; install yubikey-manager")

	// ErrHMACNotConfigured is returned when HMAC slot is not configured
	ErrHMACNotConfigured = errors.New("HMAC challenge-response not configured on this slot")

	// ErrYubiKeyNotFound is returned when a specific YubiKey serial is not found
	ErrYubiKeyNotFound = errors.New("YubiKey with specified serial not found")
)

// YubiKey represents a connected YubiKey device
type YubiKey struct {
	Serial uint32
	Name   string
}

// Identity holds the data needed to derive an age key from a YubiKey
type Identity struct {
	Serial    uint32
	Slot      uint8
	Challenge []byte // 32 bytes
	PubKey    []byte // 32 bytes (X25519 public key)
}

// DetectYubiKeys returns a list of connected YubiKeys
func DetectYubiKeys() ([]YubiKey, error) {
	if err := checkYkman(); err != nil {
		return nil, err
	}

	cmd := exec.Command("ykman", "list", "--serials")
	output, err := cmd.Output()
	if err != nil {
		// No YubiKeys connected
		return nil, nil
	}

	var keys []YubiKey
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		serial, err := strconv.ParseUint(line, 10, 32)
		if err != nil {
			continue
		}
		keys = append(keys, YubiKey{
			Serial: uint32(serial),
			Name:   fmt.Sprintf("YubiKey %d", serial),
		})
	}

	return keys, nil
}

// FindYubiKeyBySerial finds a connected YubiKey by its serial number
func FindYubiKeyBySerial(serial uint32) (*YubiKey, error) {
	keys, err := DetectYubiKeys()
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		if key.Serial == serial {
			return &key, nil
		}
	}

	return nil, ErrYubiKeyNotFound
}

// GetFirstYubiKey returns the first connected YubiKey
func GetFirstYubiKey() (*YubiKey, error) {
	keys, err := DetectYubiKeys()
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return nil, ErrNoYubiKey
	}

	return &keys[0], nil
}

// GenerateChallenge generates a random challenge for HMAC
func GenerateChallenge() ([]byte, error) {
	challenge := make([]byte, ChallengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}
	return challenge, nil
}

// HMACChallenge sends a challenge to the YubiKey and returns the HMAC response
func HMACChallenge(serial uint32, slot uint8, challenge []byte) ([]byte, error) {
	if err := checkYkman(); err != nil {
		return nil, err
	}

	// Convert challenge to hex
	challengeHex := hex.EncodeToString(challenge)

	// Build command with serial if specified
	// Use "otp calculate" to perform challenge-response (not "otp chalresp" which programs the slot)
	args := []string{"otp", "calculate", fmt.Sprintf("%d", slot), challengeHex}
	if serial > 0 {
		args = append([]string{"--device", fmt.Sprintf("%d", serial)}, args...)
	}

	cmd := exec.Command("ykman", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		stderrStr := stderr.String()
		if strings.Contains(stderrStr, "No YubiKey") {
			return nil, ErrNoYubiKey
		}
		if strings.Contains(stderrStr, "not configured") || strings.Contains(stderrStr, "No such slot") {
			return nil, ErrHMACNotConfigured
		}
		return nil, fmt.Errorf("ykman challenge-response failed: %s", stderrStr)
	}

	// Parse hex response
	responseHex := strings.TrimSpace(stdout.String())
	response, err := hex.DecodeString(responseHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode HMAC response: %w", err)
	}

	if len(response) != HMACResponseSize {
		return nil, fmt.Errorf("unexpected HMAC response size: got %d, want %d", len(response), HMACResponseSize)
	}

	return response, nil
}

// DeriveAgeKeyPair derives an X25519 key pair from a YubiKey HMAC response
func DeriveAgeKeyPair(response, challenge []byte) (privateKey, publicKey []byte, err error) {
	// seed = SHA256(response || challenge)
	h := sha256.New()
	h.Write(response)
	h.Write(challenge)
	seed := h.Sum(nil)

	// Use seed as X25519 private key (clamp it per RFC 7748)
	privateKey = make([]byte, 32)
	copy(privateKey, seed)
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Derive public key
	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	return privateKey, publicKey, nil
}

// GenerateIdentity generates a new YubiKey-derived age identity
func GenerateIdentity(serial uint32, slot uint8) (*Identity, error) {
	// Generate random challenge
	challenge, err := GenerateChallenge()
	if err != nil {
		return nil, err
	}

	// Get HMAC response from YubiKey
	response, err := HMACChallenge(serial, slot, challenge)
	if err != nil {
		return nil, err
	}

	// Derive key pair
	_, pubKey, err := DeriveAgeKeyPair(response, challenge)
	if err != nil {
		return nil, err
	}

	return &Identity{
		Serial:    serial,
		Slot:      slot,
		Challenge: challenge,
		PubKey:    pubKey,
	}, nil
}

// DerivePrivateKey derives the age private key from a YubiKey identity
func (id *Identity) DerivePrivateKey() ([]byte, error) {
	// Get HMAC response from YubiKey
	response, err := HMACChallenge(id.Serial, id.Slot, id.Challenge)
	if err != nil {
		return nil, err
	}

	// Derive key pair
	privKey, pubKey, err := DeriveAgeKeyPair(response, id.Challenge)
	if err != nil {
		return nil, err
	}

	// Verify public key matches
	if !bytes.Equal(pubKey, id.PubKey) {
		return nil, errors.New("derived public key does not match; wrong YubiKey or slot?")
	}

	return privKey, nil
}

// ToAgeIdentity converts the YubiKey identity to an age.Identity
func (id *Identity) ToAgeIdentity() (age.Identity, error) {
	privKey, err := id.DerivePrivateKey()
	if err != nil {
		return nil, err
	}

	// Create age identity from raw private key
	// age.X25519Identity expects the Bech32-encoded secret key, so we need to
	// construct it manually using the raw key
	return &x25519Identity{
		privateKey: privKey,
		publicKey:  id.PubKey,
	}, nil
}

// ToAgeRecipient returns the age.Recipient for this identity
func (id *Identity) ToAgeRecipient() (age.Recipient, error) {
	return &x25519Recipient{publicKey: id.PubKey}, nil
}

// checkYkman checks if ykman is installed
func checkYkman() error {
	_, err := exec.LookPath("ykman")
	if err != nil {
		return ErrYkmanNotFound
	}
	return nil
}

// IsHMACConfigured checks if HMAC challenge-response is configured on the given slot
func IsHMACConfigured(serial uint32, slot uint8) (bool, error) {
	if err := checkYkman(); err != nil {
		return false, err
	}

	args := []string{"otp", "info"}
	if serial > 0 {
		args = append([]string{"--device", fmt.Sprintf("%d", serial)}, args...)
	}

	cmd := exec.Command("ykman", args...)
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("failed to get OTP info: %w", err)
	}

	// Parse output to check if slot has challenge-response configured
	// Output format:
	// Slot 1: programmed (HMAC-SHA1)
	// Slot 2: empty
	slotPattern := regexp.MustCompile(fmt.Sprintf(`Slot %d:\s+(\w+)`, slot))
	matches := slotPattern.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		return false, nil
	}

	return matches[1] == "programmed", nil
}
