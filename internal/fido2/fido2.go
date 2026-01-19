//go:build cgo

// Package fido2 provides FIDO2 hmac-secret support for deriving age keys.
package fido2

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/keys-pub/go-libfido2"
	"golang.org/x/crypto/curve25519"
)

const (
	// SaltSize is the size of the salt for hmac-secret in bytes
	SaltSize = 32

	// DefaultRPID is the default relying party ID
	DefaultRPID = "confcrypt"
)

var (
	// ErrNoDevice is returned when no FIDO2 device is detected
	ErrNoDevice = errors.New("no FIDO2 device detected")

	// ErrHMACSecretNotSupported is returned when the device doesn't support hmac-secret
	ErrHMACSecretNotSupported = errors.New("device does not support hmac-secret extension")

	// ErrDeviceNotFound is returned when a specific device is not found
	ErrDeviceNotFound = errors.New("FIDO2 device not found")

	// ErrCredentialNotFound is returned when credential assertion fails
	ErrCredentialNotFound = errors.New("credential not found on device")
)

// Device represents a connected FIDO2 device
type Device struct {
	Path         string
	ProductInfo  string
	Manufacturer string
	Product      string
	VendorID     int16
	ProductID    int16
}

// AAGUIDSize is the size of the AAGUID in bytes
const AAGUIDSize = 16

// Identity holds the data needed to derive an age key from a FIDO2 device
type Identity struct {
	CredentialID []byte // Variable length credential ID
	Salt         []byte // 32 bytes
	RPID         string // Relying party ID
	RPIDHash     []byte // 32 bytes SHA256 hash of RPID
	AAGUID       []byte // 16 bytes - device identifier for pre-touch matching
	PubKey       []byte // 32 bytes (X25519 public key)
}

// DetectDevices returns a list of connected FIDO2 devices
func DetectDevices() ([]Device, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("failed to detect FIDO2 devices: %w", err)
	}

	var devices []Device
	for _, loc := range locs {
		devices = append(devices, Device{
			Path:         loc.Path,
			ProductInfo:  fmt.Sprintf("%s %s", loc.Manufacturer, loc.Product),
			Manufacturer: loc.Manufacturer,
			Product:      loc.Product,
			VendorID:     loc.VendorID,
			ProductID:    loc.ProductID,
		})
	}

	return devices, nil
}

// GetFirstDevice returns the first connected FIDO2 device
func GetFirstDevice() (*Device, error) {
	devices, err := DetectDevices()
	if err != nil {
		return nil, err
	}

	if len(devices) == 0 {
		return nil, ErrNoDevice
	}

	return &devices[0], nil
}

// FindDeviceByAAGUID finds a connected FIDO2 device by its AAGUID
func FindDeviceByAAGUID(aaguid []byte) (*Device, error) {
	devices, err := DetectDevices()
	if err != nil {
		return nil, err
	}

	if len(devices) == 0 {
		return nil, ErrNoDevice
	}

	for _, dev := range devices {
		device, err := libfido2.NewDevice(dev.Path)
		if err != nil {
			continue
		}

		info, err := device.Info()
		if err != nil {
			continue
		}

		if len(info.AAGUID) == AAGUIDSize && bytesEqual(info.AAGUID, aaguid) {
			return &dev, nil
		}
	}

	return nil, ErrDeviceNotFound
}

// bytesEqual compares two byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SupportsHMACSecret checks if the device supports the hmac-secret extension
func SupportsHMACSecret(devicePath string) (bool, error) {
	device, err := libfido2.NewDevice(devicePath)
	if err != nil {
		return false, fmt.Errorf("failed to open device: %w", err)
	}
	// Note: go-libfido2 doesn't expose Close() publicly, device is closed when GC'd

	info, err := device.Info()
	if err != nil {
		return false, fmt.Errorf("failed to get device info: %w", err)
	}

	for _, ext := range info.Extensions {
		if ext == "hmac-secret" {
			return true, nil
		}
	}

	return false, nil
}

// GenerateSalt generates a random salt for hmac-secret
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// DeviceInfo contains cached device information
type DeviceInfo struct {
	Path         string
	ProductInfo  string
	Serial       string
	SupportsHMAC bool
	RequiresPIN  bool
}

// GetDeviceInfo gets all device info in a single call to avoid multiple touches
func GetDeviceInfo(devicePath string) (*DeviceInfo, error) {
	device, err := libfido2.NewDevice(devicePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open device: %w", err)
	}

	info, err := device.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get device info: %w", err)
	}

	devInfo := &DeviceInfo{
		Path:        devicePath,
		ProductInfo: info.Versions[0], // Use first version as product info
	}

	// Try to get serial from AAGUID (last 4 bytes for YubiKey)
	// AAGUID format for YubiKey includes serial in some cases
	if len(info.AAGUID) >= 16 {
		// Format AAGUID as hex for display
		devInfo.Serial = fmt.Sprintf("%x", info.AAGUID)
	}

	// Check for hmac-secret support
	for _, ext := range info.Extensions {
		if ext == "hmac-secret" {
			devInfo.SupportsHMAC = true
			break
		}
	}

	// Check if clientPin option is set and PIN is configured
	for _, opt := range info.Options {
		if opt.Name == "clientPin" && opt.Value == libfido2.True {
			devInfo.RequiresPIN = true
			break
		}
	}

	return devInfo, nil
}

// DeviceRequiresPIN checks if the device requires a PIN for operations
func DeviceRequiresPIN(devicePath string) bool {
	info, err := GetDeviceInfo(devicePath)
	if err != nil {
		return false
	}
	return info.RequiresPIN
}

// hashRPID returns the SHA256 hash of the relying party ID
func hashRPID(rpID string) []byte {
	h := sha256.Sum256([]byte(rpID))
	return h[:]
}

// PartialIdentity holds credential data before key derivation
type PartialIdentity struct {
	CredentialID []byte
	Salt         []byte
	RPID         string
	AAGUID       []byte // 16 bytes - captured from device during credential creation
}

// CreateCredentialStep1 creates a FIDO2 credential (requires touch)
// Returns a partial identity that needs Step2 to derive the key
func CreateCredentialStep1(devicePath, rpID, pin string) (*PartialIdentity, error) {
	device, err := libfido2.NewDevice(devicePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open device: %w", err)
	}

	// Check hmac-secret support using the already-open device
	info, err := device.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get device info: %w", err)
	}
	hasHMACSecret := false
	for _, ext := range info.Extensions {
		if ext == string(libfido2.HMACSecretExtension) {
			hasHMACSecret = true
			break
		}
	}
	if !hasHMACSecret {
		return nil, ErrHMACSecretNotSupported
	}

	// Capture AAGUID from device info
	var aaguid []byte
	if len(info.AAGUID) == AAGUIDSize {
		aaguid = make([]byte, AAGUIDSize)
		copy(aaguid, info.AAGUID)
	} else {
		// Fallback: use zero AAGUID if not available
		aaguid = make([]byte, AAGUIDSize)
	}

	// Generate random user ID and salt
	userID := make([]byte, 32)
	if _, err := rand.Read(userID); err != nil {
		return nil, fmt.Errorf("failed to generate user ID: %w", err)
	}

	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}

	// Generate client data hash (random for our use case)
	cdh := make([]byte, 32)
	if _, err := rand.Read(cdh); err != nil {
		return nil, fmt.Errorf("failed to generate client data hash: %w", err)
	}

	// Create relying party and user
	rp := libfido2.RelyingParty{
		ID:   rpID,
		Name: rpID,
	}

	user := libfido2.User{
		ID:          userID,
		Name:        "confcrypt-user",
		DisplayName: "confcrypt user",
	}

	// Make credential with hmac-secret extension
	opts := &libfido2.MakeCredentialOpts{
		Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
		RK:         libfido2.False, // Non-discoverable credential
	}

	attest, err := device.MakeCredential(cdh, rp, user, libfido2.ES256, pin, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	return &PartialIdentity{
		CredentialID: attest.CredentialID,
		Salt:         salt,
		RPID:         rpID,
		AAGUID:       aaguid,
	}, nil
}

// CreateCredentialStep2 derives the key from the credential (requires touch)
func CreateCredentialStep2(devicePath string, partial *PartialIdentity, pin string) (*Identity, error) {
	device, err := libfido2.NewDevice(devicePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open device: %w", err)
	}

	// Perform an assertion to get the hmac-secret output
	secret, err := getHMACSecret(device, partial.RPID, partial.CredentialID, partial.Salt, pin)
	if err != nil {
		return nil, fmt.Errorf("failed to get hmac-secret: %w", err)
	}

	// Derive X25519 key pair from the secret
	_, pubKey, err := DeriveAgeKeyPair(secret, partial.Salt)
	if err != nil {
		return nil, err
	}

	return &Identity{
		CredentialID: partial.CredentialID,
		Salt:         partial.Salt,
		RPID:         partial.RPID,
		RPIDHash:     hashRPID(partial.RPID),
		AAGUID:       partial.AAGUID,
		PubKey:       pubKey,
	}, nil
}

// CreateCredential creates a new FIDO2 credential with hmac-secret extension (two touches)
func CreateCredential(devicePath, rpID, pin string) (*Identity, error) {
	partial, err := CreateCredentialStep1(devicePath, rpID, pin)
	if err != nil {
		return nil, err
	}
	return CreateCredentialStep2(devicePath, partial, pin)
}

// getHMACSecret performs an assertion and retrieves the hmac-secret output
func getHMACSecret(device *libfido2.Device, rpID string, credentialID, salt []byte, pin string) ([]byte, error) {
	// Generate client data hash
	cdh := make([]byte, 32)
	if _, err := rand.Read(cdh); err != nil {
		return nil, fmt.Errorf("failed to generate client data hash: %w", err)
	}

	opts := &libfido2.AssertionOpts{
		Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
		UP:         libfido2.True, // Require user presence (touch)
		HMACSalt:   salt,
	}

	assertion, err := device.Assertion(rpID, cdh, [][]byte{credentialID}, pin, opts)
	if err != nil {
		return nil, fmt.Errorf("assertion failed: %w", err)
	}

	if len(assertion.HMACSecret) == 0 {
		return nil, errors.New("hmac-secret not returned by device")
	}

	return assertion.HMACSecret, nil
}

// DeriveSecret derives the hmac-secret from a FIDO2 device using stored identity
func DeriveSecret(devicePath string, id *Identity, pin string) ([]byte, error) {
	device, err := libfido2.NewDevice(devicePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open device: %w", err)
	}

	return getHMACSecret(device, id.RPID, id.CredentialID, id.Salt, pin)
}

// DeriveAgeKeyPair derives an X25519 key pair from a FIDO2 hmac-secret
func DeriveAgeKeyPair(secret, salt []byte) (privateKey, publicKey []byte, err error) {
	// seed = SHA256(secret || salt)
	h := sha256.New()
	h.Write(secret)
	h.Write(salt)
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

// DerivePrivateKey derives the age private key from a FIDO2 identity
func (id *Identity) DerivePrivateKey(devicePath, pin string) ([]byte, error) {
	secret, err := DeriveSecret(devicePath, id, pin)
	if err != nil {
		return nil, err
	}

	privKey, pubKey, err := DeriveAgeKeyPair(secret, id.Salt)
	if err != nil {
		return nil, err
	}

	// Verify public key matches
	if len(pubKey) != len(id.PubKey) {
		return nil, errors.New("derived public key does not match; wrong device or credential?")
	}
	for i := range pubKey {
		if pubKey[i] != id.PubKey[i] {
			return nil, errors.New("derived public key does not match; wrong device or credential?")
		}
	}

	return privKey, nil
}

// GenerateIdentity generates a new FIDO2-derived age identity
func GenerateIdentity(devicePath, rpID, pin string) (*Identity, error) {
	if rpID == "" {
		rpID = DefaultRPID
	}

	return CreateCredential(devicePath, rpID, pin)
}
