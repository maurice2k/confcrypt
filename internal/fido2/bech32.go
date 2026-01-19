//go:build cgo

package fido2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	// FIDO2RecipientHRP is the human-readable part for FIDO2 recipients
	FIDO2RecipientHRP = "age1fido2"

	// MinCredentialIDSize is the minimum size of a credential ID
	MinCredentialIDSize = 16

	// MaxCredentialIDSize is the maximum size of a credential ID
	MaxCredentialIDSize = 256
)

var (
	// ErrInvalidFIDO2Recipient is returned when parsing an invalid FIDO2 recipient
	ErrInvalidFIDO2Recipient = errors.New("invalid FIDO2 recipient")

	// ErrInvalidChecksum is returned when bech32 checksum validation fails
	ErrInvalidChecksum = errors.New("invalid bech32 checksum")
)

// EncodeRecipient encodes a FIDO2 identity to a bech32 recipient string
// Format: credIDLen(2) + credID(variable) + rpIDLen(1) + rpID(variable) + aaguid(16) + salt(32) + pubkey(32)
func EncodeRecipient(id *Identity) (string, error) {
	if len(id.CredentialID) < MinCredentialIDSize || len(id.CredentialID) > MaxCredentialIDSize {
		return "", fmt.Errorf("invalid credential ID size: got %d, want %d-%d", len(id.CredentialID), MinCredentialIDSize, MaxCredentialIDSize)
	}
	if len(id.Salt) != SaltSize {
		return "", fmt.Errorf("invalid salt size: got %d, want %d", len(id.Salt), SaltSize)
	}
	if len(id.RPID) == 0 || len(id.RPID) > 255 {
		return "", fmt.Errorf("invalid RP ID length: got %d, want 1-255", len(id.RPID))
	}
	if len(id.AAGUID) != AAGUIDSize {
		return "", fmt.Errorf("invalid AAGUID size: got %d, want %d", len(id.AAGUID), AAGUIDSize)
	}
	if len(id.PubKey) != 32 {
		return "", fmt.Errorf("invalid public key size: got %d, want 32", len(id.PubKey))
	}

	// Calculate total data size: credIDLen(2) + credID + rpIDLen(1) + rpID + aaguid(16) + salt(32) + pubkey(32)
	dataSize := 2 + len(id.CredentialID) + 1 + len(id.RPID) + AAGUIDSize + 32 + 32

	// Pack data
	data := make([]byte, dataSize)
	binary.BigEndian.PutUint16(data[0:2], uint16(len(id.CredentialID)))
	offset := 2
	copy(data[offset:offset+len(id.CredentialID)], id.CredentialID)
	offset += len(id.CredentialID)
	data[offset] = byte(len(id.RPID))
	offset++
	copy(data[offset:offset+len(id.RPID)], []byte(id.RPID))
	offset += len(id.RPID)
	copy(data[offset:offset+AAGUIDSize], id.AAGUID)
	offset += AAGUIDSize
	copy(data[offset:offset+32], id.Salt)
	offset += 32
	copy(data[offset:offset+32], id.PubKey)

	// Convert to 5-bit groups for bech32
	conv, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}

	// Encode with bech32
	encoded, err := bech32Encode(FIDO2RecipientHRP, conv)
	if err != nil {
		return "", fmt.Errorf("failed to encode bech32: %w", err)
	}

	return encoded, nil
}

// DecodeRecipient decodes a bech32 FIDO2 recipient string to an Identity
func DecodeRecipient(recipient string) (*Identity, error) {
	recipient = strings.ToLower(recipient)

	// Decode bech32
	hrp, data, err := bech32Decode(recipient)
	if err != nil {
		return nil, fmt.Errorf("failed to decode bech32: %w", err)
	}

	if hrp != FIDO2RecipientHRP {
		return nil, fmt.Errorf("%w: invalid prefix %q", ErrInvalidFIDO2Recipient, hrp)
	}

	// Convert from 5-bit groups back to 8-bit
	dataBytes := intSliceToByteSlice(data)
	conv, err := convertBits(dataBytes, 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("failed to convert bits: %w", err)
	}

	convBytes := intSliceToByteSlice(conv)

	// Minimum size: credIDLen(2) + minCredID(16) + rpIDLen(1) + minRPID(1) + aaguid(16) + salt(32) + pubkey(32) = 100
	if len(convBytes) < 2+MinCredentialIDSize+1+1+AAGUIDSize+32+32 {
		return nil, fmt.Errorf("%w: data too short", ErrInvalidFIDO2Recipient)
	}

	// Read credential ID length
	credIDLen := int(binary.BigEndian.Uint16(convBytes[0:2]))
	if credIDLen < MinCredentialIDSize || credIDLen > MaxCredentialIDSize {
		return nil, fmt.Errorf("%w: invalid credential ID length %d", ErrInvalidFIDO2Recipient, credIDLen)
	}

	// Check we have enough data for rpIDLen
	if len(convBytes) < 2+credIDLen+1 {
		return nil, fmt.Errorf("%w: data too short for rpID length", ErrInvalidFIDO2Recipient)
	}

	// Read RP ID length
	rpIDLen := int(convBytes[2+credIDLen])
	if rpIDLen == 0 || rpIDLen > 255 {
		return nil, fmt.Errorf("%w: invalid RP ID length %d", ErrInvalidFIDO2Recipient, rpIDLen)
	}

	// Expected size now includes AAGUID
	expectedSize := 2 + credIDLen + 1 + rpIDLen + AAGUIDSize + 32 + 32
	if len(convBytes) != expectedSize {
		return nil, fmt.Errorf("%w: invalid data size %d, expected %d", ErrInvalidFIDO2Recipient, len(convBytes), expectedSize)
	}

	// Unpack data
	id := &Identity{
		CredentialID: make([]byte, credIDLen),
		AAGUID:       make([]byte, AAGUIDSize),
		Salt:         make([]byte, 32),
		PubKey:       make([]byte, 32),
	}

	offset := 2
	copy(id.CredentialID, convBytes[offset:offset+credIDLen])
	offset += credIDLen
	offset++ // skip rpIDLen byte (already read)
	id.RPID = string(convBytes[offset : offset+rpIDLen])
	id.RPIDHash = hashRPID(id.RPID)
	offset += rpIDLen
	copy(id.AAGUID, convBytes[offset:offset+AAGUIDSize])
	offset += AAGUIDSize
	copy(id.Salt, convBytes[offset:offset+32])
	offset += 32
	copy(id.PubKey, convBytes[offset:offset+32])

	return id, nil
}

// IsFIDO2Recipient checks if a string is a FIDO2 recipient
func IsFIDO2Recipient(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), FIDO2RecipientHRP+"1")
}

// bech32 charset
const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var charsetRev = [128]int8{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1,
	-1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
	1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
	-1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
	1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
}

// bech32Polymod computes the bech32 checksum
func bech32Polymod(values []int) int {
	gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// bech32HRPExpand expands the HRP for checksum computation
func bech32HRPExpand(hrp string) []int {
	ret := make([]int, len(hrp)*2+1)
	for i, c := range hrp {
		ret[i] = int(c) >> 5
	}
	ret[len(hrp)] = 0
	for i, c := range hrp {
		ret[len(hrp)+1+i] = int(c) & 31
	}
	return ret
}

// bech32VerifyChecksum verifies the bech32 checksum
func bech32VerifyChecksum(hrp string, data []int) bool {
	values := append(bech32HRPExpand(hrp), data...)
	return bech32Polymod(values) == 1
}

// bech32CreateChecksum creates a bech32 checksum
func bech32CreateChecksum(hrp string, data []int) []int {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ 1
	ret := make([]int, 6)
	for i := 0; i < 6; i++ {
		ret[i] = (polymod >> (5 * (5 - i))) & 31
	}
	return ret
}

// bech32Encode encodes data to bech32
func bech32Encode(hrp string, data []int) (string, error) {
	combined := append(data, bech32CreateChecksum(hrp, data)...)
	ret := hrp + "1"
	for _, d := range combined {
		ret += string(charset[d])
	}
	return ret, nil
}

// bech32Decode decodes a bech32 string
func bech32Decode(s string) (string, []int, error) {
	// FIDO2 credential IDs can be large, so we need a generous limit
	// Max data: credIDLen(2) + credID(256) + rpIDLen(1) + rpID(255) + salt(32) + pubkey(32) = 578 bytes
	// 578 bytes * 8/5 = ~925 5-bit groups + HRP(9) + separator(1) + checksum(6) = ~941
	if len(s) > 1000 {
		return "", nil, errors.New("bech32 string too long")
	}

	// Find separator
	pos := strings.LastIndex(s, "1")
	if pos < 1 || pos+7 > len(s) {
		return "", nil, errors.New("invalid bech32 separator position")
	}

	hrp := s[:pos]
	dataStr := s[pos+1:]

	// Decode data
	data := make([]int, len(dataStr))
	for i, c := range dataStr {
		if c >= 128 || charsetRev[c] == -1 {
			return "", nil, fmt.Errorf("invalid bech32 character: %c", c)
		}
		data[i] = int(charsetRev[c])
	}

	// Verify checksum
	if !bech32VerifyChecksum(hrp, data) {
		return "", nil, ErrInvalidChecksum
	}

	// Remove checksum
	return hrp, data[:len(data)-6], nil
}

// convertBits converts a byte slice from one bit grouping to another
func convertBits(data []byte, fromBits, toBits int, pad bool) ([]int, error) {
	acc := 0
	bits := 0
	ret := make([]int, 0, len(data)*fromBits/toBits+1)
	maxv := (1 << toBits) - 1

	for _, value := range data {
		acc = (acc << fromBits) | int(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			ret = append(ret, (acc>>bits)&maxv)
		}
	}

	if pad {
		if bits > 0 {
			ret = append(ret, (acc<<(toBits-bits))&maxv)
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, errors.New("invalid padding")
	}

	return ret, nil
}

func intSliceToByteSlice(data []int) []byte {
	ret := make([]byte, len(data))
	for i, v := range data {
		ret[i] = byte(v)
	}
	return ret
}
