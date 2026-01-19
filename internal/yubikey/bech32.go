package yubikey

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	// YubiKeyRecipientHRP is the human-readable part for YubiKey recipients
	YubiKeyRecipientHRP = "age1yubikey"

	// DataSize is the total size of encoded data: serial(4) + slot(1) + challenge(32) + pubkey(32) = 69 bytes
	DataSize = 4 + 1 + 32 + 32
)

var (
	// ErrInvalidYubiKeyRecipient is returned when parsing an invalid YubiKey recipient
	ErrInvalidYubiKeyRecipient = errors.New("invalid YubiKey recipient")

	// ErrInvalidChecksum is returned when bech32 checksum validation fails
	ErrInvalidChecksum = errors.New("invalid bech32 checksum")
)

// EncodeRecipient encodes a YubiKey identity to a bech32 recipient string
func EncodeRecipient(id *Identity) (string, error) {
	if len(id.Challenge) != ChallengeSize {
		return "", fmt.Errorf("invalid challenge size: got %d, want %d", len(id.Challenge), ChallengeSize)
	}
	if len(id.PubKey) != 32 {
		return "", fmt.Errorf("invalid public key size: got %d, want 32", len(id.PubKey))
	}

	// Pack data: serial(4) + slot(1) + challenge(32) + pubkey(32)
	data := make([]byte, DataSize)
	binary.BigEndian.PutUint32(data[0:4], id.Serial)
	data[4] = id.Slot
	copy(data[5:37], id.Challenge)
	copy(data[37:69], id.PubKey)

	// Convert to 5-bit groups for bech32
	conv, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}

	// Encode with bech32
	encoded, err := bech32Encode(YubiKeyRecipientHRP, conv)
	if err != nil {
		return "", fmt.Errorf("failed to encode bech32: %w", err)
	}

	return encoded, nil
}

// DecodeRecipient decodes a bech32 YubiKey recipient string to an Identity
func DecodeRecipient(recipient string) (*Identity, error) {
	recipient = strings.ToLower(recipient)

	// Decode bech32
	hrp, data, err := bech32Decode(recipient)
	if err != nil {
		return nil, fmt.Errorf("failed to decode bech32: %w", err)
	}

	if hrp != YubiKeyRecipientHRP {
		return nil, fmt.Errorf("%w: invalid prefix %q", ErrInvalidYubiKeyRecipient, hrp)
	}

	// Convert from 5-bit groups back to 8-bit
	dataBytes := intSliceToByteSlice(data)
	conv, err := convertBits(dataBytes, 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("failed to convert bits: %w", err)
	}

	convBytes := intSliceToByteSlice(conv)
	if len(convBytes) != DataSize {
		return nil, fmt.Errorf("%w: invalid data size %d", ErrInvalidYubiKeyRecipient, len(convBytes))
	}

	// Unpack data
	id := &Identity{
		Serial:    binary.BigEndian.Uint32(convBytes[0:4]),
		Slot:      convBytes[4],
		Challenge: make([]byte, ChallengeSize),
		PubKey:    make([]byte, 32),
	}
	copy(id.Challenge, convBytes[5:37])
	copy(id.PubKey, convBytes[37:69])

	return id, nil
}

// IsYubiKeyRecipient checks if a string is a YubiKey recipient
func IsYubiKeyRecipient(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), YubiKeyRecipientHRP+"1")
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
	// Standard bech32 limit is 90, but we need more for our 69-byte payload
	// age uses longer strings too, so we increase the limit
	if len(s) > 200 {
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

// convertBitsToBytes converts 5-bit groups back to bytes
func convertBitsToBytes(data []int) ([]byte, error) {
	conv, err := convertBits(intSliceToByteSlice(data), 5, 8, false)
	if err != nil {
		return nil, err
	}
	return intSliceToByteSlice(conv), nil
}

func intSliceToByteSlice(data []int) []byte {
	ret := make([]byte, len(data))
	for i, v := range data {
		ret[i] = byte(v)
	}
	return ret
}
