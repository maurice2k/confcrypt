package yubikey

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeRecipient(t *testing.T) {
	// Create a test identity
	original := &Identity{
		Serial:    12345678,
		Slot:      2,
		Challenge: make([]byte, ChallengeSize),
		PubKey:    make([]byte, 32),
	}

	// Fill with test data
	for i := range original.Challenge {
		original.Challenge[i] = byte(i)
	}
	for i := range original.PubKey {
		original.PubKey[i] = byte(i + 100)
	}

	// Encode
	encoded, err := EncodeRecipient(original)
	if err != nil {
		t.Fatalf("EncodeRecipient failed: %v", err)
	}

	// Verify prefix
	if !IsYubiKeyRecipient(encoded) {
		t.Errorf("encoded string should be a YubiKey recipient: %s", encoded)
	}

	t.Logf("Encoded recipient: %s", encoded)
	t.Logf("Length: %d characters", len(encoded))

	// Decode
	decoded, err := DecodeRecipient(encoded)
	if err != nil {
		t.Fatalf("DecodeRecipient failed: %v", err)
	}

	// Verify fields
	if decoded.Serial != original.Serial {
		t.Errorf("Serial mismatch: got %d, want %d", decoded.Serial, original.Serial)
	}
	if decoded.Slot != original.Slot {
		t.Errorf("Slot mismatch: got %d, want %d", decoded.Slot, original.Slot)
	}
	if !bytes.Equal(decoded.Challenge, original.Challenge) {
		t.Errorf("Challenge mismatch")
	}
	if !bytes.Equal(decoded.PubKey, original.PubKey) {
		t.Errorf("PubKey mismatch")
	}
}

func TestIsYubiKeyRecipient(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"age1yubikey1qpzry9x8gf2tvdw0s3jn54khce6mua7l", true},
		{"AGE1YUBIKEY1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L", true},
		{"age1qpzry9x8gf2tvdw0s3jn54khce6mua7l", false},
		{"ssh-ed25519 AAAA...", false},
		{"", false},
	}

	for _, tt := range tests {
		got := IsYubiKeyRecipient(tt.input)
		if got != tt.want {
			t.Errorf("IsYubiKeyRecipient(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestDecodeInvalidRecipient(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"wrong prefix", "age1xyz1qpzry9x8gf2tvdw0s3jn54khce6mua7l"},
		{"invalid checksum", "age1yubikey1qpzry9x8gf2tvdw0s3jn54khce6mua7x"},
		{"too short", "age1yubikey1qpzry"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeRecipient(tt.input)
			if err == nil {
				t.Errorf("expected error for input %q", tt.input)
			}
		})
	}
}
