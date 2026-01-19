//go:build cgo

package fido2

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncodeDecodeRecipient(t *testing.T) {
	// Create a test identity
	credID := make([]byte, 64)
	salt := make([]byte, 32)
	aaguid := make([]byte, AAGUIDSize)
	pubKey := make([]byte, 32)

	rand.Read(credID)
	rand.Read(salt)
	rand.Read(aaguid)
	rand.Read(pubKey)

	id := &Identity{
		CredentialID: credID,
		Salt:         salt,
		RPID:         "confcrypt",
		RPIDHash:     hashRPID("confcrypt"),
		AAGUID:       aaguid,
		PubKey:       pubKey,
	}

	// Encode
	encoded, err := EncodeRecipient(id)
	if err != nil {
		t.Fatalf("EncodeRecipient failed: %v", err)
	}

	// Check prefix
	if !IsFIDO2Recipient(encoded) {
		t.Errorf("encoded string should be detected as FIDO2 recipient")
	}

	// Decode
	decoded, err := DecodeRecipient(encoded)
	if err != nil {
		t.Fatalf("DecodeRecipient failed: %v", err)
	}

	// Verify
	if !bytes.Equal(decoded.CredentialID, id.CredentialID) {
		t.Errorf("CredentialID mismatch")
	}
	if !bytes.Equal(decoded.Salt, id.Salt) {
		t.Errorf("Salt mismatch")
	}
	if decoded.RPID != id.RPID {
		t.Errorf("RPID mismatch: got %q, want %q", decoded.RPID, id.RPID)
	}
	if !bytes.Equal(decoded.RPIDHash, id.RPIDHash) {
		t.Errorf("RPIDHash mismatch")
	}
	if !bytes.Equal(decoded.AAGUID, id.AAGUID) {
		t.Errorf("AAGUID mismatch")
	}
	if !bytes.Equal(decoded.PubKey, id.PubKey) {
		t.Errorf("PubKey mismatch")
	}
}

func TestEncodeDecodeRecipientVariableCredID(t *testing.T) {
	// Test with different credential ID sizes
	sizes := []int{16, 32, 64, 128, 256}

	for _, size := range sizes {
		t.Run("credID_size_"+string(rune('0'+size/100))+string(rune('0'+(size%100)/10))+string(rune('0'+size%10)), func(t *testing.T) {
			credID := make([]byte, size)
			salt := make([]byte, 32)
			aaguid := make([]byte, AAGUIDSize)
			pubKey := make([]byte, 32)

			rand.Read(credID)
			rand.Read(salt)
			rand.Read(aaguid)
			rand.Read(pubKey)

			id := &Identity{
				CredentialID: credID,
				Salt:         salt,
				RPID:         "test.example.com",
				RPIDHash:     hashRPID("test.example.com"),
				AAGUID:       aaguid,
				PubKey:       pubKey,
			}

			encoded, err := EncodeRecipient(id)
			if err != nil {
				t.Fatalf("EncodeRecipient failed for size %d: %v", size, err)
			}

			decoded, err := DecodeRecipient(encoded)
			if err != nil {
				t.Fatalf("DecodeRecipient failed for size %d: %v", size, err)
			}

			if !bytes.Equal(decoded.CredentialID, id.CredentialID) {
				t.Errorf("CredentialID mismatch for size %d", size)
			}
			if decoded.RPID != id.RPID {
				t.Errorf("RPID mismatch for size %d", size)
			}
			if !bytes.Equal(decoded.AAGUID, id.AAGUID) {
				t.Errorf("AAGUID mismatch for size %d", size)
			}
		})
	}
}

func TestIsFIDO2Recipient(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"age1fido21qpzry9x8gf2tvdw0s3jn54khce6mua7l", true},
		{"AGE1FIDO21QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L", true},
		{"age1yubikey1qpzry9x8gf2tvdw0s3jn54khce6mua7l", false},
		{"age1qpzry9x8gf2tvdw0s3jn54khce6mua7l", false},
		{"", false},
	}

	for _, tt := range tests {
		result := IsFIDO2Recipient(tt.input)
		if result != tt.expected {
			t.Errorf("IsFIDO2Recipient(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestInvalidRecipients(t *testing.T) {
	// Test with invalid credential ID size (too small)
	smallCredID := make([]byte, 8)
	rand.Read(smallCredID)

	id := &Identity{
		CredentialID: smallCredID,
		Salt:         make([]byte, 32),
		RPID:         "confcrypt",
		AAGUID:       make([]byte, AAGUIDSize),
		PubKey:       make([]byte, 32),
	}

	_, err := EncodeRecipient(id)
	if err == nil {
		t.Error("expected error for small credential ID")
	}

	// Test with invalid salt size
	id.CredentialID = make([]byte, 64)
	id.Salt = make([]byte, 16)
	_, err = EncodeRecipient(id)
	if err == nil {
		t.Error("expected error for invalid salt size")
	}

	// Test with empty RPID
	id.Salt = make([]byte, 32)
	id.RPID = ""
	_, err = EncodeRecipient(id)
	if err == nil {
		t.Error("expected error for empty RPID")
	}

	// Test with invalid AAGUID size
	id.RPID = "confcrypt"
	id.AAGUID = make([]byte, 8) // Wrong size
	_, err = EncodeRecipient(id)
	if err == nil {
		t.Error("expected error for invalid AAGUID size")
	}
}
