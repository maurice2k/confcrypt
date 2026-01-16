package crypto

import (
	"bytes"
	"testing"

	"filippo.io/age"
)

func TestGenerateAESKey(t *testing.T) {
	key1, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	if len(key1) != 32 {
		t.Errorf("Expected 32 byte key, got %d bytes", len(key1))
	}

	// Generate another key and ensure they're different
	key2, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Error("Two generated keys should not be equal")
	}
}

func TestAESGCMRoundtrip(t *testing.T) {
	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hello")},
		{"medium", []byte("this is a medium length test string for encryption")},
		{"long", bytes.Repeat([]byte("x"), 10000)},
		{"unicode", []byte("Hello 世界 🌍")},
		{"binary", []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}},
	}

	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, iv, tag, err := EncryptAESGCM(key, tc.plaintext)
			if err != nil {
				t.Fatalf("EncryptAESGCM failed: %v", err)
			}

			// Verify IV is 12 bytes
			if len(iv) != 12 {
				t.Errorf("Expected 12 byte IV, got %d bytes", len(iv))
			}

			// Verify tag is 16 bytes
			if len(tag) != 16 {
				t.Errorf("Expected 16 byte tag, got %d bytes", len(tag))
			}

			// Decrypt
			decrypted, err := DecryptAESGCM(key, ciphertext, iv, tag)
			if err != nil {
				t.Fatalf("DecryptAESGCM failed: %v", err)
			}

			if !bytes.Equal(decrypted, tc.plaintext) {
				t.Errorf("Decrypted text doesn't match original.\nExpected: %v\nGot: %v", tc.plaintext, decrypted)
			}
		})
	}
}

func TestAESGCMIVUniqueness(t *testing.T) {
	key, _ := GenerateAESKey()
	plaintext := []byte("test data")

	ivs := make(map[string]bool)
	for i := 0; i < 100; i++ {
		_, iv, _, err := EncryptAESGCM(key, plaintext)
		if err != nil {
			t.Fatalf("EncryptAESGCM failed: %v", err)
		}

		ivStr := string(iv)
		if ivs[ivStr] {
			t.Error("Generated duplicate IV")
		}
		ivs[ivStr] = true
	}
}

func TestAESGCMTamperedCiphertext(t *testing.T) {
	key, _ := GenerateAESKey()
	plaintext := []byte("sensitive data")

	ciphertext, iv, tag, err := EncryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptAESGCM failed: %v", err)
	}

	// Tamper with ciphertext
	if len(ciphertext) > 0 {
		tamperedCiphertext := make([]byte, len(ciphertext))
		copy(tamperedCiphertext, ciphertext)
		tamperedCiphertext[0] ^= 0xff

		_, err = DecryptAESGCM(key, tamperedCiphertext, iv, tag)
		if err == nil {
			t.Error("Expected decryption to fail with tampered ciphertext")
		}
	}

	// Tamper with tag
	tamperedTag := make([]byte, len(tag))
	copy(tamperedTag, tag)
	tamperedTag[0] ^= 0xff

	_, err = DecryptAESGCM(key, ciphertext, iv, tamperedTag)
	if err == nil {
		t.Error("Expected decryption to fail with tampered tag")
	}

	// Tamper with IV
	tamperedIV := make([]byte, len(iv))
	copy(tamperedIV, iv)
	tamperedIV[0] ^= 0xff

	_, err = DecryptAESGCM(key, ciphertext, tamperedIV, tag)
	if err == nil {
		t.Error("Expected decryption to fail with tampered IV")
	}
}

func TestAESGCMWrongKey(t *testing.T) {
	key1, _ := GenerateAESKey()
	key2, _ := GenerateAESKey()
	plaintext := []byte("secret message")

	ciphertext, iv, tag, err := EncryptAESGCM(key1, plaintext)
	if err != nil {
		t.Fatalf("EncryptAESGCM failed: %v", err)
	}

	_, err = DecryptAESGCM(key2, ciphertext, iv, tag)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key")
	}
}

func TestAgeKeypairGeneration(t *testing.T) {
	identity, err := GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("GenerateAgeKeypair failed: %v", err)
	}

	// Verify we can get the public key
	pubKey := identity.Recipient().String()
	if pubKey == "" {
		t.Error("Expected non-empty public key")
	}

	// Verify public key format
	if len(pubKey) < 10 || pubKey[:3] != "age" {
		t.Errorf("Invalid public key format: %s", pubKey)
	}
}

func TestAgeEncryptDecryptRoundtrip(t *testing.T) {
	identity, err := GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("GenerateAgeKeypair failed: %v", err)
	}

	testData := []byte("this is the AES key to encrypt")

	// Encrypt for the recipient
	encrypted, err := EncryptForRecipients(testData, []age.Recipient{identity.Recipient()})
	if err != nil {
		t.Fatalf("EncryptForRecipients failed: %v", err)
	}

	// Decrypt with identity
	decrypted, err := DecryptWithIdentities(encrypted, []age.Identity{identity})
	if err != nil {
		t.Fatalf("DecryptWithIdentities failed: %v", err)
	}

	if !bytes.Equal(decrypted, testData) {
		t.Errorf("Decrypted data doesn't match.\nExpected: %s\nGot: %s", testData, decrypted)
	}
}

func TestAgeMultipleRecipients(t *testing.T) {
	// Generate 3 keypairs
	identities := make([]*age.X25519Identity, 3)
	recipients := make([]age.Recipient, 3)

	for i := 0; i < 3; i++ {
		id, err := GenerateAgeKeypair()
		if err != nil {
			t.Fatalf("GenerateAgeKeypair failed: %v", err)
		}
		identities[i] = id
		recipients[i] = id.Recipient()
	}

	testData := []byte("shared secret for all recipients")

	// Encrypt for all recipients
	encrypted, err := EncryptForRecipients(testData, recipients)
	if err != nil {
		t.Fatalf("EncryptForRecipients failed: %v", err)
	}

	// Each identity should be able to decrypt
	for i, id := range identities {
		decrypted, err := DecryptWithIdentities(encrypted, []age.Identity{id})
		if err != nil {
			t.Errorf("Identity %d failed to decrypt: %v", i, err)
			continue
		}

		if !bytes.Equal(decrypted, testData) {
			t.Errorf("Identity %d decrypted wrong data.\nExpected: %s\nGot: %s", i, testData, decrypted)
		}
	}
}

func TestAgeWrongIdentity(t *testing.T) {
	identity1, _ := GenerateAgeKeypair()
	identity2, _ := GenerateAgeKeypair()

	testData := []byte("secret for identity1 only")

	// Encrypt only for identity1
	encrypted, err := EncryptForRecipients(testData, []age.Recipient{identity1.Recipient()})
	if err != nil {
		t.Fatalf("EncryptForRecipients failed: %v", err)
	}

	// identity2 should not be able to decrypt
	_, err = DecryptWithIdentities(encrypted, []age.Identity{identity2})
	if err == nil {
		t.Error("Expected decryption to fail with wrong identity")
	}
}

func TestParseAgeRecipient(t *testing.T) {
	// Generate a valid keypair to get a valid public key
	identity, _ := GenerateAgeKeypair()
	validPubKey := identity.Recipient().String()

	testCases := []struct {
		name    string
		pubKey  string
		wantErr bool
	}{
		{"valid", validPubKey, false},
		{"with_whitespace", "  " + validPubKey + "  ", false},
		{"invalid", "not-a-valid-key", true},
		{"empty", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAgeRecipient(tc.pubKey)
			if tc.wantErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestParseAgeIdentity(t *testing.T) {
	// Generate a valid keypair to get a valid private key
	identity, _ := GenerateAgeKeypair()
	validPrivKey := identity.String()

	testCases := []struct {
		name    string
		privKey string
		wantErr bool
	}{
		{"valid", validPrivKey, false},
		{"with_whitespace", "  " + validPrivKey + "  ", false},
		{"invalid", "not-a-valid-key", true},
		{"empty", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAgeIdentity(tc.privKey)
			if tc.wantErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestParseAgeIdentities(t *testing.T) {
	id1, _ := GenerateAgeKeypair()
	id2, _ := GenerateAgeKeypair()

	testCases := []struct {
		name      string
		content   string
		wantCount int
		wantErr   bool
	}{
		{"single", id1.String(), 1, false},
		{"multiple", id1.String() + "\n" + id2.String(), 2, false},
		{"with_comments", "# comment\n" + id1.String() + "\n# another comment", 1, false},
		{"with_empty_lines", "\n\n" + id1.String() + "\n\n", 1, false},
		{"empty", "", 0, true},
		{"only_comments", "# comment\n# another", 0, true},
		{"invalid_key", "invalid-key", 0, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			identities, err := ParseAgeIdentities(tc.content)
			if tc.wantErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tc.wantErr && len(identities) != tc.wantCount {
				t.Errorf("Expected %d identities, got %d", tc.wantCount, len(identities))
			}
		})
	}
}
