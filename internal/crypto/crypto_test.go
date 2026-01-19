package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
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

func TestDetectKeyType(t *testing.T) {
	ageIdentity, _ := GenerateAgeKeypair()
	agePubKey := ageIdentity.Recipient().String()

	testCases := []struct {
		name     string
		pubKey   string
		expected KeyType
	}{
		{"age_key", agePubKey, KeyTypeAge},
		{"yubikey", "age1yubikey1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", KeyTypeYubiKey},
		{"fido2", "age1fido21qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", KeyTypeFIDO2},
		{"ssh_ed25519", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest test@example.com", KeyTypeSSHEd25519},
		{"ssh_rsa", "ssh-rsa AAAAB3NzaC1yc2EAAAAtest test@example.com", KeyTypeSSHRSA},
		{"ecdsa", "ecdsa-sha2-nistp256 AAAAE2VjZHNhtest test@example.com", KeyTypeSSHECDSA},
		{"unknown", "some-random-string", KeyTypeUnknown},
		{"empty", "", KeyTypeUnknown},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := DetectKeyType(tc.pubKey)
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestIsSSHKey(t *testing.T) {
	ageIdentity, _ := GenerateAgeKeypair()
	agePubKey := ageIdentity.Recipient().String()

	testCases := []struct {
		name     string
		pubKey   string
		expected bool
	}{
		{"age_key", agePubKey, false},
		{"ssh_ed25519", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest test@example.com", true},
		{"ssh_rsa", "ssh-rsa AAAAB3NzaC1yc2EAAAAtest test@example.com", true},
		{"ecdsa", "ecdsa-sha2-nistp256 AAAAE2VjZHNhtest test@example.com", true},
		{"unknown", "some-random-string", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsSSHKey(tc.pubKey)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestParseSSHEd25519Recipient(t *testing.T) {
	// Generate a real SSH ed25519 key for testing
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to create SSH public key: %v", err)
	}
	pubKeyStr := string(ssh.MarshalAuthorizedKey(sshPub))

	// Test parsing with ParseRecipient
	recipient, err := ParseRecipient(pubKeyStr)
	if err != nil {
		t.Fatalf("ParseRecipient failed for SSH ed25519 key: %v", err)
	}

	if recipient == nil {
		t.Error("Expected non-nil recipient")
	}

	// Verify it's the right type
	if _, ok := recipient.(*agessh.Ed25519Recipient); !ok {
		t.Errorf("Expected *agessh.Ed25519Recipient, got %T", recipient)
	}
}

func TestParseSSHEd25519Identity(t *testing.T) {
	// Generate a real SSH ed25519 key for testing
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	// Convert private key to PEM format
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	sshPrivKeyPEM := string(pem.EncodeToMemory(pemBlock))

	// Test parsing with ParseIdentity
	identity, err := ParseIdentity(sshPrivKeyPEM)
	if err != nil {
		t.Fatalf("ParseIdentity failed for SSH ed25519 key: %v", err)
	}

	if identity == nil {
		t.Error("Expected non-nil identity")
	}

	// Verify it's the right type
	if _, ok := identity.(*agessh.Ed25519Identity); !ok {
		t.Errorf("Expected *agessh.Ed25519Identity, got %T", identity)
	}
}

func TestSSHEd25519EncryptDecryptRoundtrip(t *testing.T) {
	// Generate SSH ed25519 keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	// Create SSH identity
	identity, err := agessh.NewEd25519Identity(priv)
	if err != nil {
		t.Fatalf("Failed to create SSH identity: %v", err)
	}

	// Create SSH recipient from public key
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to create SSH public key: %v", err)
	}
	recipient, err := agessh.NewEd25519Recipient(sshPub)
	if err != nil {
		t.Fatalf("Failed to create SSH recipient: %v", err)
	}

	testData := []byte("this is test data for SSH ed25519 encryption")

	// Encrypt for the SSH recipient
	encrypted, err := EncryptForRecipients(testData, []age.Recipient{recipient})
	if err != nil {
		t.Fatalf("EncryptForRecipients failed: %v", err)
	}

	// Decrypt with SSH identity
	decrypted, err := DecryptWithIdentities(encrypted, []age.Identity{identity})
	if err != nil {
		t.Fatalf("DecryptWithIdentities failed: %v", err)
	}

	if !bytes.Equal(decrypted, testData) {
		t.Errorf("Decrypted data doesn't match.\nExpected: %s\nGot: %s", testData, decrypted)
	}
}

func TestParseIdentitiesWithSSHKey(t *testing.T) {
	// Generate SSH ed25519 key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	sshPrivKeyPEM := string(pem.EncodeToMemory(pemBlock))

	// Test ParseIdentities with SSH key
	identities, err := ParseIdentities(sshPrivKeyPEM)
	if err != nil {
		t.Fatalf("ParseIdentities failed for SSH key: %v", err)
	}

	if len(identities) != 1 {
		t.Errorf("Expected 1 identity, got %d", len(identities))
	}

	if _, ok := identities[0].(*agessh.Ed25519Identity); !ok {
		t.Errorf("Expected *agessh.Ed25519Identity, got %T", identities[0])
	}
}

func TestMixedAgeAndSSHRecipients(t *testing.T) {
	// Generate age keypair
	ageIdentity, err := GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate age keypair: %v", err)
	}

	// Generate SSH ed25519 keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	sshIdentity, err := agessh.NewEd25519Identity(priv)
	if err != nil {
		t.Fatalf("Failed to create SSH identity: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to create SSH public key: %v", err)
	}
	sshRecipient, err := agessh.NewEd25519Recipient(sshPub)
	if err != nil {
		t.Fatalf("Failed to create SSH recipient: %v", err)
	}

	// Mix age and SSH recipients
	recipients := []age.Recipient{ageIdentity.Recipient(), sshRecipient}
	testData := []byte("shared secret for mixed recipients")

	// Encrypt for both
	encrypted, err := EncryptForRecipients(testData, recipients)
	if err != nil {
		t.Fatalf("EncryptForRecipients failed: %v", err)
	}

	// Age identity should decrypt
	decrypted, err := DecryptWithIdentities(encrypted, []age.Identity{ageIdentity})
	if err != nil {
		t.Fatalf("Age identity failed to decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, testData) {
		t.Error("Age decrypted wrong data")
	}

	// SSH identity should also decrypt
	decrypted, err = DecryptWithIdentities(encrypted, []age.Identity{sshIdentity})
	if err != nil {
		t.Fatalf("SSH identity failed to decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, testData) {
		t.Error("SSH decrypted wrong data")
	}
}

func TestParseRecipientAutoDetection(t *testing.T) {
	// Generate age key
	ageIdentity, _ := GenerateAgeKeypair()
	agePubKey := ageIdentity.Recipient().String()

	// Generate SSH ed25519 key
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	sshPubKey := string(ssh.MarshalAuthorizedKey(sshPub))

	testCases := []struct {
		name         string
		pubKey       string
		expectedType string
		wantErr      bool
	}{
		{"age_key", agePubKey, "*age.X25519Recipient", false},
		{"ssh_ed25519", sshPubKey, "*agessh.Ed25519Recipient", false},
		{"invalid", "not-a-valid-key", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recipient, err := ParseRecipient(tc.pubKey)
			if tc.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			typeName := ""
			switch recipient.(type) {
			case *age.X25519Recipient:
				typeName = "*age.X25519Recipient"
			case *agessh.Ed25519Recipient:
				typeName = "*agessh.Ed25519Recipient"
			case *agessh.RSARecipient:
				typeName = "*agessh.RSARecipient"
			}

			if typeName != tc.expectedType {
				t.Errorf("Expected %s, got %s", tc.expectedType, typeName)
			}
		})
	}
}

// TestMixedRecipientsEndToEnd is an integration test that encrypts data for both
// an age recipient and an SSH recipient using string parsing (like SaveEncryptedSecrets does)
func TestMixedRecipientsEndToEnd(t *testing.T) {
	// Generate age keypair
	ageIdentity, err := GenerateAgeKeypair()
	if err != nil {
		t.Fatalf("Failed to generate age keypair: %v", err)
	}
	agePubKeyStr := ageIdentity.Recipient().String()
	agePrivKeyStr := ageIdentity.String()

	// Generate SSH ed25519 keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	// Convert to SSH public key string format
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to create SSH public key: %v", err)
	}
	sshPubKeyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " test@example.com"

	// Convert to SSH private key PEM format
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("Failed to marshal SSH private key: %v", err)
	}
	sshPrivKeyStr := string(pem.EncodeToMemory(pemBlock))

	// Parse recipients from strings (like SaveEncryptedSecrets does)
	ageRecipient, err := ParseRecipient(agePubKeyStr)
	if err != nil {
		t.Fatalf("Failed to parse age recipient: %v", err)
	}

	sshRecipient, err := ParseRecipient(sshPubKeyStr)
	if err != nil {
		t.Fatalf("Failed to parse SSH recipient: %v", err)
	}

	// Encrypt for both recipients
	testData := []byte("this is sensitive config data encrypted for both age and SSH recipients")
	recipients := []age.Recipient{ageRecipient, sshRecipient}

	encrypted, err := EncryptForRecipients(testData, recipients)
	if err != nil {
		t.Fatalf("EncryptForRecipients failed: %v", err)
	}

	// Parse identities from strings and decrypt
	t.Run("decrypt_with_age_identity", func(t *testing.T) {
		identity, err := ParseIdentity(agePrivKeyStr)
		if err != nil {
			t.Fatalf("Failed to parse age identity: %v", err)
		}

		decrypted, err := DecryptWithIdentities(encrypted, []age.Identity{identity})
		if err != nil {
			t.Fatalf("Age identity failed to decrypt: %v", err)
		}
		if !bytes.Equal(decrypted, testData) {
			t.Errorf("Age decrypted wrong data: got %q, want %q", decrypted, testData)
		}
	})

	t.Run("decrypt_with_ssh_identity", func(t *testing.T) {
		identity, err := ParseIdentity(sshPrivKeyStr)
		if err != nil {
			t.Fatalf("Failed to parse SSH identity: %v", err)
		}

		decrypted, err := DecryptWithIdentities(encrypted, []age.Identity{identity})
		if err != nil {
			t.Fatalf("SSH identity failed to decrypt: %v", err)
		}
		if !bytes.Equal(decrypted, testData) {
			t.Errorf("SSH decrypted wrong data: got %q, want %q", decrypted, testData)
		}
	})

	// Also test ParseIdentities (used by loadIdentitiesFromFile)
	t.Run("decrypt_with_parsed_identities_age", func(t *testing.T) {
		identities, err := ParseIdentities(agePrivKeyStr)
		if err != nil {
			t.Fatalf("Failed to parse age identities: %v", err)
		}

		decrypted, err := DecryptWithIdentities(encrypted, identities)
		if err != nil {
			t.Fatalf("Age identities failed to decrypt: %v", err)
		}
		if !bytes.Equal(decrypted, testData) {
			t.Errorf("Age decrypted wrong data: got %q, want %q", decrypted, testData)
		}
	})

	t.Run("decrypt_with_parsed_identities_ssh", func(t *testing.T) {
		identities, err := ParseIdentities(sshPrivKeyStr)
		if err != nil {
			t.Fatalf("Failed to parse SSH identities: %v", err)
		}

		decrypted, err := DecryptWithIdentities(encrypted, identities)
		if err != nil {
			t.Fatalf("SSH identities failed to decrypt: %v", err)
		}
		if !bytes.Equal(decrypted, testData) {
			t.Errorf("SSH decrypted wrong data: got %q, want %q", decrypted, testData)
		}
	})
}

func TestParseIdentitiesWithPassphrase(t *testing.T) {
	// Generate an SSH ed25519 keypair
	_, sshPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	// Create passphrase-protected PEM
	passphrase := []byte("test-passphrase-123")
	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(sshPrivKey, "test@example.com", passphrase)
	if err != nil {
		t.Fatalf("Failed to marshal private key with passphrase: %v", err)
	}
	encryptedPEM := string(pem.EncodeToMemory(pemBlock))

	// Create unencrypted PEM for comparison
	unencryptedPemBlock, err := ssh.MarshalPrivateKey(sshPrivKey, "test@example.com")
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	unencryptedPEM := string(pem.EncodeToMemory(unencryptedPemBlock))

	t.Run("passphrase_protected_key_without_callback_fails", func(t *testing.T) {
		_, err := ParseIdentitiesWithPassphrase(encryptedPEM, "/path/to/key", nil)
		if err == nil {
			t.Error("Expected error for passphrase-protected key without callback")
		}
		if !strings.Contains(err.Error(), "passphrase") {
			t.Errorf("Expected passphrase-related error, got: %v", err)
		}
	})

	t.Run("passphrase_protected_key_with_callback_succeeds", func(t *testing.T) {
		callCount := 0
		passphraseFunc := func(keyPath string) ([]byte, error) {
			callCount++
			if keyPath != "/path/to/key" {
				t.Errorf("Expected keyPath '/path/to/key', got %q", keyPath)
			}
			return passphrase, nil
		}

		identities, err := ParseIdentitiesWithPassphrase(encryptedPEM, "/path/to/key", passphraseFunc)
		if err != nil {
			t.Fatalf("Failed to parse passphrase-protected key: %v", err)
		}
		if len(identities) != 1 {
			t.Fatalf("Expected 1 identity, got %d", len(identities))
		}
		// Note: passphrase callback is lazy - only called when Unwrap is invoked
		// So callCount might be 0 here
	})

	t.Run("passphrase_protected_key_wrong_passphrase", func(t *testing.T) {
		passphraseFunc := func(keyPath string) ([]byte, error) {
			return []byte("wrong-passphrase"), nil
		}

		identities, err := ParseIdentitiesWithPassphrase(encryptedPEM, "/path/to/key", passphraseFunc)
		if err != nil {
			t.Fatalf("Failed to create identity: %v", err)
		}

		// The error should occur when trying to use the identity
		// Create some test data to encrypt
		signer, err := ssh.NewSignerFromKey(sshPrivKey)
		if err != nil {
			t.Fatalf("Failed to create signer: %v", err)
		}
		recipient, err := agessh.NewEd25519Recipient(signer.PublicKey())
		if err != nil {
			t.Fatalf("Failed to create recipient: %v", err)
		}

		testData := []byte("test data for passphrase test")
		encrypted, err := EncryptForRecipients(testData, []age.Recipient{recipient})
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Decryption should fail with wrong passphrase
		_, err = DecryptWithIdentities(encrypted, identities)
		if err == nil {
			t.Error("Expected decryption to fail with wrong passphrase")
		}
	})

	t.Run("unencrypted_key_with_callback_succeeds", func(t *testing.T) {
		// Callback should not be called for unencrypted keys
		callCount := 0
		passphraseFunc := func(keyPath string) ([]byte, error) {
			callCount++
			return nil, nil
		}

		identities, err := ParseIdentitiesWithPassphrase(unencryptedPEM, "/path/to/key", passphraseFunc)
		if err != nil {
			t.Fatalf("Failed to parse unencrypted key: %v", err)
		}
		if len(identities) != 1 {
			t.Fatalf("Expected 1 identity, got %d", len(identities))
		}
		if callCount != 0 {
			t.Errorf("Passphrase callback should not be called for unencrypted keys, called %d times", callCount)
		}
	})

	t.Run("age_key_with_callback_succeeds", func(t *testing.T) {
		// Generate age key
		ageIdentity, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatalf("Failed to generate age identity: %v", err)
		}

		callCount := 0
		passphraseFunc := func(keyPath string) ([]byte, error) {
			callCount++
			return nil, nil
		}

		identities, err := ParseIdentitiesWithPassphrase(ageIdentity.String(), "/path/to/key", passphraseFunc)
		if err != nil {
			t.Fatalf("Failed to parse age key: %v", err)
		}
		if len(identities) != 1 {
			t.Fatalf("Expected 1 identity, got %d", len(identities))
		}
		if callCount != 0 {
			t.Errorf("Passphrase callback should not be called for age keys, called %d times", callCount)
		}
	})
}
