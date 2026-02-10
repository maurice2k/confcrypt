package format

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func TestChunkBase64(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		lineLen int
		want    string
	}{
		{
			name:    "short data no chunking",
			data:    "aGVsbG8gd29ybGQ=",
			lineLen: 80,
			want:    "aGVsbG8gd29ybGQ=",
		},
		{
			name:    "exact line length",
			data:    strings.Repeat("A", 80),
			lineLen: 80,
			want:    strings.Repeat("A", 80),
		},
		{
			name:    "two lines",
			data:    strings.Repeat("A", 100),
			lineLen: 80,
			want:    strings.Repeat("A", 80) + "\n" + strings.Repeat("A", 20),
		},
		{
			name:    "three lines",
			data:    strings.Repeat("B", 200),
			lineLen: 80,
			want:    strings.Repeat("B", 80) + "\n" + strings.Repeat("B", 80) + "\n" + strings.Repeat("B", 40),
		},
		{
			name:    "empty data",
			data:    "",
			lineLen: 80,
			want:    "",
		},
		{
			name:    "zero line length",
			data:    "test",
			lineLen: 0,
			want:    "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ChunkBase64(tt.data, tt.lineLen)
			if got != tt.want {
				t.Errorf("ChunkBase64() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUnchunkBase64(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "no newlines",
			data: "aGVsbG8gd29ybGQ=",
			want: "aGVsbG8gd29ybGQ=",
		},
		{
			name: "with newlines",
			data: "aGVsbG8g\nd29ybGQ=",
			want: "aGVsbG8gd29ybGQ=",
		},
		{
			name: "with multiple newlines",
			data: "aGVs\nbG8g\nd29y\nbGQ=",
			want: "aGVsbG8gd29ybGQ=",
		},
		{
			name: "with CRLF",
			data: "aGVsbG8g\r\nd29ybGQ=",
			want: "aGVsbG8gd29ybGQ=",
		},
		{
			name: "with spaces",
			data: "aGVsbG8g d29ybGQ=",
			want: "aGVsbG8gd29ybGQ=",
		},
		{
			name: "with tabs",
			data: "aGVsbG8g\td29ybGQ=",
			want: "aGVsbG8gd29ybGQ=",
		},
		{
			name: "empty",
			data: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UnchunkBase64(tt.data)
			if got != tt.want {
				t.Errorf("UnchunkBase64() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestChunkUnchunkRoundTrip(t *testing.T) {
	// Test that chunking and unchunking is reversible
	original := strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 10) + "=="

	chunked := ChunkBase64(original, 80)
	unchunked := UnchunkBase64(chunked)

	if unchunked != original {
		t.Errorf("Round trip failed: got %q, want %q", unchunked, original)
	}
}

func TestIsFullFileEncrypted(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		want    bool
	}{
		{
			name:    "valid full file encrypted",
			content: []byte("$CONFCRYPT_ENCRYPTED;ENC[AES256_GCM,data:test,iv:abc,tag:xyz,type:bytes]"),
			want:    true,
		},
		{
			name:    "regular encrypted value",
			content: []byte("ENC[AES256_GCM,data:test,iv:abc,tag:xyz,type:str]"),
			want:    false,
		},
		{
			name:    "plain text",
			content: []byte("hello world"),
			want:    false,
		},
		{
			name:    "empty",
			content: []byte(""),
			want:    false,
		},
		{
			name:    "partial header",
			content: []byte("$CONFCRYPT"),
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsFullFileEncrypted(tt.content)
			if got != tt.want {
				t.Errorf("IsFullFileEncrypted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatParseFullFileRoundTrip(t *testing.T) {
	// Create a test encrypted value
	ev := &EncryptedValue{
		Data: []byte("hello world this is some test data that will be encrypted"),
		IV:   []byte("123456789012"),     // 12 bytes
		Tag:  []byte("1234567890123456"), // 16 bytes
		Type: TypeBytes,
	}

	// Format it
	formatted := FormatFullFileEncrypted(ev)

	// Check it has the header
	if !strings.HasPrefix(formatted, FullFileHeader) {
		t.Errorf("Missing header prefix")
	}

	// Check it has newlines (chunked)
	if !strings.Contains(formatted, "\n") {
		// Only check for long data that would need chunking
		if len(ev.Data) > 50 { // Base64 of 50 bytes is > 66 chars
			t.Errorf("Expected chunked output with newlines")
		}
	}

	// Parse it back
	parsed, err := ParseFullFileEncrypted(formatted)
	if err != nil {
		t.Fatalf("ParseFullFileEncrypted() error = %v", err)
	}

	// Compare
	if string(parsed.Data) != string(ev.Data) {
		t.Errorf("Data mismatch: got %q, want %q", parsed.Data, ev.Data)
	}
	if string(parsed.IV) != string(ev.IV) {
		t.Errorf("IV mismatch: got %q, want %q", parsed.IV, ev.IV)
	}
	if string(parsed.Tag) != string(ev.Tag) {
		t.Errorf("Tag mismatch: got %q, want %q", parsed.Tag, ev.Tag)
	}
	if parsed.Type != ev.Type {
		t.Errorf("Type mismatch: got %q, want %q", parsed.Type, ev.Type)
	}
}

func TestFormatFullFileEncryptedChunking(t *testing.T) {
	// Create a large encrypted value that will need chunking
	largeData := make([]byte, 1000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	ev := &EncryptedValue{
		Data: largeData,
		IV:   []byte("123456789012"),
		Tag:  []byte("1234567890123456"),
		Type: TypeBytes,
	}

	formatted := FormatFullFileEncrypted(ev)

	// Count newlines in the data section (between "data:\n" and "\n,iv:")
	dataStart := strings.Index(formatted, "data:\n") + 6
	dataEnd := strings.Index(formatted, "\n,iv:")
	dataSection := formatted[dataStart:dataEnd]

	lines := strings.Split(dataSection, "\n")
	for i, line := range lines {
		if i < len(lines)-1 { // Not the last line
			if len(line) != 80 {
				t.Errorf("Line %d has length %d, expected 80", i, len(line))
			}
		}
		// Last line can be shorter (remainder)
	}

	// Verify the format has ,iv: on its own line
	if !strings.Contains(formatted, "\n,iv:") {
		t.Error("Expected ,iv: to be on its own line")
	}
}

func TestParseFullFileEncryptedInvalid(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "missing header",
			content: "ENC[AES256_GCM,data:dGVzdA==,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:bytes]",
		},
		{
			name:    "invalid IV length",
			content: "$CONFCRYPT_ENCRYPTED;ENC[AES256_GCM,data:dGVzdA==,iv:MTIz,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:bytes]",
		},
		{
			name:    "invalid tag length",
			content: "$CONFCRYPT_ENCRYPTED;ENC[AES256_GCM,data:dGVzdA==,iv:MTIzNDU2Nzg5MDEy,tag:MTIz,type:bytes]",
		},
		{
			name:    "invalid base64",
			content: "$CONFCRYPT_ENCRYPTED;ENC[AES256_GCM,data:!!!invalid!!!,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:bytes]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseFullFileEncrypted(tt.content)
			if err == nil {
				t.Error("Expected error but got nil")
			}
		})
	}
}

// --- Restored core ENC[...] value tests ---

func TestIsEncrypted(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid_str", "ENC[AES256_GCM,data:dGVzdA==,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:str]", true},
		{"valid_int", "ENC[AES256_GCM,data:MTIz,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:int]", true},
		{"valid_float", "ENC[AES256_GCM,data:MS4yMw==,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:float]", true},
		{"valid_bool", "ENC[AES256_GCM,data:dHJ1ZQ==,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:bool]", true},
		{"valid_null", "ENC[AES256_GCM,data:,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:null]", true},
		{"valid_empty_data", "ENC[AES256_GCM,data:,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:str]", true},
		{"plain_text", "just plain text", false},
		{"empty", "", false},
		{"wrong_prefix", "DEC[AES256_GCM,data:dGVzdA==,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:str]", false},
		{"missing_data", "ENC[AES256_GCM,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:str]", false},
		{"missing_iv", "ENC[AES256_GCM,data:dGVzdA==,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:str]", false},
		{"missing_tag", "ENC[AES256_GCM,data:dGVzdA==,iv:MTIzNDU2Nzg5MDEy,type:str]", false},
		{"missing_type", "ENC[AES256_GCM,data:dGVzdA==,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==]", false},
		{"invalid_type", "ENC[AES256_GCM,data:dGVzdA==,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:invalid]", false},
		{"partial", "ENC[AES256_GCM,data:", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsEncrypted(tc.input)
			if result != tc.expected {
				t.Errorf("IsEncrypted(%q) = %v, expected %v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestFormatEncryptedValue(t *testing.T) {
	ev := &EncryptedValue{
		Data: []byte("test"),
		IV:   []byte("123456789012"),
		Tag:  []byte("1234567890123456"),
		Type: TypeString,
	}

	result := FormatEncryptedValue(ev)

	if !IsEncrypted(result) {
		t.Errorf("FormatEncryptedValue produced invalid format: %s", result)
	}
}

func TestParseEncryptedValue(t *testing.T) {
	ev := &EncryptedValue{
		Data: []byte("test data"),
		IV:   []byte("123456789012"),
		Tag:  []byte("1234567890123456"),
		Type: TypeString,
	}

	formatted := FormatEncryptedValue(ev)
	parsed, err := ParseEncryptedValue(formatted)

	if err != nil {
		t.Fatalf("ParseEncryptedValue failed: %v", err)
	}

	if !bytes.Equal(parsed.Data, ev.Data) {
		t.Errorf("Data mismatch: got %v, want %v", parsed.Data, ev.Data)
	}
	if !bytes.Equal(parsed.IV, ev.IV) {
		t.Errorf("IV mismatch: got %v, want %v", parsed.IV, ev.IV)
	}
	if !bytes.Equal(parsed.Tag, ev.Tag) {
		t.Errorf("Tag mismatch: got %v, want %v", parsed.Tag, ev.Tag)
	}
	if parsed.Type != ev.Type {
		t.Errorf("Type mismatch: got %v, want %v", parsed.Type, ev.Type)
	}
}

func TestParseEncryptedValueAllTypes(t *testing.T) {
	types := []ValueType{TypeString, TypeInt, TypeFloat, TypeBool, TypeNull}

	for _, vt := range types {
		t.Run(string(vt), func(t *testing.T) {
			ev := &EncryptedValue{
				Data: []byte("test"),
				IV:   []byte("123456789012"),
				Tag:  []byte("1234567890123456"),
				Type: vt,
			}

			formatted := FormatEncryptedValue(ev)
			parsed, err := ParseEncryptedValue(formatted)

			if err != nil {
				t.Fatalf("ParseEncryptedValue failed for type %s: %v", vt, err)
			}

			if parsed.Type != vt {
				t.Errorf("Type mismatch: got %v, want %v", parsed.Type, vt)
			}
		})
	}
}

func TestParseEncryptedValueErrors(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{"invalid_format", "not encrypted"},
		{"wrong_prefix", "DEC[AES256_GCM,data:dGVzdA==,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:str]"},
		{"invalid_base64_data", "ENC[AES256_GCM,data:!!!,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:str]"},
		{"invalid_base64_iv", "ENC[AES256_GCM,data:dGVzdA==,iv:!!!,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:str]"},
		{"invalid_base64_tag", "ENC[AES256_GCM,data:dGVzdA==,iv:MTIzNDU2Nzg5MDEy,tag:!!!,type:str]"},
		{"wrong_iv_length", "ENC[AES256_GCM,data:dGVzdA==,iv:c2hvcnQ=,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,type:str]"},
		{"wrong_tag_length", "ENC[AES256_GCM,data:dGVzdA==,iv:MTIzNDU2Nzg5MDEy,tag:c2hvcnQ=,type:str]"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseEncryptedValue(tc.input)
			if err == nil {
				t.Errorf("Expected error for input %q, got none", tc.input)
			}
		})
	}
}

func TestFormatParseRoundtrip(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
		vt   ValueType
	}{
		{"empty_string", []byte{}, TypeString},
		{"simple_string", []byte("hello world"), TypeString},
		{"unicode", []byte("Hello 世界 🌍"), TypeString},
		{"binary", []byte{0x00, 0x01, 0xff, 0xfe}, TypeString},
		{"int", []byte("12345"), TypeInt},
		{"float", []byte("3.14159"), TypeFloat},
		{"bool_true", []byte("true"), TypeBool},
		{"bool_false", []byte("false"), TypeBool},
		{"null", []byte{}, TypeNull},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			iv := make([]byte, 12)
			rand.Read(iv)
			tag := make([]byte, 16)
			rand.Read(tag)

			ev := &EncryptedValue{
				Data: tc.data,
				IV:   iv,
				Tag:  tag,
				Type: tc.vt,
			}

			formatted := FormatEncryptedValue(ev)
			parsed, err := ParseEncryptedValue(formatted)

			if err != nil {
				t.Fatalf("Roundtrip failed: %v", err)
			}

			if !bytes.Equal(parsed.Data, ev.Data) {
				t.Errorf("Data mismatch after roundtrip")
			}
			if !bytes.Equal(parsed.IV, ev.IV) {
				t.Errorf("IV mismatch after roundtrip")
			}
			if !bytes.Equal(parsed.Tag, ev.Tag) {
				t.Errorf("Tag mismatch after roundtrip")
			}
			if parsed.Type != ev.Type {
				t.Errorf("Type mismatch after roundtrip: got %v, want %v", parsed.Type, ev.Type)
			}
		})
	}
}

func TestDetectValueType(t *testing.T) {
	testCases := []struct {
		name     string
		value    interface{}
		expected ValueType
	}{
		{"nil", nil, TypeNull},
		{"string", "hello", TypeString},
		{"empty_string", "", TypeString},
		{"int", 42, TypeInt},
		{"int64", int64(42), TypeInt},
		{"float64", 3.14, TypeFloat},
		{"float32", float32(3.14), TypeFloat},
		{"bool_true", true, TypeBool},
		{"bool_false", false, TypeBool},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := DetectValueType(tc.value)
			if result != tc.expected {
				t.Errorf("DetectValueType(%v) = %v, expected %v", tc.value, result, tc.expected)
			}
		})
	}
}

func TestValueToString(t *testing.T) {
	testCases := []struct {
		name     string
		value    interface{}
		expected string
	}{
		{"nil", nil, ""},
		{"string", "hello", "hello"},
		{"int", 42, "42"},
		{"float", 3.14, "3.14"},
		{"bool_true", true, "true"},
		{"bool_false", false, "false"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ValueToString(tc.value)
			if result != tc.expected {
				t.Errorf("ValueToString(%v) = %q, expected %q", tc.value, result, tc.expected)
			}
		})
	}
}

func TestStringToValue(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		vt       ValueType
		expected interface{}
		wantErr  bool
	}{
		{"null", "", TypeNull, nil, false},
		{"string", "hello", TypeString, "hello", false},
		{"int", "42", TypeInt, int64(42), false},
		{"negative_int", "-42", TypeInt, int64(-42), false},
		{"float", "3.14", TypeFloat, 3.14, false},
		{"bool_true", "true", TypeBool, true, false},
		{"bool_false", "false", TypeBool, false, false},
		{"bool_True", "True", TypeBool, true, false},
		{"bool_FALSE", "FALSE", TypeBool, false, false},
		{"invalid_int", "not_a_number", TypeInt, nil, true},
		{"invalid_float", "not_a_float", TypeFloat, nil, true},
		{"invalid_bool", "maybe", TypeBool, nil, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := StringToValue(tc.input, tc.vt)

			if tc.wantErr {
				if err == nil {
					t.Errorf("Expected error for StringToValue(%q, %v)", tc.input, tc.vt)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result != tc.expected {
				t.Errorf("StringToValue(%q, %v) = %v, expected %v", tc.input, tc.vt, result, tc.expected)
			}
		})
	}
}
