package format

import (
	"bytes"
	"crypto/rand"
	"testing"
)

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
	// Create a valid encrypted value
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
