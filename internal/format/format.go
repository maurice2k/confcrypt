package format

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ValueType represents the original type of an encrypted value
type ValueType string

const (
	TypeString ValueType = "str"
	TypeInt    ValueType = "int"
	TypeFloat  ValueType = "float"
	TypeBool   ValueType = "bool"
	TypeNull   ValueType = "null"
	TypeBytes  ValueType = "bytes"
)

// EncryptedValue represents a parsed ENC[...] value
type EncryptedValue struct {
	Data []byte    // Ciphertext
	IV   []byte    // Initialization vector (12 bytes)
	Tag  []byte    // Authentication tag (16 bytes)
	Type ValueType // Original value type
}

const encPrefix = "ENC[AES256_GCM,"
const encSuffix = "]"

// encRegex matches the ENC[...] format
var encRegex = regexp.MustCompile(`^ENC\[AES256_GCM,data:([A-Za-z0-9+/=]*),iv:([A-Za-z0-9+/=]+),tag:([A-Za-z0-9+/=]+),type:(str|int|float|bool|null|bytes)\]$`)

// IsEncrypted checks if a string value is already encrypted
func IsEncrypted(s string) bool {
	return encRegex.MatchString(s)
}

// FormatEncryptedValue formats an encrypted value into the ENC[...] string format
func FormatEncryptedValue(ev *EncryptedValue) string {
	return fmt.Sprintf("%sdata:%s,iv:%s,tag:%s,type:%s%s",
		encPrefix,
		base64.StdEncoding.EncodeToString(ev.Data),
		base64.StdEncoding.EncodeToString(ev.IV),
		base64.StdEncoding.EncodeToString(ev.Tag),
		ev.Type,
		encSuffix,
	)
}

// ParseEncryptedValue parses an ENC[...] string into an EncryptedValue
func ParseEncryptedValue(s string) (*EncryptedValue, error) {
	matches := encRegex.FindStringSubmatch(s)
	if matches == nil {
		return nil, fmt.Errorf("invalid encrypted value format: %q", s)
	}

	data, err := base64.StdEncoding.DecodeString(matches[1])
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in data field: %w", err)
	}

	iv, err := base64.StdEncoding.DecodeString(matches[2])
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in iv field: %w", err)
	}

	tag, err := base64.StdEncoding.DecodeString(matches[3])
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in tag field: %w", err)
	}

	if len(iv) != 12 {
		return nil, fmt.Errorf("invalid IV length: expected 12, got %d", len(iv))
	}

	if len(tag) != 16 {
		return nil, fmt.Errorf("invalid tag length: expected 16, got %d", len(tag))
	}

	return &EncryptedValue{
		Data: data,
		IV:   iv,
		Tag:  tag,
		Type: ValueType(matches[4]),
	}, nil
}

// DetectValueType determines the ValueType from a Go value
func DetectValueType(v interface{}) ValueType {
	if v == nil {
		return TypeNull
	}
	switch v.(type) {
	case bool:
		return TypeBool
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return TypeInt
	case float32, float64:
		return TypeFloat
	case string:
		return TypeString
	default:
		return TypeString
	}
}

// ValueToString converts a value to its string representation for encryption
func ValueToString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case float64:
		return strconv.FormatFloat(val, 'g', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(val), 'g', -1, 32)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// StringToValue converts a decrypted string back to its original type
func StringToValue(s string, t ValueType) (interface{}, error) {
	switch t {
	case TypeNull:
		return nil, nil
	case TypeBool:
		s = strings.ToLower(s)
		if s == "true" {
			return true, nil
		} else if s == "false" {
			return false, nil
		}
		return nil, fmt.Errorf("invalid bool value: %q", s)
	case TypeInt:
		var i int64
		if _, err := fmt.Sscanf(s, "%d", &i); err != nil {
			return nil, fmt.Errorf("invalid int value: %q", s)
		}
		return i, nil
	case TypeFloat:
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid float value: %q", s)
		}
		return f, nil
	case TypeString:
		return s, nil
	default:
		return s, nil
	}
}
