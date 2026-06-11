package format

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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

// FullFileHeader is the marker at the start of fully encrypted files
const FullFileHeader = "$CONFCRYPT_ENCRYPTED;"

// ChunkLineLength is the number of characters per line for chunked base64 output
const ChunkLineLength = 80

// encRegex matches the ENC[...] format
var encRegex = regexp.MustCompile(`^ENC\[AES256_GCM,data:([A-Za-z0-9+/=]*),iv:([A-Za-z0-9+/=]+),tag:([A-Za-z0-9+/=]+),type:(str|int|float|bool|null|bytes)\]$`)

// fullFileRegex matches the full file encrypted format (with optional newlines in data and before ,iv:)
var fullFileRegex = regexp.MustCompile(`^\$CONFCRYPT_ENCRYPTED;ENC\[AES256_GCM,data:\n?([\s\S]*?)\n?,iv:([A-Za-z0-9+/=]+),tag:([A-Za-z0-9+/=]+),type:(str|int|float|bool|null|bytes)\]$`)

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
	switch val := v.(type) {
	case bool:
		return TypeBool
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return TypeInt
	case float32, float64:
		return TypeFloat
	case json.Number:
		if strings.ContainsAny(val.String(), ".eE") {
			return TypeFloat
		}
		return TypeInt
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
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			// Integers beyond int64 are preserved exactly as json.Number
			var numErr *strconv.NumError
			if errors.As(err, &numErr) && numErr.Err == strconv.ErrRange {
				return json.Number(s), nil
			}
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

// IsFullFileEncrypted checks if content is a fully encrypted file
func IsFullFileEncrypted(content []byte) bool {
	return len(content) > len(FullFileHeader) && string(content[:len(FullFileHeader)]) == FullFileHeader
}

// FormatFullFileEncrypted formats an encrypted value for full file encryption
// The output includes the header and chunked base64 data
func FormatFullFileEncrypted(ev *EncryptedValue) string {
	dataB64 := base64.StdEncoding.EncodeToString(ev.Data)
	chunkedData := ChunkBase64(dataB64, ChunkLineLength)

	return fmt.Sprintf("%s%sdata:\n%s\n,iv:%s,tag:%s,type:%s%s",
		FullFileHeader,
		encPrefix,
		chunkedData,
		base64.StdEncoding.EncodeToString(ev.IV),
		base64.StdEncoding.EncodeToString(ev.Tag),
		ev.Type,
		encSuffix,
	)
}

// ParseFullFileEncrypted parses a fully encrypted file content
func ParseFullFileEncrypted(content string) (*EncryptedValue, error) {
	// Tolerate trailing whitespace/newlines that editors commonly append.
	matches := fullFileRegex.FindStringSubmatch(strings.TrimRight(content, " \t\r\n"))
	if matches == nil {
		return nil, fmt.Errorf("invalid full file encrypted format")
	}

	// Unchunk the base64 data (remove newlines)
	dataB64 := UnchunkBase64(matches[1])

	data, err := base64.StdEncoding.DecodeString(dataB64)
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

// ChunkBase64 splits a base64 string into lines of the specified length
func ChunkBase64(data string, lineLen int) string {
	if lineLen <= 0 || len(data) <= lineLen {
		return data
	}

	var result strings.Builder
	for i := 0; i < len(data); i += lineLen {
		end := i + lineLen
		if end > len(data) {
			end = len(data)
		}
		if i > 0 {
			result.WriteByte('\n')
		}
		result.WriteString(data[i:end])
	}
	return result.String()
}

// UnchunkBase64 removes newlines and whitespace from chunked base64 data
func UnchunkBase64(data string) string {
	// Remove all whitespace (newlines, spaces, tabs)
	var result strings.Builder
	for _, c := range data {
		if c != '\n' && c != '\r' && c != ' ' && c != '\t' {
			result.WriteRune(c)
		}
	}
	return result.String()
}
