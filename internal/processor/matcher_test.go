package processor

import (
	"strings"
	"testing"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/doc"
)

func TestExactMatch(t *testing.T) {
	testCases := []struct {
		name     string
		rule     string
		keyName  string
		expected bool
	}{
		{"exact_match", "password", "password", true},
		{"no_match", "password", "username", false},
		{"case_sensitive", "Password", "password", false},
		{"partial_no_match", "pass", "password", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matcher, err := NewMatcher([]config.KeyRule{{Key: tc.rule, Type: "exact"}}, nil)
			if err != nil {
				t.Fatalf("NewMatcher failed: %v", err)
			}

			result := matcher.ShouldEncrypt(tc.keyName, []string{tc.keyName})
			if result != tc.expected {
				t.Errorf("ShouldEncrypt(%q) = %v, expected %v", tc.keyName, result, tc.expected)
			}
		})
	}
}

func TestRegexMatch(t *testing.T) {
	testCases := []struct {
		name     string
		rule     string
		keyName  string
		expected bool
	}{
		{"suffix_match", "/password$/", "db_password", true},
		{"suffix_no_match", "/password$/", "password_hash", false},
		{"prefix_match", "/^api_/", "api_key", true},
		{"contains_match", "/secret/", "my_secret_key", true},
		{"case_insensitive_default", "/password$/", "DB_PASSWORD", true},
		{"pass_match", "/pass.*/", "mypass", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matcher, err := NewMatcher([]config.KeyRule{{Key: tc.rule, Type: "regex"}}, nil)
			if err != nil {
				t.Fatalf("NewMatcher failed: %v", err)
			}

			result := matcher.ShouldEncrypt(tc.keyName, []string{tc.keyName})
			if result != tc.expected {
				t.Errorf("ShouldEncrypt(%q) with rule %q = %v, expected %v", tc.keyName, tc.rule, result, tc.expected)
			}
		})
	}
}

func TestRegexCaseSensitive(t *testing.T) {
	// Test case-sensitive mode with options: "-i"
	testCases := []struct {
		name     string
		rule     string
		options  string
		keyName  string
		expected bool
	}{
		{"case_insensitive_default", "/password$/", "", "DB_PASSWORD", true},
		{"case_sensitive_with_option", "/password$/", "-i", "DB_PASSWORD", false},
		{"case_sensitive_match", "/password$/", "-i", "db_password", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matcher, err := NewMatcher([]config.KeyRule{{Key: tc.rule, Type: "regex", Options: tc.options}}, nil)
			if err != nil {
				t.Fatalf("NewMatcher failed: %v", err)
			}

			result := matcher.ShouldEncrypt(tc.keyName, []string{tc.keyName})
			if result != tc.expected {
				t.Errorf("ShouldEncrypt(%q) with rule %q options %q = %v, expected %v", tc.keyName, tc.rule, tc.options, result, tc.expected)
			}
		})
	}
}

func TestPathMatch(t *testing.T) {
	testCases := []struct {
		name     string
		rule     string
		keyName  string
		path     []string
		expected bool
	}{
		{"relative_match", "$db.password", "password", []string{"api", "db", "password"}, true},
		{"relative_no_match", "$db.password", "password", []string{"api", "cache", "password"}, false},
		{"absolute_match", "$.db.password", "password", []string{"db", "password"}, true},
		{"absolute_no_match", "$.db.password", "password", []string{"api", "db", "password"}, false},
		{"single_segment", "$password", "password", []string{"db", "password"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matcher, err := NewMatcher([]config.KeyRule{{Key: tc.rule, Type: "path"}}, nil)
			if err != nil {
				t.Fatalf("NewMatcher failed: %v", err)
			}

			result := matcher.ShouldEncrypt(tc.keyName, tc.path)
			if result != tc.expected {
				t.Errorf("ShouldEncrypt(%q, %v) with rule %q = %v, expected %v", tc.keyName, tc.path, tc.rule, result, tc.expected)
			}
		})
	}
}

func TestExcludeRules(t *testing.T) {
	include := []config.KeyRule{{Key: "/password$/", Type: "regex"}}
	exclude := []config.KeyRule{{Key: "test_password", Type: "exact"}}

	matcher, err := NewMatcher(include, exclude)
	if err != nil {
		t.Fatalf("NewMatcher failed: %v", err)
	}

	testCases := []struct {
		keyName  string
		expected bool
	}{
		{"db_password", true},
		{"test_password", false}, // Excluded
		{"api_password", true},
	}

	for _, tc := range testCases {
		t.Run(tc.keyName, func(t *testing.T) {
			result := matcher.ShouldEncrypt(tc.keyName, []string{tc.keyName})
			if result != tc.expected {
				t.Errorf("ShouldEncrypt(%q) = %v, expected %v", tc.keyName, result, tc.expected)
			}
		})
	}
}

func jsonRoot(t *testing.T, src string) doc.Node {
	t.Helper()
	d, err := doc.ParseJSON([]byte(src))
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	return d.Root()
}

func TestFindMatchingKeys(t *testing.T) {
	include := []config.KeyRule{
		{Key: "/password$/", Type: "regex"},
		{Key: "api_key", Type: "exact"},
	}

	matcher, err := NewMatcher(include, nil)
	if err != nil {
		t.Fatalf("NewMatcher failed: %v", err)
	}

	results := matcher.FindMatchingKeys(jsonRoot(t, `{
		"db": {"password": "secret123", "host": "localhost"},
		"api_key": "ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]",
		"name": "test"
	}`))

	if len(results) != 2 {
		t.Fatalf("Expected 2 matching keys, got %d", len(results))
	}
	if results[0].KeyName != "password" || results[0].Value != "secret123" || results[0].Encrypted {
		t.Errorf("unexpected first result: %+v", results[0])
	}
	if results[1].KeyName != "api_key" || !results[1].Encrypted {
		t.Errorf("unexpected second result: %+v", results[1])
	}
}

func TestFindMatchingKeysNested(t *testing.T) {
	include := []config.KeyRule{{Key: "/password$/", Type: "regex"}}

	matcher, err := NewMatcher(include, nil)
	if err != nil {
		t.Fatalf("NewMatcher failed: %v", err)
	}

	results := matcher.FindMatchingKeys(jsonRoot(t, `{"level1": {"level2": {"level3": {"password": "deep_secret"}}}}`))

	if len(results) != 1 {
		t.Fatalf("Expected 1 matching key, got %d", len(results))
	}
	expectedPath := []string{"level1", "level2", "level3", "password"}
	if strings.Join(results[0].Path, ".") != strings.Join(expectedPath, ".") {
		t.Errorf("Path mismatch: got %v, expected %v", results[0].Path, expectedPath)
	}
}

func TestFindMatchingKeysInArray(t *testing.T) {
	include := []config.KeyRule{{Key: "/password$/", Type: "regex"}}

	matcher, err := NewMatcher(include, nil)
	if err != nil {
		t.Fatalf("NewMatcher failed: %v", err)
	}

	results := matcher.FindMatchingKeys(jsonRoot(t, `{"users": [
		{"name": "user1", "password": "pass1"},
		{"name": "user2", "password": "pass2"}
	]}`))

	if len(results) != 2 {
		t.Errorf("Expected 2 matching keys (one per user), got %d", len(results))
	}
}

func TestFindMatchingKeysMatchedList(t *testing.T) {
	include := []config.KeyRule{{Key: "secrets", Type: "exact"}}

	matcher, err := NewMatcher(include, nil)
	if err != nil {
		t.Fatalf("NewMatcher failed: %v", err)
	}

	results := matcher.FindMatchingKeys(jsonRoot(t, `{"secrets": ["a", ["b"], {"secrets": "c"}]}`))
	var paths []string
	for _, r := range results {
		paths = append(paths, strings.Join(r.Path, "."))
	}
	want := "secrets[0] secrets[1][0] secrets.secrets"
	if got := strings.Join(paths, " "); got != want {
		t.Errorf("paths: got %q, want %q", got, want)
	}
}

func TestInvalidRegex(t *testing.T) {
	// Invalid regex pattern
	_, err := NewMatcher([]config.KeyRule{{Key: "/[invalid/", Type: "regex"}}, nil)
	if err == nil {
		t.Error("Expected error for invalid regex")
	}
}

func TestInvalidPathFormat(t *testing.T) {
	// Path without $ prefix
	_, err := NewMatcher([]config.KeyRule{{Key: "db.password", Type: "path"}}, nil)
	if err == nil {
		t.Error("Expected error for path without $ prefix")
	}
}

func TestExplicitTypeOverride(t *testing.T) {
	// Test that explicit type: exact treats special characters literally
	testCases := []struct {
		name     string
		rule     config.KeyRule
		keyName  string
		expected bool
	}{
		{
			"dollar_as_exact",
			config.KeyRule{Key: "$password", Type: "exact"},
			"$password",
			true,
		},
		{
			"dollar_not_path",
			config.KeyRule{Key: "$password", Type: "exact"},
			"password",
			false,
		},
		{
			"slash_as_exact",
			config.KeyRule{Key: "/password/", Type: "exact"},
			"/password/",
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matcher, err := NewMatcher([]config.KeyRule{tc.rule}, nil)
			if err != nil {
				t.Fatalf("NewMatcher failed: %v", err)
			}

			result := matcher.ShouldEncrypt(tc.keyName, []string{tc.keyName})
			if result != tc.expected {
				t.Errorf("ShouldEncrypt(%q) = %v, expected %v", tc.keyName, result, tc.expected)
			}
		})
	}
}
