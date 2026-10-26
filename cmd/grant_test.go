package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/maurice2k/confcrypt/internal/config"
)

func grantTestConfig(t *testing.T) (*config.Config, []string) {
	t.Helper()
	cfg, _, _ := createEncryptedYAMLFixture(t)
	bob := "age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg"
	carol := "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
	cfg.Recipients = append(cfg.Recipients,
		config.RecipientConfig{Name: "Bob", Age: bob},
		config.RecipientConfig{Name: "Carol", Age: carol},
	)
	pending := missingStoreRecipients(cfg)
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending recipients, got %v", pending)
	}
	return cfg, pending
}

func TestResolvePendingGrantsWithFlagGrantsAll(t *testing.T) {
	cfg, pending := grantTestConfig(t)
	var out bytes.Buffer
	granted, denied := resolvePendingGrants(cfg, pending, true, false, strings.NewReader(""), &out)
	if len(granted) != 2 || len(denied) != 0 {
		t.Fatalf("expected all granted, got granted=%v denied=%v", granted, denied)
	}
	if out.Len() != 0 {
		t.Errorf("expected no output with --grant, got %q", out.String())
	}
}

func TestResolvePendingGrantsNonInteractiveDeniesAll(t *testing.T) {
	cfg, pending := grantTestConfig(t)
	var out bytes.Buffer
	granted, denied := resolvePendingGrants(cfg, pending, false, false, strings.NewReader("y\ny\n"), &out)
	if len(granted) != 0 || len(denied) != 2 {
		t.Fatalf("expected all denied, got granted=%v denied=%v", granted, denied)
	}
	if !strings.Contains(out.String(), "--grant") || !strings.Contains(out.String(), "Bob") {
		t.Errorf("expected warning naming the recipients and --grant, got %q", out.String())
	}
	if strings.Contains(out.String(), "Grant access?") {
		t.Errorf("must not prompt without a terminal, got %q", out.String())
	}
}

func TestResolvePendingGrantsInteractivePerRecipient(t *testing.T) {
	cfg, pending := grantTestConfig(t)
	var out bytes.Buffer
	// Bob: yes, Carol: no (pending is sorted by key; map answers by position)
	granted, denied := resolvePendingGrants(cfg, pending, false, true, strings.NewReader("yes\nn\n"), &out)
	if len(granted) != 1 || granted[0] != pending[0] {
		t.Fatalf("expected first pending recipient granted, got granted=%v", granted)
	}
	if len(denied) != 1 || denied[0] != pending[1] {
		t.Fatalf("expected second pending recipient denied, got denied=%v", denied)
	}
	if strings.Count(out.String(), "Grant access?") != 2 {
		t.Errorf("expected two prompts, got %q", out.String())
	}
}

func TestResolvePendingGrantsInteractiveEOFDenies(t *testing.T) {
	cfg, pending := grantTestConfig(t)
	var out bytes.Buffer
	granted, denied := resolvePendingGrants(cfg, pending, false, true, strings.NewReader(""), &out)
	if len(granted) != 0 || len(denied) != 2 {
		t.Fatalf("EOF must deny, got granted=%v denied=%v", granted, denied)
	}
}

func TestResolvePendingGrantsNothingPending(t *testing.T) {
	cfg, _, _ := createEncryptedYAMLFixture(t)
	var out bytes.Buffer
	granted, denied := resolvePendingGrants(cfg, nil, false, true, strings.NewReader(""), &out)
	if granted != nil || denied != nil || out.Len() != 0 {
		t.Fatalf("expected no-op, got granted=%v denied=%v out=%q", granted, denied, out.String())
	}
}
