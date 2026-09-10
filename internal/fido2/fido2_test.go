//go:build cgo

package fido2

import (
	"errors"
	"fmt"
	"testing"

	"github.com/keys-pub/go-libfido2"
)

func TestSelectCredentialOwner(t *testing.T) {
	tests := []struct {
		name       string
		candidates []Device
		probe      func(Device) error
		wantPath   string
		wantErr    error
	}{
		{
			name:       "matching candidate",
			candidates: []Device{{Path: "first"}},
			probe:      func(Device) error { return nil },
			wantPath:   "first",
		},
		{
			name:       "user presence required means match",
			candidates: []Device{{Path: "first"}},
			probe:      func(Device) error { return libfido2.ErrUserPresenceRequired },
			wantPath:   "first",
		},
		{
			name:       "UP required means match",
			candidates: []Device{{Path: "first"}},
			probe:      func(Device) error { return libfido2.ErrUPRequired },
			wantPath:   "first",
		},
		{
			name:       "sole candidate rejects credential",
			candidates: []Device{{Path: "first"}},
			probe:      func(Device) error { return libfido2.ErrNoCredentials },
			wantErr:    ErrDeviceNotFound,
		},
		{
			name:       "wrapped rejection is conclusive",
			candidates: []Device{{Path: "first"}},
			probe: func(Device) error {
				return fmt.Errorf("assertion failed: %w", libfido2.ErrInvalidCredential)
			},
			wantErr: ErrDeviceNotFound,
		},
		{
			name:       "sole candidate with inconclusive probe",
			candidates: []Device{{Path: "first"}},
			probe:      func(Device) error { return errors.New("transport failure") },
			wantPath:   "first",
		},
		{
			name:       "not allowed is inconclusive",
			candidates: []Device{{Path: "first"}},
			probe:      func(Device) error { return libfido2.ErrNotAllowed },
			wantPath:   "first",
		},
		{
			name:       "sole inconclusive candidate remains after rejection",
			candidates: []Device{{Path: "first"}, {Path: "second"}},
			probe: func(dev Device) error {
				if dev.Path == "first" {
					return libfido2.ErrNoCredentials
				}
				return libfido2.ErrNotAllowed
			},
			wantPath: "second",
		},
		{
			name:       "later candidate owns credential",
			candidates: []Device{{Path: "first"}, {Path: "second"}},
			probe: func(dev Device) error {
				if dev.Path == "first" {
					return libfido2.ErrNoCredentials
				}
				return nil
			},
			wantPath: "second",
		},
		{
			name:       "all candidates reject credential",
			candidates: []Device{{Path: "first"}, {Path: "second"}},
			probe:      func(Device) error { return libfido2.ErrNoCredentials },
			wantErr:    ErrDeviceNotFound,
		},
		{
			name:       "multiple inconclusive candidates",
			candidates: []Device{{Path: "first"}, {Path: "second"}},
			probe:      func(Device) error { return errors.New("unsupported probe") },
			wantErr:    ErrDeviceNotFound,
		},
		{
			name:       "no candidates",
			candidates: nil,
			probe:      func(Device) error { return nil },
			wantErr:    ErrDeviceNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectCredentialOwner(tt.candidates, tt.probe)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("selectCredentialOwner() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantPath == "" {
				if got != nil {
					t.Fatalf("selectCredentialOwner() = %q, want nil", got.Path)
				}
				return
			}
			if got == nil || got.Path != tt.wantPath {
				t.Fatalf("selectCredentialOwner() = %v, want path %q", got, tt.wantPath)
			}
		})
	}
}
