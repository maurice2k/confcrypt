//go:build cgo

package cmd

import (
	"fmt"
	"os"
	"os/user"

	"github.com/spf13/cobra"
)

var keygenFIDO2Cmd = &cobra.Command{
	Use:   "fido2",
	Short: "Generate a FIDO2-derived age key using hmac-secret",
	Long: `Generate an age-compatible key derived from FIDO2 hmac-secret extension.

The generated recipient string contains all information needed to derive the key:
- Credential ID (for credential identification)
- Salt (random value for key derivation)
- RP ID (for verification)
- Public key

The private key is never stored - it's derived on-demand using the FIDO2 device.
If your device requires a PIN, you will be prompted to enter it.

Prerequisites:
  A FIDO2-compatible security key (e.g., YubiKey 5 series) with hmac-secret support.
  Install libfido2: brew install libfido2

Example:
  confcrypt keygen fido2`,
	Run: runKeygenFIDO2,
}

func init() {
	keygenCmd.AddCommand(keygenFIDO2Cmd)
}

func runKeygenFIDO2(cmd *cobra.Command, args []string) {
	// Use shared FIDO2 generation logic
	recipient, _, err := generateFIDO2Recipient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Get username for the example command
	userName := "your-name"
	if u, err := user.Current(); err == nil {
		if u.Name != "" {
			userName = u.Name
		} else if u.Username != "" {
			userName = u.Username
		}
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Add to your project:")
	fmt.Fprintf(os.Stderr, "  confcrypt recipient add --name \"%s\" %s\n", userName, recipient)
	fmt.Fprintln(os.Stderr)

	// Output recipient to stdout for easy piping
	fmt.Println(recipient)
}
