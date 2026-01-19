package cmd

import (
	"fmt"
	"os"
	"os/user"

	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/yubikey"
)

var (
	keygenYubiKey bool
	keygenSlot    int
)

var keygenYubiKeyCmd = &cobra.Command{
	Use:   "yubikey",
	Short: "Generate a YubiKey-derived age key",
	Long: `Generate an age-compatible key derived from YubiKey HMAC challenge-response.

The generated recipient string contains all information needed to derive the key:
- YubiKey serial number (for device identification)
- HMAC slot (1 or 2)
- Random challenge (salt)
- Public key

The private key is never stored - it's derived on-demand using the YubiKey.

Prerequisites:
  Configure HMAC challenge-response on your YubiKey:
    ykman otp chalresp --generate 2 --touch

Example:
  confcrypt keygen yubikey
  confcrypt keygen yubikey --slot 1`,
	Run: runKeygenYubiKey,
}

func init() {
	keygenYubiKeyCmd.Flags().IntVar(&keygenSlot, "slot", yubikey.DefaultSlot, "HMAC slot to use (1 or 2)")

	keygenCmd.AddCommand(keygenYubiKeyCmd)
}

func runKeygenYubiKey(cmd *cobra.Command, args []string) {
	// Validate slot
	if keygenSlot != 1 && keygenSlot != 2 {
		fmt.Fprintf(os.Stderr, "Error: slot must be 1 or 2\n")
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "Detecting YubiKey...")

	// Find YubiKey
	yk, err := yubikey.GetFirstYubiKey()
	if err != nil {
		if err == yubikey.ErrNoYubiKey {
			fmt.Fprintln(os.Stderr, "Error: no YubiKey detected")
			fmt.Fprintln(os.Stderr, "Make sure your YubiKey is connected.")
		} else if err == yubikey.ErrYkmanNotFound {
			fmt.Fprintln(os.Stderr, "Error: ykman not found")
			fmt.Fprintln(os.Stderr, "Install yubikey-manager: pip install yubikey-manager")
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Found YubiKey with serial: %d\n", yk.Serial)
	fmt.Fprintf(os.Stderr, "Using HMAC slot %d\n", keygenSlot)

	// Check if HMAC is configured
	configured, err := yubikey.IsHMACConfigured(yk.Serial, uint8(keygenSlot))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not check HMAC configuration: %v\n", err)
	} else if !configured {
		fmt.Fprintf(os.Stderr, "Error: HMAC challenge-response not configured on slot %d\n", keygenSlot)
		fmt.Fprintln(os.Stderr, "Configure it with: ykman otp chalresp --generate", keygenSlot, "--touch")
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "\nTouch your YubiKey...")

	// Generate identity
	identity, err := yubikey.GenerateIdentity(yk.Serial, uint8(keygenSlot))
	if err != nil {
		if err == yubikey.ErrHMACNotConfigured {
			fmt.Fprintf(os.Stderr, "Error: HMAC challenge-response not configured on slot %d\n", keygenSlot)
			fmt.Fprintln(os.Stderr, "Configure it with: ykman otp chalresp --generate", keygenSlot, "--touch")
		} else {
			fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		}
		os.Exit(1)
	}

	// Encode to recipient string
	recipient, err := yubikey.EncodeRecipient(identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding recipient: %v\n", err)
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
