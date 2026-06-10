package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/config"
)

var (
	rekeyAgeKeyFile  string
	rekeySSHKeyFile  string
	rekeyYubiKeyFlag bool
	rekeyFIDO2Flag   bool
)

var rekeyCmd = &cobra.Command{
	Use:   "rekey",
	Short: "Rotate the AES key and re-encrypt all values",
	Long:  `Generate a new AES key and re-encrypt all values with the new key.`,
	Run:   runRekey,
}

func init() {
	rekeyCmd.Flags().StringVar(&rekeyAgeKeyFile, "age-key", "", "Path to age private key file (use without value to force age auto-detect)")
	rekeyCmd.Flags().StringVar(&rekeySSHKeyFile, "ssh-key", "", "Path to SSH private key file (use without value to force SSH auto-detect)")
	rekeyCmd.Flags().BoolVar(&rekeyYubiKeyFlag, "yubikey-key", false, "Use YubiKey HMAC challenge-response")
	rekeyCmd.Flags().BoolVar(&rekeyFIDO2Flag, "fido2-key", false, "Use FIDO2 hmac-secret (requires CGO build)")
	// Allow --age-key and --ssh-key without a value (sets to "auto")
	rekeyCmd.Flags().Lookup("age-key").NoOptDefVal = AutoDetectMarker
	rekeyCmd.Flags().Lookup("ssh-key").NoOptDefVal = AutoDetectMarker
	rootCmd.AddCommand(rekeyCmd)
}

func runRekey(cmd *cobra.Command, args []string) {
	// Load config
	cfg, err := config.Load(resolvedConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !cfg.HasSecrets() {
		fmt.Fprintf(os.Stderr, "Error: no encrypted secrets found - nothing to rekey\n")
		os.Exit(1)
	}

	// Load identities to decrypt current values
	identities, err := LoadDecryptionIdentity(cfg, rekeyAgeKeyFile, rekeySSHKeyFile, rekeyYubiKeyFlag, rekeyFIDO2Flag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading identities: %v\n", err)
		os.Exit(1)
	}

	rekeyedFiles, err := performRekey(cfg, identities)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(rekeyedFiles) == 0 {
		fmt.Println("No encrypted files found - rotated AES key only")
		return
	}

	for _, relPath := range rekeyedFiles {
		fmt.Printf("Rekeyed: %s\n", relPath)
	}

	fmt.Printf("\nSuccessfully rekeyed %d file(s) with new AES key\n", len(rekeyedFiles))
}
