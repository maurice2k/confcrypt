package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/maurice2k/confcrypt/internal/config"
)

// grantRecipients is the --grant flag: grant key access to recipients that
// were added to .confcrypt.yml by hand without asking.
var grantRecipients bool

func init() {
	rootCmd.PersistentFlags().BoolVar(&grantRecipients, "grant", false,
		"Grant key access to recipients added to .confcrypt.yml by hand without asking")
}

// confirmPendingGrants decides which configured recipients without a key
// store entry (added by hand-editing .confcrypt.yml) receive access during
// this run. With --grant all of them are granted. Otherwise each one is
// confirmed interactively, or skipped with a warning when there is no
// terminal. Returns the granted and the denied public keys.
func confirmPendingGrants(cfg *config.Config) (granted, denied []string) {
	pending := missingStoreRecipients(cfg)
	if len(pending) == 0 || !cfg.HasSecrets() {
		return nil, nil
	}
	return resolvePendingGrants(cfg, pending, grantRecipients, !isNonInteractive(), os.Stdin, os.Stderr)
}

// resolvePendingGrants is the testable core of confirmPendingGrants.
func resolvePendingGrants(cfg *config.Config, pending []string, grant, interactive bool, in io.Reader, out io.Writer) (granted, denied []string) {
	if len(pending) == 0 {
		return nil, nil
	}
	if grant {
		return pending, nil
	}

	if !interactive {
		denied = pending
	} else {
		reader := bufio.NewReader(in)
		for _, pubKey := range pending {
			fmt.Fprintf(out, "Recipient %s is listed in %s but has no access to the encryption key yet.\n",
				recipientLabel(cfg, pubKey), displayPath(cfg.ConfigPath()))
			fmt.Fprint(out, "Grant access? [y/N] ")
			answer, err := reader.ReadString('\n')
			if err != nil && answer == "" {
				fmt.Fprintln(out)
			}
			switch strings.ToLower(strings.TrimSpace(answer)) {
			case "y", "yes":
				granted = append(granted, pubKey)
			default:
				denied = append(denied, pubKey)
			}
		}
	}

	if len(denied) > 0 {
		fmt.Fprintf(out, "Warning: access not granted to %d recipient%s listed in %s:\n",
			len(denied), plural(len(denied)), displayPath(cfg.ConfigPath()))
		for _, pubKey := range denied {
			fmt.Fprintf(out, "  - %s\n", recipientLabel(cfg, pubKey))
		}
		if interactive {
			fmt.Fprintf(out, "Re-run with --grant to grant access, or remove the entry from %s.\n", config.DefaultConfigName)
		} else {
			fmt.Fprintf(out, "No terminal to confirm; re-run with --grant to grant access, or remove the entry from %s.\n", config.DefaultConfigName)
		}
	}
	return granted, denied
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
