package cmd

import (
	"github.com/spf13/cobra"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate encryption keys",
	Long:  `Generate encryption keys for use with confcrypt.`,
}

func init() {
	rootCmd.AddCommand(keygenCmd)
}
