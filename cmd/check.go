package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/config"
	"github.com/maurice2k/confcrypt/internal/processor"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check for unencrypted keys (exit 1 if found)",
	Long:  `Check if there are any unencrypted values for keys that should be encrypted.`,
	Run:   runCheck,
}

func init() {
	rootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) {
	// Load config
	cfg, err := config.Load(resolvedConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Create processor
	proc, err := processor.NewProcessor(cfg, LoadIdentities)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Get files to process
	files, err := GetFilesToProcess(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "No files to process\n")
		os.Exit(0)
	}

	foundUnencrypted := false

	for _, file := range files {
		unencrypted, err := proc.CheckFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking %s: %v\n", file, err)
			os.Exit(1)
		}

		if len(unencrypted) > 0 {
			foundUnencrypted = true
			fmt.Printf("%s:\n", file)
			for _, r := range unencrypted {
				fmt.Printf("  - %s\n", strings.Join(r.Path, "."))
			}
		}
	}

	if foundUnencrypted {
		fmt.Println("\nFound unencrypted keys that should be encrypted.")
		os.Exit(1)
	}

	fmt.Println("All matching keys are encrypted.")
}
