package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/maurice2k/confcrypt/internal/askpasshelper"
)

var installAskpassPrint bool

var installAskpassHelperCmd = &cobra.Command{
	Use:   "install-askpass-helper [path]",
	Short: "Install the bundled confcrypt-askpass helper script",
	Long: `Writes out the confcrypt-askpass helper script bundled inside this
confcrypt binary. The helper auto-detects the best available backend to
prompt for a FIDO2 PIN or SSH key passphrase (macOS: osascript, ssh-askpass,
pinentry-mac; Linux: pinentry-gnome3, pinentry-gtk-2, ssh-askpass, zenity)
and is intended for use with CONFCRYPT_ASKPASS (or SSH_ASKPASS).

Since the script is embedded in the binary, it always matches your installed
confcrypt version - no separate download or version tracking needed.

If no path is given, it's installed next to the running confcrypt binary.

Examples:
  confcrypt install-askpass-helper
  confcrypt install-askpass-helper /usr/local/bin/confcrypt-askpass
  confcrypt install-askpass-helper --print > ~/bin/confcrypt-askpass`,
	Args: cobra.MaximumNArgs(1),
	Run:  runInstallAskpassHelper,
}

func init() {
	installAskpassHelperCmd.Flags().BoolVar(&installAskpassPrint, "print", false, "Print the script to stdout instead of writing a file")
	rootCmd.AddCommand(installAskpassHelperCmd)
}

func runInstallAskpassHelper(cmd *cobra.Command, args []string) {
	if installAskpassPrint {
		os.Stdout.Write(askpasshelper.Script)
		return
	}

	targetPath, err := resolveAskpassInstallPath(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(targetPath, askpasshelper.Script, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to write %s: %v\n", targetPath, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Installed confcrypt-askpass to %s\n", targetPath)
	fmt.Fprintf(os.Stderr, "Set: export CONFCRYPT_ASKPASS=%s\n", targetPath)
}

// resolveAskpassInstallPath determines where to write the helper script: an
// explicit path/directory argument, or next to the running confcrypt binary.
func resolveAskpassInstallPath(args []string) (string, error) {
	if len(args) == 1 {
		path := args[0]
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return filepath.Join(path, askpasshelper.ScriptName), nil
		}
		return path, nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("could not determine confcrypt binary location: %w (specify an explicit path)", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", fmt.Errorf("could not resolve confcrypt binary location: %w (specify an explicit path)", err)
	}
	return filepath.Join(filepath.Dir(exePath), askpasshelper.ScriptName), nil
}
