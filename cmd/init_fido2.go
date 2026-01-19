//go:build cgo

package cmd

var initFIDO2Flag bool

func init() {
	initCmd.Flags().BoolVar(&initFIDO2Flag, "fido2-key", false, "Generate a FIDO2-derived key using hmac-secret")
}

// IsFIDO2InitEnabled returns true if FIDO2 init is enabled
func IsFIDO2InitEnabled() bool {
	return initFIDO2Flag
}
