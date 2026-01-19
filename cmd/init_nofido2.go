//go:build !cgo

package cmd

// IsFIDO2InitEnabled returns false for non-CGO builds
func IsFIDO2InitEnabled() bool {
	return false
}
