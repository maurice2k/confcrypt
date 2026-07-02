// Package askpasshelper embeds the bundled confcrypt-askpass helper script
// so it ships inside the confcrypt binary itself (available via `confcrypt
// install-askpass-helper`, even for `go install` users) instead of relying
// on a separately downloaded/versioned file.
package askpasshelper

import _ "embed"

//go:embed confcrypt-askpass
var Script []byte

// ScriptName is the recommended filename for the installed helper.
const ScriptName = "confcrypt-askpass"
