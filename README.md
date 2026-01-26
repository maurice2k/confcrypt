# confcrypt

A command-line tool for encrypting sensitive values in YAML and JSON configuration files using [age](https://github.com/FiloSottile/age) public-key cryptography.

*confcrypt* only encrypts values matching configured patterns while keeping the file structure readable. Supports multiple recipients with age keys, SSH keys, FIDO2 compatible devices or YubiKey OTP. Works similarly to [sops](https://github.com/getsops/sops), but more straightforward.

## Features

- **Selective encryption**: Only encrypts values matching your defined key patterns
- **Multiple recipients**: Encrypt for multiple team members using age or SSH public keys
- **SSH key support**: Use existing SSH keys (ed25519, RSA) alongside native age keys
- **FIDO2 support**: Derive keys from FIDO2 hmac-secret extension (requires CGO build)
- **YubiKey support**: Derive keys from YubiKey HMAC challenge-response (OTP slot)
- **Format preservation**: Maintains YAML/JSON structure and comments
- **Flexible key matching**: Exact names, regex patterns, or JSON paths
- **Idempotent**: Re-running encryption leaves already-encrypted values unchanged
- **CI-friendly**: `check` command returns exit code 1 if unencrypted secrets found (also usable as pre-commit hook)
- **Key rotation**: `rekey` command to rotate the encryption key

## Quick Start

[Install *confcrypt*](#installation), then:

### 1. Have a keypair ready

You can use any of:
- **Native age key**: `age-keygen -o ~/.config/age/key.txt`
- **Existing SSH key**: `~/.ssh/id_ed25519` (ed25519 or RSA)
- **FIDO2 device (YubiKey, FIDO2 compatible)**: Use hmac-secret extension (see [FIDO2 Support](#fido2-support))
- **YubiKey OTP**: Configure HMAC challenge-response (see [YubiKey Support](#yubikey-support))

### 2. Initialize *confcrypt*

```bash
confcrypt init
```

This creates a `.confcrypt.yml` with:
- Your public key as the first recipient (auto-detected from age key or SSH key)
- Default file patterns: `*.yml`, `*.yaml`, `*.json`
- Default sensitive key patterns: `/password$/`, `/api_key$/`, `/secret$/`, `/token$/`

You can also specify a particular key file or hardware key:

```bash
# Use specific age key
confcrypt init --age-key ~/.age/key.txt

# Use specific SSH public key
confcrypt init --ssh-key ~/.ssh/id_ed25519.pub

# Use FIDO2 hmac-secret (requires CGO build)
confcrypt init --fido2-key

# Use YubiKey HMAC challenge-response
confcrypt init --yubikey-key
```

### 3. Encrypt your config files

```bash
confcrypt
```

### 4. Decrypt when needed

```bash
# Decrypt a single file
confcrypt decrypt config.yml

# Decrypt all matching files
confcrypt decrypt
```

## Installation

### Quick Install (recommended)

Download and install the latest release automatically:

```bash
curl -fsSL https://raw.githubusercontent.com/maurice2k/confcrypt/main/install.sh | sh
```

This installs to `/usr/local/bin` by default. To install elsewhere:

```bash
INSTALL_DIR=~/.local/bin curl -fsSL https://raw.githubusercontent.com/maurice2k/confcrypt/main/install.sh | sh
```

### From source (go install)

```bash
go install github.com/maurice2k/confcrypt@latest
```

**Note:** This builds without CGO, so FIDO2 support is disabled.

### Build from source using Makefile

The project includes a Makefile with convenient build targets:

```bash
git clone https://github.com/maurice2k/confcrypt.git
cd confcrypt

# Build with CGO (FIDO2 support, requires libfido2)
make build

# Install to $GOPATH/bin (with CGO)
make install

# Build without CGO (no FIDO2 support, but portable)
make build-nocgo

# Install to $GOPATH/bin (without CGO)
make install-nocgo

# Cross-compile for all platforms (without CGO)
make build-all-nocgo

# Run tests
make test

# See all available targets
make help
```

The Makefile automatically detects macOS with Homebrew and sets the correct CGO flags for libfido2.

### Build from source with CGO (FIDO2 support)

For full FIDO2 hmac-secret support, you need to build with CGO enabled and `libfido2` installed.

**1. Install libfido2:**

```bash
# macOS
brew install libfido2

# Debian/Ubuntu
sudo apt install libfido2-dev

# Fedora
sudo dnf install libfido2-devel
```

**2. Build with CGO:**

Using the Makefile (recommended):

```bash
make build
```

Or manually on Linux:

```bash
CGO_ENABLED=1 go build -o confcrypt .
```

On macOS without the Makefile, you may need to specify library paths:

```bash
# macOS (Apple Silicon)
CGO_LDFLAGS="-L/opt/homebrew/opt/libfido2/lib -lfido2 -L/opt/homebrew/opt/openssl@3/lib -lcrypto" \
CGO_CFLAGS="-I/opt/homebrew/opt/libfido2/include -I/opt/homebrew/opt/openssl@3/include" \
CGO_ENABLED=1 go build -o confcrypt .

# macOS (Intel)
CGO_LDFLAGS="-L/usr/local/opt/libfido2/lib -lfido2 -L/usr/local/opt/openssl@3/lib -lcrypto" \
CGO_CFLAGS="-I/usr/local/opt/libfido2/include -I/usr/local/opt/openssl@3/include" \
CGO_ENABLED=1 go build -o confcrypt .
```

These flags tell the C compiler where to find the `libfido2` headers (`CGO_CFLAGS`) and the linker where to find the libraries (`CGO_LDFLAGS`).

### Manual Configuration

You can also create `.confcrypt.yml` manually:

```yaml
# Recipients who can decrypt the files
# Supports age keys (age:), SSH keys (ssh:), FIDO2 (fido2:), and YubiKey (yubikey:)
recipients:
  - name: "Alice"
    age: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
  - name: "Bob"
    ssh: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... bob@example.com
  - name: "Carol"
    ssh: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... carol@example.com
  - name: "Dave"
    fido2: age1fido21qpzry9x8...  # FIDO2-derived key
  - name: "Eve"
    yubikey: age1yubikey1q94ldgcz...  # YubiKey-derived key

# Files to process (glob patterns)
files:
  - "*.yml"
  - "*.yaml"
  - "*.json"

# Keys to encrypt (exact match, /regex/, or $path)
# Regex patterns are case-insensitive by default
keys_include:
  - /password$/
  - /api_key$/
  - /secret$/
  - /token$/

# Keys to exclude from encryption
keys_exclude:
  - /_unencrypted$/
```

## Usage

```
confcrypt [command] [options]

Commands:
  init            Initialize a new .confcrypt.yml config file
  encrypt         Encrypt matching keys (default)
  decrypt         Decrypt encrypted values
  check           Check for unencrypted keys (exit 1 if found)
  rekey           Rotate the AES-256 key and re-encrypt all values
  recipient add   Add a recipient (public key required, --name optional)
  recipient rm    Remove a recipient by public key (rekeys by default)

Global Options:
  --path string        Base path where .confcrypt.yml is located (default: current directory)
  --config string      Path to .confcrypt.yml config file (overrides --path)
  --file string        Process a specific file only
  --stdout             Output to stdout instead of modifying files in-place
  --version            Show version
  --help               Show help

Encrypt Options:
  --dry-run            Show what would be encrypted without making changes
  --json               Output encrypted fields in JSON format

Decrypt Options:
  --output-path string Write decrypted files to this directory
  --force              Continue decryption even if MAC verification fails
```

## Examples

### Encrypting a config file

**Before (`config.yml`):**
```yaml
database:
  host: localhost
  port: 5432
  username: admin
  password: supersecret

api:
  endpoint: https://api.example.com
  api_key: sk_live_12345
```

**After running *confcrypt*:**
```yaml
database:
  host: localhost
  port: 5432
  username: admin
  password: ENC[AES256_GCM,data:c3VwZXJzZWNyZXQ=,iv:...,tag:...,type:str]

api:
  endpoint: https://api.example.com
  api_key: ENC[AES256_GCM,data:c2tfbGl2ZV8xMjM0NQ==,iv:...,tag:...,type:str]
```

### Key Matching Patterns

| Pattern | Type | Description |
|---------|------|-------------|
| `password` | Exact | Matches any key named "password" at any depth |
| `/^api_/` | Regex | Matches keys starting with "api_" (case-insensitive) |
| `/_secret$/` | Regex | Matches keys ending with "_secret" (case-insensitive) |
| `$db.password` | Path (relative) | Matches "password" inside any "db" object |
| `$.db.password` | Path (absolute) | Matches "password" in root-level "db" only |

### Regex Case Sensitivity

**Regex patterns are case-insensitive by default.** This means `/password$/` will match `password`, `PASSWORD`, `Password`, etc.

To make a regex case-sensitive, use the object form with `options: -i`:

```yaml
keys_include:
  # Case-insensitive (default) - matches "api_key", "API_KEY", "Api_Key"
  - /api_key$/

  # Case-sensitive - only matches exactly "api_key"
  - key: /api_key$/
    type: regex
    options: "-i"
```

### Explicit type for edge cases

If your key name starts with `$` or `/`, use the object form:

```yaml
keys_include:
  - key: "$special_var"
    type: exact
  - key: "/literal/slashes/"
    type: exact
```

### Preview encryption (dry-run)

```bash
# Show what would be encrypted (human-readable)
confcrypt encrypt --dry-run

# Show what would be encrypted (JSON format)
confcrypt encrypt --dry-run --json
```

### JSON output

```bash
# Encrypt and output what was encrypted in JSON format
confcrypt encrypt --json
```

Output format:
```json
{
  "files": {
    "config.yml": ["database.password", "api.api_key"],
    "secrets.json": ["credentials.token"]
  }
}
```

### Check for unencrypted secrets (CI usage)

```bash
confcrypt check
# Exit code 0: All matching keys are encrypted
# Exit code 1: Found unencrypted keys
```

### Decrypt to stdout

```bash
confcrypt decrypt --stdout config.yml
```

### Decrypt to a different directory

```bash
# Decrypt to a separate directory (preserves encrypted source files)
confcrypt decrypt --output-path ./decrypted/

# Use absolute path
confcrypt decrypt --output-path /tmp/decrypted-configs/
```

When using `--output-path`:
- Decrypted files are written to the specified directory, preserving the relative path structure
- Source files remain encrypted

## Managing Recipients

*confcrypt* supports adding and removing recipients dynamically.

### Add a recipient (`recipient add`)

```bash
# Add with age key
confcrypt recipient add --name "Bob" age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg

# Add with SSH key
confcrypt recipient add --name "Carol" "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... carol@example.com"

# Add without name
confcrypt recipient add age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg
```

**What happens:**
1. The new recipient is added to the `recipients` list in `.confcrypt.yml`
2. If encrypted secrets exist, the existing AES-256 key is encrypted for the new recipient
3. The new recipient can now decrypt all config files with their private key

**Note:** No rekeying occurs - the same AES-256 key is used, just encrypted for an additional recipient.

### Remove a recipient (`recipient rm`)

```bash
# Default: rekeys (generates new AES-256 key, re-encrypts everything)
confcrypt recipient rm age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg

# Skip rekeying (just remove their access to current key)
confcrypt recipient rm --no-rekey age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg
```

**Default behavior (with rekey):**
1. The recipient is removed from the `recipients` list
2. A new AES-256 key is generated
3. All encrypted values are decrypted and re-encrypted with the new key
4. The new key is encrypted for remaining recipients only
5. The removed recipient cannot decrypt any files (even if they had a copy of the old AES-256 key)

**With `--no-rekey`:**
1. The recipient is removed from the `recipients` list
2. The existing AES-256 key is re-encrypted for remaining recipients only
3. The removed recipient loses access, but if they had a copy of the old AES-256 key, they could still decrypt

**Note:** You cannot remove the last recipient - at least one must remain.

## Key Rotation (`rekey`)

Rotate the AES encryption key and re-encrypt all values:

```bash
confcrypt rekey
```

**What happens:**
1. All encrypted values are decrypted using the current AES-256 key
2. A new random AES-256 key is generated
3. All values are re-encrypted with the new key
4. The new key is encrypted for all current recipients
5. MACs are updated for all files

**Use cases:**
- Regular key rotation policy
- After a security incident
- After removing a recipient (done automatically by default)

## Private Key Configuration

*confcrypt* looks for your private key in this order (age keys take precedence over SSH keys):

1. `SOPS_AGE_KEY_FILE` environment variable (for sops compatibility)
2. `CONFCRYPT_AGE_KEY_FILE` environment variable
3. `CONFCRYPT_AGE_KEY` environment variable (key content directly)
4. `CONFCRYPT_SSH_KEY_FILE` environment variable (SSH private key file)
5. `~/.config/age/key.txt` (default age location)
6. `~/.ssh/id_ed25519` (SSH ed25519 key)
7. `~/.ssh/id_rsa` (SSH RSA key)
8. FIDO2 recipients from `.confcrypt.yml` (auto-detected, requires touch/PIN)
9. YubiKey recipients from `.confcrypt.yml` (auto-detected, requires touch)

### Supported Key Types

| Key Type | Recipient (encryption) | Identity (decryption) |
|----------|------------------------|----------------------|
| Native age (X25519) | `age:` field | age key file |
| SSH ed25519 | `ssh:` field | `~/.ssh/id_ed25519` |
| SSH RSA | `ssh:` field | `~/.ssh/id_rsa` |
| FIDO2 hmac-secret | `fido2:` field | FIDO2 device |
| YubiKey HMAC | `yubikey:` field | YubiKey device |
| SSH sk-ed25519 (FIDO) | Not supported | Not supported |

**Note**: SSH sk-ed25519 (hardware-backed FIDO keys) are not supported because the private key material cannot be exported from the hardware token. Use the FIDO2 hmac-secret support instead.

## FIDO2 Support

*confcrypt* can derive encryption keys from FIDO2 devices using the hmac-secret extension. This provides stronger crypto (SHA-256) and optional PIN protection.

**Note**: FIDO2 support requires building *confcrypt* with CGO enabled and libfido2 installed. See [Build from source with CGO](#build-from-source-with-cgo-fido2-support) in the Installation section.

### Generate a FIDO2 recipient

```bash
confcrypt keygen fido2
confcrypt keygen fido2 --pin  # Require PIN
```

This outputs a recipient string like:
```
age1fido21qpzry9x8gf2tvdw0s3jn54khce6mua7l...
```

### Add FIDO2 recipient to project

```bash
confcrypt recipient add --name "Your Name" age1fido21qpzry9x8...
```

### How it works

1. **Credential creation**: A FIDO2 credential is created with the hmac-secret extension
2. **Salt generation**: A random 32-byte salt is generated
3. **Secret derivation**: The device computes HMAC-SHA256 using its internal secret and the salt
4. **Key derivation**: The secret is used to derive an X25519 keypair
5. **Decryption**: Touch the device (and enter PIN if configured) to re-derive the private key

### FIDO2 vs YubiKey OTP

| Feature | FIDO2 hmac-secret | YubiKey OTP HMAC |
|---------|-------------------|------------------|
| Algorithm | HMAC-SHA256 | HMAC-SHA1 |
| PIN support | Yes | No |
| External tool | `libfido2` (CGO) | `ykman` |
| Build | Requires CGO | Standard Go |

## YubiKey Support

*confcrypt* supports deriving encryption keys from YubiKey HMAC challenge-response. This provides hardware-backed key derivation without storing any secrets on disk.

### Prerequisites

1. Install `ykman` (YubiKey Manager):
   ```bash
   brew install ykman  # macOS
   pip install yubikey-manager  # or via pip
   ```

2. Configure HMAC challenge-response on your YubiKey:
   ```bash
   ykman otp chalresp --generate 2 --touch
   ```
   This configures slot 2 with a random secret and requires touch for each operation.

### Generate a YubiKey recipient

```bash
confcrypt keygen yubikey
```

This outputs a recipient string like:
```
age1yubikey1q94ldgcz5v2ejqt7gt7vrxxg6jr652pe8guse6kgnctrc9x3hev52wwr8588z7a3ukc7ewwy72ssts0xm0r5xy9yk6jjjrlzz7thuta9wcve2ygv44r0y
```

The recipient string contains:
- YubiKey serial number (for device identification)
- HMAC slot (1 or 2)
- Random challenge (salt)
- X25519 public key

### Add YubiKey recipient to project

```bash
confcrypt recipient add --name "Your Name" age1yubikey1q94ldgcz...
```

### How it works

1. **Key generation**: A random 32-byte challenge is generated and sent to the YubiKey
2. **HMAC response**: The YubiKey computes HMAC-SHA1 using its internal secret
3. **Key derivation**: The response is combined with the challenge via SHA256 to derive an X25519 keypair
4. **Encryption**: The derived public key is used for age encryption
5. **Decryption**: Touch the YubiKey to re-derive the private key on-demand

The private key is **never stored** - it's derived each time using the YubiKey.

## Encrypted Value Format

Values are encrypted using AES-256-GCM and stored in this format:

```
ENC[AES256_GCM,data:<base64>,iv:<base64>,tag:<base64>,type:<type>]
```

- `data`: AES-GCM ciphertext (base64)
- `iv`: 12-byte initialization vector (base64)
- `tag`: 16-byte authentication tag (base64)
- `type`: Original value type (`str`, `int`, `float`, `bool`, `null`)

The AES-256 key is randomly generated per config and encrypted for each recipient using their public key (age or SSH).

## Config File Structure

After encryption, *confcrypt* adds a `.confcrypt` section to your `.confcrypt.yml`:

```yaml
.confcrypt:
  version: "1.0"
  updated_at: "2026-01-16T12:00:00Z"
  store:
    - recipient: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
      secret: !!binary |
        YWdlLWVuY3J5cHRpb24...
  macs:
    config.yml: ENC[AES256_GCM,data:...,iv:...,tag:...,type:bytes]
    config.json: ENC[AES256_GCM,data:...,iv:...,tag:...,type:bytes]
```

- `version`: Config format version
- `updated_at`: Last encryption timestamp (UTC)
- `store`: AES-256 key encrypted for each recipient
- `macs`: Per-file Message Authentication Codes (SHA256 hash of encrypted values, encrypted)

## Tamper Detection

*confcrypt* computes a MAC (Message Authentication Code) for each encrypted file. The MAC is a SHA256 hash of all encrypted values, which is then encrypted with the same AES-256 key.

On decryption, *confcrypt* verifies the MAC before decrypting. If the encrypted values have been tampered with, decryption fails:

```
Error: config.yml: MAC verification failed - file may have been tampered with
Use --force to decrypt anyway
```

To proceed despite tampering detection:

```bash
confcrypt decrypt --force
```

This protects against:
- Modification of encrypted ciphertext
- Swapping encrypted values between fields

## How It Works

*confcrypt* uses a two-layer encryption scheme:

### Layer 1: AES-256-GCM encryption

The AES-256-GCM encryption is used to encrypt the values that require encryption according to the rules in the config file.

```
┌─────────────────────────────────────────────────────────────────┐
│             Config values that should be encrypted              │
│  api_key: "sk_live_..."                                         │
│  password: "secret123"                                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              | generate or reuse an AES-256 key ("secret") and
                              | and encrypt the values with it using AES-256-GCM
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Encrypted values                            │
│  api_key: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]      │
│  password: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]     │
└─────────────────────────────────────────────────────────────────┘
```

### Layer 2: Public-key encryption

The public-key encryption (age or SSH) is used to encrypt the AES-256 key ("secret") for each recipient using their public key.
```
┌─────────────────────────────────────────────────────────────────┐
│                     AES-256 key ("secret")                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              | encrypt the secret with each recipient's public key
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                 ▼
      ┌──────────┐      ┌──────────┐      ┌──────────┐
      │ Alice's  │      │  Bob's   │      │ Carol's  │
      │ pub key  │      │ pub key  │      │ pub key  │
      └──────────┘      └──────────┘      └──────────┘
            │                 │                 │
            ▼                 ▼                 ▼
      ┌──────────┐      ┌──────────┐      ┌──────────┐
      │  Secret  │      │  Secret  │      │  Secret  │
      │encrypted │      │encrypted │      │encrypted │
      │for Alice │      │ for Bob  │      │for Carol │
      └──────────┘      └──────────┘      └──────────┘
```

### Encryption Flow

1. Generate a random AES-256 key ("secret") or reuse existing one
2. Encrypt each matching value with AES-256-GCM (produces ciphertext + IV + auth tag)
3. Encrypt the AES-256 key ("secret") separately for each recipient using their public key
4. Store encrypted AES-256 keys in `.confcrypt.store` inside the .confcrypt.yml file

### Decryption Flow

1. Use your private key to decrypt your copy of the AES-256 key ("secret")
2. Use the AES-256 key ("secret") from step 1 to decrypt all encrypted values

### Why This Design?

This approach allows **multiple recipients to both decrypt AND encrypt** the same files without sharing a master secret in plaintext:

- Any recipient can decrypt existing secrets (they have the AES-256 key)
- Any recipient can encrypt new secrets (same AES-256 key)
- Adding a recipient only requires encrypting the AES-256 key for them (no re-encryption of values)
- Removing a recipient with `rekey` generates a new AES-256 key they don't have access to

## License

MIT License - see [LICENSE](LICENSE) file.
