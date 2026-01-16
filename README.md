# confcrypt

A command-line tool for encrypting sensitive values in YAML and JSON configuration files using [age](https://github.com/FiloSottile/age) public-key cryptography.

Similar to [sops](https://github.com/getsops/sops), confcrypt encrypts only specific keys in your config files while leaving the structure readable. It supports multiple recipients, allowing team members to decrypt files with their own private keys.

## Features

- **Selective encryption**: Only encrypts values matching your defined key patterns
- **Multiple recipients**: Encrypt for multiple team members using age public keys
- **Format preservation**: Maintains YAML/JSON structure and comments
- **Flexible key matching**: Exact names, regex patterns, or JSON paths
- **Idempotent**: Re-running encryption leaves already-encrypted values unchanged
- **CI-friendly**: `check` command returns exit code 1 if unencrypted secrets found
- **Key rotation**: `rekey` command to rotate the encryption key

## How It Works

confcrypt uses a two-layer encryption scheme:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Config Values                            │
│  password: "secret123"  api_key: "sk_live_..."  token: "..."   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ Encrypt with AES-256-GCM
┌─────────────────────────────────────────────────────────────────┐
│                     Encrypted Values                            │
│  password: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]    │
└─────────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                 ▼
      ┌──────────┐      ┌──────────┐      ┌──────────┐
      │ Alice's  │      │  Bob's   │      │ Carol's  │
      │ age key  │      │ age key  │      │ age key  │
      └──────────┘      └──────────┘      └──────────┘
            │                 │                 │
            ▼                 ▼                 ▼
      ┌──────────┐      ┌──────────┐      ┌──────────┐
      │ AES key  │      │ AES key  │      │ AES key  │
      │encrypted │      │encrypted │      │encrypted │
      │for Alice │      │ for Bob  │      │for Carol │
      └──────────┘      └──────────┘      └──────────┘
```

### Key Hierarchy

1. **AES-256 Key**: A random 256-bit key is generated once per project. This key encrypts all sensitive values using AES-256-GCM.

2. **Age Public Keys**: Each recipient's age public key encrypts a copy of the AES key. These encrypted copies are stored in `.confcrypt.yml`.

### Encryption Flow

1. Generate a random AES-256 key (or reuse existing one)
2. Encrypt each matching value with AES-GCM (produces ciphertext + IV + auth tag)
3. Encrypt the AES key separately for each recipient using their age public key
4. Store encrypted AES keys in `.confcrypt.store`

### Decryption Flow

1. Use your age private key to decrypt your copy of the AES key
2. Use the AES key to decrypt all encrypted values

### Why This Design?

This approach allows **multiple recipients to both decrypt AND encrypt** the same files without sharing a master secret in plaintext:

- Any recipient can decrypt existing secrets (they have the AES key)
- Any recipient can encrypt new secrets (same AES key)
- Adding a recipient only requires encrypting the AES key for them (no re-encryption of values)
- Removing a recipient with `rekey` generates a new AES key they don't have access to

## Installation

### From source

```bash
go install github.com/maurice2k/confcrypt@latest
```

### Build from source

```bash
git clone https://github.com/maurice2k/confcrypt.git
cd confcrypt
go build -o confcrypt .
```

## Quick Start

### 1. Generate an age keypair (if you don't have one)

```bash
age-keygen -o ~/.config/age/key.txt
```

### 2. Initialize confcrypt

```bash
confcrypt init
```

This creates a `.confcrypt.yml` with:
- Your age public key as the first recipient (auto-detected from your local key)
- Default file patterns: `*.yml`, `*.yaml`, `*.json`
- Default sensitive key patterns: `/password$/`, `/api_key$/`, `/secret$/`, `/token$/`

### 3. Encrypt your config files

```bash
confcrypt
```

### 4. Decrypt when needed

```bash
confcrypt decrypt config.yml
```

### Manual Configuration

You can also create `.confcrypt.yml` manually:

```yaml
# Recipients who can decrypt the files
recipients:
  - name: "Alice"
    age: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
  - name: "Bob"
    age: age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg

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
  init           Initialize a new .confcrypt.yml config file
  encrypt        Encrypt matching keys (default)
  decrypt        Decrypt encrypted values
  check          Check for unencrypted keys (exit 1 if found)
  rekey          Rotate the AES key and re-encrypt all values
  recipient-add  Add a recipient (age key required, --name optional)
  recipient-rm   Remove a recipient by age key (rekeys by default)

Options:
  -path string      Base path where .confcrypt.yml is located (default: current directory)
  -config string    Path to .confcrypt.yml config file (overrides -path)
  -file string      Process a specific file only
  -stdout           Output to stdout instead of modifying files in-place
  -version          Show version
  -help             Show help
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

**After running `confcrypt`:**
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

## Managing Recipients

confcrypt supports adding and removing recipients dynamically.

### Add a new team member (`recipient-add`)

```bash
# Add with a descriptive name
confcrypt recipient-add --name "Bob" age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg

# Add without name (just the age public key)
confcrypt recipient-add age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg
```

**What happens:**
1. The new recipient is added to the `recipients` list in `.confcrypt.yml`
2. If encrypted secrets exist, the existing AES key is encrypted for the new recipient
3. The new team member can now decrypt all config files with their private key

**Note:** No rekeying occurs - the same AES key is used, just encrypted for an additional recipient.

### Remove a team member (`recipient-rm`)

```bash
# Default: rekeys (generates new AES key, re-encrypts everything)
confcrypt recipient-rm age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg

# Skip rekeying (just remove their access to current key)
confcrypt recipient-rm --no-rekey age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg
```

**Default behavior (with rekey):**
1. The recipient is removed from the `recipients` list
2. A new AES key is generated
3. All encrypted values are decrypted and re-encrypted with the new key
4. The new key is encrypted for remaining recipients only
5. The removed team member cannot decrypt any files (even if they had a copy of the old AES key)

**With `--no-rekey`:**
1. The recipient is removed from the `recipients` list
2. The existing AES key is re-encrypted for remaining recipients only
3. The removed team member loses access, but if they had a copy of the old AES key, they could still decrypt

**Note:** You cannot remove the last recipient - at least one must remain.

## Key Rotation (`rekey`)

Rotate the AES encryption key and re-encrypt all values:

```bash
confcrypt rekey
```

**What happens:**
1. All encrypted values are decrypted using the current AES key
2. A new random AES key is generated
3. All values are re-encrypted with the new key
4. The new key is encrypted for all current recipients
5. MACs are updated for all files

**Use cases:**
- Regular key rotation policy
- After a security incident
- After removing a recipient (done automatically by default)

## Private Key Configuration

confcrypt looks for your age private key in this order:

1. `SOPS_AGE_KEY_FILE` environment variable (for sops compatibility)
2. `CONFCRYPT_AGE_KEY_FILE` environment variable
3. `CONFCRYPT_AGE_KEY` environment variable (key content directly)
4. `~/.config/age/key.txt` (default age location)

## Encrypted Value Format

Values are encrypted using AES-256-GCM and stored in this format:

```
ENC[AES256_GCM,data:<base64>,iv:<base64>,tag:<base64>,type:<type>]
```

- `data`: AES-GCM ciphertext (base64)
- `iv`: 12-byte initialization vector (base64)
- `tag`: 16-byte authentication tag (base64)
- `type`: Original value type (`str`, `int`, `float`, `bool`, `null`)

The AES key is randomly generated per config and encrypted for each recipient using their age public key.

## Config File Structure

After encryption, confcrypt adds a `.confcrypt` section to your `.confcrypt.yml`:

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
- `store`: AES key encrypted for each recipient
- `macs`: Per-file Message Authentication Codes (SHA256 hash of encrypted values, encrypted)

## Tamper Detection

confcrypt computes a MAC (Message Authentication Code) for each encrypted file. The MAC is a SHA256 hash of all encrypted values, which is then encrypted with the same AES key.

On decryption, confcrypt verifies the MAC before decrypting. If the encrypted values have been tampered with, decryption will fail with an error:

```
Error verifying config.yml: MAC verification failed - file may have been tampered with
```

This protects against:
- Modification of encrypted ciphertext
- Swapping encrypted values between fields

## License

MIT License - see [LICENSE](LICENSE) file.
