# ChaCha20-Poly1305 🔐

## Overview
ChaCha20-Poly1305 is a modern **AEAD** cipher — Authenticated Encryption with Associated Data — that combines the **ChaCha20** stream cipher (confidentiality) with the **Poly1305** one-time MAC (integrity + authenticity) in a single operation. It is the standard alternative to AES-GCM, used in TLS 1.3, WireGuard, and SSH, and it shines in software / on mobile where the CPU lacks AES acceleration.

> **AEAD ≠ plain encryption.** Unlike AES-CBC (menu 3), which only hides data, ChaCha20-Poly1305 also *detects tampering*: decryption verifies a 16-byte tag first and refuses to release any plaintext if a single bit was altered.

## How It Works (encrypt-then-MAC)
1. **ChaCha20** derives a keystream from the key + nonce and XORs it with the plaintext (a stream cipher — ciphertext is the same length as the plaintext, no padding).
2. **Poly1305** computes a tag over the AAD + ciphertext using a one-time key derived from ChaCha20.
3. On decryption the tag is **recomputed and checked first** — tampered data is rejected before it is ever decrypted, which structurally avoids the padding-oracle class of bugs.

### The three inputs
| Input | Size | Secret? | Rule |
|-------|------|---------|------|
| Key | 32 bytes (256-bit) | Yes | Shared by both sides |
| Nonce | 12 bytes (96-bit) | No (sent in clear) | **Unique per message** — reuse is catastrophic |
| AAD | any | No (authenticated only) | Optional; must match on decrypt |

Output layout in CryptoLens: `base64(nonce ‖ ciphertext ‖ tag)`.

> **⚠️ Nonce reuse is catastrophic.** Encrypting two messages with the same key+nonce leaks their XOR *and* breaks Poly1305's authentication. A random 96-bit nonce is safe for a moderate message count; for very high volumes use **XChaCha20-Poly1305** (192-bit nonce) or a counter. See the **Nonce Reuse** attack simulation (menu 12).

## Features
- Authenticated encryption (AEAD): confidentiality + integrity in one step
- 256-bit key, 96-bit nonce, 128-bit tag
- Additional Authenticated Data (AAD) support (via configuration)
- **Automatic built-in tamper test** — flips a ciphertext bit and shows decryption is rejected
- Non-interactive: works cleanly in the TUI (no stdin prompts)
- File-based key storage

## Usage

### Command Line Interface
```bash
# Select ChaCha20-Poly1305 from the main menu (Option 11)
11. ChaCha20-Poly1305 Encryption

# Choose operation
1. Encrypt
2. Decrypt

# Enter text to process
Enter text to process: Your secret message

# Key Management
1. Use existing key
2. Enter custom key (32 bytes in hex)

# Nonce Management
1. Generate random nonce
2. Enter custom nonce (12 bytes in hex)

# Optional: Enter Additional Authenticated Data (AAD)
```

### Programmatic Usage
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto"

// Create ChaCha20-Poly1305 processor
chachaProcessor := crypto.NewChaCha20Poly1305Processor()

// Configure the processor
config := map[string]interface{}{
    "keyFile": "keys/custom_chacha_key.bin",  // Optional: custom key file path
}
chachaProcessor.Configure(config)

// Encrypt
encrypted, steps, err := chachaProcessor.Process("Your secret message", "encrypt")

// Decrypt
decrypted, steps, err := chachaProcessor.Process(encrypted, "decrypt")
```

## Technical Details

### Key Lengths
- Key: 32 bytes (256 bits)
  - Used for both ChaCha20 encryption and Poly1305 MAC
  - Must be kept secret and secure
  - Never reuse with different nonces

- Nonce: 12 bytes (96 bits)
  - Must be unique for each encryption
  - Never reuse with the same key
  - Nonce reuse leads to security failure

- Tag: 16 bytes (128 bits)
  - Authentication tag from Poly1305
  - Ensures message integrity
  - Must be verified during decryption

### Encryption Process
1. Input validation
2. Key management (existing or custom)
3. Nonce generation/selection
4. AAD handling (optional)
5. ChaCha20 encryption
6. Poly1305 MAC generation
7. Result combination and encoding

### Decryption Process
1. Input validation and decoding
2. Nonce extraction
3. Ciphertext and tag separation
4. Key management
5. AAD verification
6. Authentication check
7. ChaCha20 decryption

### Security Features
- Authenticated encryption
- Tampering detection
- Nonce uniqueness enforcement
- AAD integrity protection
- Timing attack resistance
- Constant-time operations

## Examples

### Encryption Example
```bash
Input: Hi
AAD: anophel
Output: OqfYZvGIm/rqGvbP8EXNAHwvla5YnWNQrimsWPfB

Processing Steps:
1. Input Text: Hi
2. Generated Nonce: 3a a7 d8 66 f1 88 9b fa ea 1a f6 cf
3. AAD: anophel
4. Ciphertext: f0 45
5. Authentication Tag: cd 00 7c 2f 95 ae 58 9d 63 50 ae 29 ac 58 f7 c1
6. Final Result: OqfYZvGIm/rqGvbP8EXNAHwvla5YnWNQrimsWPfB
```

### Decryption Example
```bash
Input: OqfYZvGIm/rqGvbP8EXNAHwvla5YnWNQrimsWPfB
AAD: anophel
Output: Hi

Processing Steps:
1. Extracted Nonce: 3a a7 d8 66 f1 88 9b fa ea 1a f6 cf
2. Extracted Ciphertext: f0 45
3. Extracted Tag: cd 00 7c 2f 95 ae 58 9d 63 50 ae 29 ac 58 f7 c1
4. Verified AAD: anophel
5. Decrypted Text: Hi
```

## Implementation Details

### ChaCha20 Stream Cipher
1. Key Setup
   - 256-bit key expansion
   - 96-bit nonce handling
   - Counter initialization

2. Block Processing
   - Quarter round operations
   - State mixing
   - Keystream generation

### Poly1305 MAC
1. Key Derivation
   - From ChaCha20 key
   - Clamping operations

2. Message Processing
   - Block handling
   - Modular arithmetic
   - Final tag generation

### Combined Operation
1. Encryption Flow
   - Plaintext processing
   - Key and nonce setup
   - ChaCha20 encryption
   - Poly1305 authentication
   - Result combination

2. Decryption Flow
   - Input separation
   - Authentication verification
   - ChaCha20 decryption
   - Result validation

## Best Practices
1. Always use unique nonces
2. Keep encryption keys secure
3. Use AAD for associated metadata
4. Verify authentication tags
5. Handle errors appropriately
6. Monitor key storage security
7. Regular key rotation
8. Secure key file permissions

## Troubleshooting

### Common Issues
1. Authentication Failures
   - Check key matches
   - Verify nonce uniqueness
   - Validate AAD consistency
   - Check for tampering

2. Key Management Issues
   - Verify key file exists
   - Check file permissions
   - Ensure key length (32 bytes)
   - Validate key format

3. Nonce Issues
   - Ensure uniqueness
   - Check nonce length (12 bytes)
   - Verify nonce format
   - Prevent reuse

## References
- [ChaCha20-Poly1305 RFC](https://tools.ietf.org/html/rfc8439)
- [ChaCha20 Wikipedia](https://en.wikipedia.org/wiki/ChaCha20)
- [Poly1305 Wikipedia](https://en.wikipedia.org/wiki/Poly1305)
- [Go Crypto Package](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305) 