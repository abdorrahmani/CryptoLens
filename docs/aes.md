# AES (Advanced Encryption Standard) 🔐

## Overview
AES — originally the Rijndael cipher, standardized by NIST in 2001 (FIPS-197) — is the workhorse of modern symmetric encryption: TLS, disk encryption, VPNs, and messaging all rely on it. "Symmetric" means the same secret key both encrypts and decrypts. CryptoLens implements AES with configurable key sizes (128/192/256 bits, defaulting to 256) in **CBC mode** with **PKCS#7 padding**, and walks through every step — padding, IV, block chaining, and the reverse on decryption.

> **AES is a block cipher, not a whole encryption scheme.** The cipher only transforms one 16-byte block; a *mode of operation* (CBC here) chains blocks to handle real messages. Most real-world failures come from misusing the mode, not from breaking AES.

## Features
- Configurable key sizes (128/192/256 bits → 10/12/14 rounds)
- Fresh random IV per encryption
- PKCS#7 padding with full validation on decrypt
- Concrete, per-input padding and CBC-chaining walkthrough
- IV prepended to ciphertext, Base64-encoded output
- File-based key storage (demo only)

## Usage

### Terminal User Interface
```
# Select AES from the main menu
3. AES Encryption/Decryption

# Choose operation
1. Encrypt
2. Decrypt

# Enter text to process
Enter text to process: Your secret message
```

### Programmatic Usage
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto"

aes := crypto.NewAESProcessor()
aes.Configure(map[string]interface{}{
    "keySize": 256,                        // 128, 192, or 256
    "keyFile": "keys/custom_aes_key.bin",  // optional
})

encrypted, steps, err := aes.Process("Your secret message", crypto.OperationEncrypt)
decrypted, steps, err := aes.Process(encrypted, crypto.OperationDecrypt)
```

## How It Works

### Block cipher vs. mode of operation
AES itself maps one 16-byte block to one 16-byte block under the key. To encrypt arbitrary-length data you need:
1. **Padding** so the length is a multiple of 16, and
2. **A mode** that combines successive block encryptions. CryptoLens uses **CBC**.

### PKCS#7 padding
CBC needs whole 16-byte blocks. PKCS#7 fills the remainder with bytes whose value equals the number of padding bytes:

| Input length mod 16 | Padding bytes | Value |
|---------------------|---------------|-------|
| 2 (e.g. "Hi")       | 14            | `0x0E` ×14 |
| 5 (e.g. "Hello")    | 11            | `0x0B` ×11 |
| 0 (already aligned) | 16 (full block) | `0x10` ×16 |

The full extra block when already aligned is deliberate — it lets the decrypter always distinguish padding from real data.

### CBC chaining
```
Encrypt:  C[1] = AES_encrypt(P[1] XOR IV)
          C[i] = AES_encrypt(P[i] XOR C[i-1])   for i > 1

Decrypt:  P[1] = AES_decrypt(C[1]) XOR IV
          P[i] = AES_decrypt(C[i]) XOR C[i-1]   for i > 1
```
XORing each block with the previous ciphertext means **identical plaintext blocks encrypt differently**, hiding the patterns that ECB mode leaks (see the ECB attack simulation, menu 12). The output is `IV || ciphertext`, Base64-encoded, so the decrypter can recover the IV (which is not secret).

### Inside one AES block (14 rounds for AES-256)
Each block is arranged as a 4×4 byte matrix (the "state") and put through rounds of:
1. **SubBytes** — non-linear S-box substitution (confusion)
2. **ShiftRows** — rotate matrix rows (diffusion across columns)
3. **MixColumns** — linear column mixing (diffusion within columns)
4. **AddRoundKey** — XOR the round key from the key schedule

The first round is AddRoundKey only; the final round omits MixColumns. This is handled by Go's `crypto/aes`; CryptoLens describes it for understanding rather than re-implementing it.

## Example

### Encrypting `Hi` (AES-256)
```
Input as Bytes:  48 69
PKCS#7:          2 mod 16 = 2 → 14 bytes of 0x0E
Padded Input:    48 69 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e
IV (random):     f4 3e 34 09 ...
P[1] XOR IV:     bc 57 3a 07 ...   ← this is what AES encrypts
Ciphertext:      86 67 0e 6e ...
Result:          base64(IV || ciphertext)
```
The Base64 result changes every run because the IV is random — that is correct and desirable.

## Security Considerations

| Point | Why it matters |
|-------|----------------|
| Keep the key secret | Anyone with the key can decrypt. This tool's `keys/` storage is for the demo only; use a KMS/OS keystore in production |
| Unique, unpredictable IV | Reusing an IV with the same key in CBC leaks whether messages share a prefix |
| CBC ≠ authenticity | CBC gives confidentiality only; an attacker can flip ciphertext bits, and padding checks enable **padding-oracle attacks** |
| Prefer AEAD | AES-GCM or ChaCha20-Poly1305 (menu 11) encrypt *and* authenticate in one step |

AES the cipher remains unbroken; choose the mode carefully.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "invalid base64 string" | Input to decrypt isn't valid Base64 | Paste the exact encrypted output |
| "ciphertext too short" / "not a whole number of blocks" | Input is truncated or not AES output | Ensure IV (16 bytes) + full blocks are present |
| "failed to unpad: invalid padding" | Wrong key, corrupted data, or tampering | Verify the key matches the one used to encrypt |

## References
- [FIPS-197 — AES Specification (NIST)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [AES — Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [Block cipher mode of operation (CBC) — Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC)
- [PKCS#7 padding — RFC 5652 §6.3](https://tools.ietf.org/html/rfc5652#section-6.3)
- [Go `crypto/aes` package](https://pkg.go.dev/crypto/aes)
