# HMAC (Hash-based Message Authentication Code) 🔑

## Overview
HMAC combines a cryptographic hash function with a **secret key** to produce an authentication *tag*. It answers two questions at once: was the message **altered** (integrity), and did it come from someone holding the **shared key** (authenticity)? CryptoLens computes HMAC by hand — showing every intermediate value — cross-checks it against Go's `crypto/hmac`, and demonstrates the verification step that is HMAC's whole reason to exist. Supported hashes: SHA-1, SHA-256, SHA-512, BLAKE2b-256, BLAKE2b-512, BLAKE3.

> **HMAC vs. a plain hash:** a bare hash (menu 4) gives integrity only — anyone can recompute it. Adding a secret key means only key-holders can produce or verify the tag. HMAC is still one-way: you cannot recover the message from the tag.

## Features
- Six hash functions, selectable at runtime; built-in benchmark
- **Hand-computed construction** with every intermediate value shown (block key, K⊕ipad, K⊕opad, inner hash, tag), verified against `crypto/hmac`
- **Verification demo**: accepts the real message, rejects a tampered one, and explains constant-time comparison
- Explains *why* HMAC is nested (length-extension resistance)
- Hex and Base64 output

## Usage

### Terminal User Interface
```
# Select HMAC from the main menu
6. HMAC (Hash-based Message Authentication)

# Choose hash algorithm (or benchmark)
1. SHA-1   2. SHA-256   3. SHA-512
4. BLAKE2b-256   5. BLAKE2b-512   6. BLAKE3   7. Run Benchmark

# Enter text to process
Enter text to process: Your message here
```

### Programmatic Usage
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto"

h := crypto.NewHMACProcessor()
h.Configure(map[string]interface{}{
    "hashAlgorithm": "sha256", // sha1, sha256, sha512, blake2b-256, blake2b-512, blake3
    "keyFile":       "keys/hmac_key.bin",
})

result, steps, err := h.Process("Your message here", crypto.OperationEncrypt)
// HMAC is one-way; only OperationEncrypt (compute a tag) is valid.
```

## How It Works

### The workflow
1. **Sender** computes `tag = HMAC(key, message)` and sends `(message, tag)`.
2. **Receiver** recomputes `HMAC(key, message)` and checks it equals the tag.
3. Match → authentic and untampered. Mismatch → reject.

### The construction
```
HMAC(K, m) = H( (K ⊕ opad) ‖ H( (K ⊕ ipad) ‖ m ) )
```
CryptoLens walks this on your real input:
1. **Normalize the key** to the hash's block size (hash it down if longer, zero-pad if shorter).
2. **Derive two keys:** `K ⊕ ipad` (ipad = `0x36` repeated) and `K ⊕ opad` (opad = `0x5c` repeated).
3. **Inner hash:** `H(innerKey ‖ message)`.
4. **Outer hash:** `H(outerKey ‖ innerHash)` → the tag.

### Why nested? (length-extension resistance)
The obvious construction `Hash(key ‖ message)` is **insecure** with Merkle–Damgård hashes like SHA-1/SHA-2: knowing `Hash(key ‖ msg)` and the length lets an attacker forge a valid value for `msg ‖ extra` **without the key** (the length-extension attack). HMAC's outer hash conceals the inner hash's internal state, so extension is impossible. (This is also why SHA-256's own page, menu 4, warns against `hash(key‖message)`.)

## Verification (the point)
CryptoLens demonstrates both outcomes:
- **Untampered:** the receiver recomputes the tag → matches → **ACCEPT**.
- **Tampered:** flipping one byte of the message changes ~half the tag's bits, and without the key the attacker cannot produce the right tag → **REJECT**.

Tags must be compared in **constant time** (`hmac.Equal` / `subtle.ConstantTimeCompare`). A normal `==` returns early on the first differing byte; measuring that timing can leak the tag byte-by-byte — see the **Timing Attack** simulation (menu 12).

## Choosing the Hash
| Algorithm | Tag size | Notes |
|-----------|----------|-------|
| sha1 | 20 bytes | Legacy. HMAC-SHA1 is not broken, but avoid for new work |
| sha256 | 32 bytes | Safe, ubiquitous default |
| sha512 | 64 bytes | Larger margin; faster than SHA-256 on 64-bit CPUs |
| blake2b-256 | 32 bytes | Faster than SHA-2, modern (128-byte block) |
| blake2b-512 | 64 bytes | Faster than SHA-512, modern |
| blake3 | 32 bytes | Very fast; parallel/tree hashing |

Run **menu 6 → Run Benchmark** to compare their speed on your machine.

## Security Considerations
- HMAC provides **integrity + authenticity**, but **not confidentiality** — the message is not encrypted. Combine with encryption (encrypt-then-MAC) when you need both.
- Keep the key secret; use a full-length random key (≥ the hash output size).
- HMAC is provably resistant to length-extension, unlike a bare hash.
- Even with a weakened hash, HMAC holds up (HMAC-SHA1 is still unbroken), though SHA-256+ is preferred.
- HMAC underpins **HKDF** and **PBKDF2** (menu 7) and **JWT HS256** (menu 10).

## Troubleshooting
| Symptom | Cause | Fix |
|---------|-------|-----|
| "invalid operation" on decrypt | HMAC is one-way | Only compute tags; there is nothing to decrypt |
| Tag differs from another tool | Different key or hash algorithm | Match the key bytes and hash choice exactly |
| Verification always fails | Comparing different encodings | Compare raw bytes (or the same hex/Base64 form) with a constant-time check |

## References
- [RFC 2104 — HMAC](https://datatracker.ietf.org/doc/html/rfc2104)
- [HMAC — Wikipedia](https://en.wikipedia.org/wiki/HMAC)
- [Length extension attack — Wikipedia](https://en.wikipedia.org/wiki/Length_extension_attack)
- [Go `crypto/hmac` package](https://pkg.go.dev/crypto/hmac)
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) · [BLAKE2](https://blake2.net/)
