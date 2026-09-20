# PBKDF (Password-Based Key Derivation) 🔑

## Overview
A password-based key derivation function turns a human password into a fixed-length cryptographic key — **deliberately slowly**. It is how passwords should be stored and how a passphrase becomes an AES key. CryptoLens implements three: **PBKDF2**, **scrypt**, and **Argon2id**, and shows the salt, the cost parameters, and the derived key for each.

> **Why slow?** A plain hash (menu 4) is built to be *fast* — billions of guesses/sec on a GPU, which is exactly wrong for passwords. A KDF adds a **salt** (defeats rainbow tables) and a **work factor** (makes each guess expensive), turning brute force (menu 12) impractical.

## Features
- Three algorithms: PBKDF2-SHA256, scrypt, Argon2id — each genuinely run and compared
- Per-run random salt, shown as hex
- Algorithm-specific cost parameters displayed (iterations, or memory/time/threads)
- Live derivation timing
- Password-strength warnings
- Base64 output

## Usage

### Terminal User Interface
```
# Select PBKDF from the main menu
7. PBKDF (Password-Based Key Derivation)

# Choose algorithm (or benchmark all three)
1. PBKDF2   2. Argon2id   3. Scrypt   4. Run Benchmark on All

# Enter the password/passphrase
Enter text to process: correct horse battery staple
```

### Programmatic Usage
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto"

kdf := crypto.NewPBKDFProcessor()
kdf.Configure(map[string]interface{}{
    "algorithm":  "argon2id", // pbkdf2 | argon2id | scrypt
    "iterations": 100000,     // PBKDF2 only
    "memory":     65536,      // Argon2id KiB
    "threads":    4,          // Argon2id
    "keyLength":  32,
})

derivedKeyB64, steps, err := kdf.Process("password", crypto.OperationEncrypt)
// One-way: store the derived key + salt + params, never the password.
```

## Why a KDF, Not a Bare Hash
A KDF fixes the two things a plain hash lacks:
- **Salt** — a unique random value per password, so two users with the same password get different hashes and one precomputed **rainbow table** can't crack many accounts. The salt isn't secret; store it alongside the hash.
- **Work factor** — a tunable cost (iterations, or memory) so each guess is slow. Aim for **~100–500 ms** per derivation: painful for an attacker running billions of guesses, unnoticed by a real login. Raise it as hardware improves.

Bare SHA-256 has neither — never store passwords with it.

## The Three Algorithms
| Algorithm | Hardness | Cost knobs | Verdict |
|-----------|----------|------------|---------|
| **PBKDF2** | CPU only | iterations | OK / legacy; FIPS-approved. Literally HMAC (menu 6) repeated |
| **scrypt** | CPU + memory | N, r, p | Good; memory-hard (here N=32768, r=8, p=1 ≈ 32 MiB/guess) |
| **Argon2id** | CPU + memory | time, memory, threads | **Best**; winner of the 2015 Password Hashing Competition |

**Memory-hardness** is the key modern property: it forces an attacker to spend lots of RAM per guess, which neutralizes cheap massively-parallel GPU/ASIC cracking. PBKDF2 is only CPU-hard, so it's the weakest of the three against that threat — but it's simple and standardized.

For new systems, **prefer Argon2id**. Run **menu 7 → Run Benchmark** to compare all three on your machine.

## How It Works
1. **Generate a random salt** (16 bytes here), unique to this password.
2. **Stretch** the password with the chosen algorithm and its cost parameters:
   - PBKDF2: `iterations` rounds of HMAC-SHA256.
   - scrypt: fills `N·r·128` bytes of memory (memory-hard).
   - Argon2id: fills `memory` KiB across `time` passes and `threads` lanes (memory-hard + side-channel resistant).
3. **Output** a fixed-length derived key (32 bytes), Base64-encoded.

Verifying a login: re-derive with the *stored* salt and parameters, then compare in **constant time** (same discipline as HMAC, menu 6).

## Security Considerations
- Store only `(algorithm, parameters, salt, derived key)` — **never** the password.
- Use a unique random salt per password (automatic here).
- Tune cost to ~100–500 ms; increase it over time.
- A KDF also converts a passphrase into a symmetric key for **AES** (menu 3).
- A KDF buys time; it can't rescue a genuinely weak password — strength warnings are shown for short or common inputs.

## Troubleshooting
| Symptom | Cause | Fix |
|---------|-------|-----|
| "unsupported PBKDF algorithm" | Typo in `algorithm` | Use `pbkdf2`, `argon2id`, or `scrypt` |
| Derivation feels slow | High cost parameters (expected) | That's the point; lower memory/iterations only if login latency is too high |
| Different key each run | New random salt each time (expected) | Persist the salt to reproduce the key |

## References
- [RFC 8018 — PKCS #5 / PBKDF2](https://datatracker.ietf.org/doc/html/rfc8018)
- [Argon2 — Password Hashing Competition winner](https://github.com/P-H-C/phc-winner-argon2)
- [scrypt — RFC 7914](https://datatracker.ietf.org/doc/html/rfc7914)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Go `golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto)
