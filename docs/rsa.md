# RSA (Rivest–Shamir–Adleman) 🔐

## Overview
RSA (1977) was the first practical **public-key** cipher. It is **asymmetric**: it uses a *key pair* rather than one shared secret — a public key that anyone can use to encrypt, and a private key that only the owner uses to decrypt. CryptoLens implements RSA with configurable key sizes (1024/2048/4096 bits, default 2048) and PKCS#1 v1.5 padding, and walks through the real key parameters, a live toy-math example, and the encrypt/decrypt flow.

> **The padlock analogy:** hand out open padlocks freely (the public key). Anyone can snap one shut on a box and send it to you, but only you hold the key that opens it (the private key). That asymmetry is the whole idea.

## Features
- Configurable key sizes (1024/2048/4096 bits), PEM key storage
- Shows the real key parameters: modulus size, public exponent `e`, max message size
- **Live worked example** on tiny primes (p=61, q=53) computing keygen, encrypt, and decrypt
- Friendly, specific error when a message exceeds the size limit
- Base64 ciphertext output
- Real-world context: hybrid encryption, signatures, quantum threat

## Usage

### Terminal User Interface
```
# Select RSA from the main menu
5. RSA Encryption/Decryption

# Choose operation
1. Encrypt
2. Decrypt

# Enter text to process
Enter text to process: Your secret message
```

### Programmatic Usage
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto"

rsa := crypto.NewRSAProcessor()
rsa.Configure(map[string]interface{}{
    "keySize":        2048,
    "publicKeyFile":  "keys/rsa_public.pem",
    "privateKeyFile": "keys/rsa_private.pem",
})

encrypted, steps, err := rsa.Process("Your secret message", crypto.OperationEncrypt)
decrypted, steps, err := rsa.Process(encrypted, crypto.OperationDecrypt)
```

## How It Works

### The trapdoor
Multiplying two large primes `p · q = n` is easy; **factoring** `n` back into `p` and `q` is infeasible for a large enough `n`. The public key exposes `n`, but only someone who knows the factors can derive the private key. That "easy one way, infeasible to reverse — unless you hold the trapdoor" is what makes RSA secure.

### Key generation (worked example with tiny primes)
Real keys use primes hundreds of digits long; the same math on small numbers:
```
1. Pick primes    p = 61, q = 53
2. Modulus        n = p·q = 3233
3. Totient        φ(n) = (p−1)(q−1) = 3120
4. Public exp     e = 17            (coprime with φ)
5. Private exp    d = e⁻¹ mod φ = 2753   (so e·d mod φ = 1)
   Public key  = (n=3233, e=17)
   Private key = (n=3233, d=2753)
6. Encrypt m=65:  c = m^e mod n = 2790
7. Decrypt c=2790: m = c^d mod n = 65   ✅
```
Security rests on step 5: without `p` and `q` you cannot compute `φ`, and without `φ` you cannot find `d`.

### Encryption / Decryption
```
Encrypt (public key):   c = m^e mod n
Decrypt (private key):  m = c^d mod n
```
The public exponent `e` is almost always **65537** — prime, with few 1-bits, so encryption is fast. PKCS#1 v1.5 padding mixes in **random bytes**, so encrypting the same text twice yields different ciphertexts; that randomization is essential to security. The ciphertext is always exactly the modulus size (256 bytes for RSA-2048), regardless of message length.

## The Message-Size Limit
RSA encrypts a single number smaller than `n`, so the plaintext must fit in one block:

| Key size | Max message (PKCS#1 v1.5) |
|----------|---------------------------|
| 1024-bit | 117 bytes |
| 2048-bit | 245 bytes |
| 4096-bit | 501 bytes |

(`modulus bytes − 11`.) CryptoLens returns a clear error if you exceed it. Real systems don't encrypt bulk data with RSA directly — see hybrid encryption below.

## RSA in the Real World
- **Hybrid encryption:** RSA is slow and size-limited, so TLS and PGP use RSA only to *wrap a random AES key*, then encrypt the actual data with AES (menu 3). This is the standard pattern.
- **Digital signatures:** sign with the *private* key, verify with the *public* key — the reverse of encryption. Proves authenticity and integrity (see JWT RS256, menu 10).
- **Padding matters:** "textbook" RSA with no padding is insecure. Modern code prefers **OAEP** over the PKCS#1 v1.5 used here, which has known padding-oracle pitfalls.

## Security Considerations
| Point | Detail |
|-------|--------|
| Key size | Use ≥ 2048-bit; 1024-bit is deprecated. 3072/4096-bit for long-term secrets |
| Private key secrecy | Anyone with the private key can decrypt *and* forge signatures |
| Quantum threat | A large quantum computer running **Shor's algorithm** would break RSA; hence the shift to post-quantum algorithms for long-lived data |
| Alternatives | For key agreement, elliptic-curve methods like **X25519** (menu 9) are smaller and faster |

## Troubleshooting
| Symptom | Cause | Fix |
|---------|-------|-----|
| "message is N bytes but RSA-2048 … can encrypt at most 245" | Plaintext too large | Use hybrid encryption (RSA-wrap an AES key) |
| "failed to decrypt (wrong key, corrupted data, or bad padding)" | Wrong key pair, altered ciphertext | Ensure the matching private key and intact Base64 |
| "invalid base64 string" | Decrypt input isn't the encrypt output | Paste the exact Base64 ciphertext |

## References
- [RSA (cryptosystem) — Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [PKCS#1 / RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017)
- [Shor's algorithm — Wikipedia](https://en.wikipedia.org/wiki/Shor%27s_algorithm)
- [NIST SP 800-57 — Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [Go `crypto/rsa` package](https://pkg.go.dev/crypto/rsa)
