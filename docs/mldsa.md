# ML-DSA (Post-Quantum Signatures) 🛡️

## Overview
ML-DSA (FIPS 204), formerly **Dilithium**, is a **post-quantum digital signature scheme**. Signatures prove **authenticity** and **integrity**: sign with a private key, and anyone can verify with the public key — the reverse roles of encryption. It serves the same purpose as RSA (menu 5) and EdDSA (menu 10) signatures, but its security rests on **lattice** problems (Module-LWE / Module-SIS) with no known efficient quantum attack. CryptoLens signs a message, verifies it, and demonstrates that tampering invalidates the signature. Default parameter set: **ML-DSA-65**.

> **Signatures don't hide data.** They authenticate it. To also encrypt, combine with a KEM like ML-KEM (menu 12).

## Why Post-Quantum?
**Shor's algorithm** on a large quantum computer would recover the private key behind RSA/ECDSA/EdDSA signatures and forge them at will. Signatures especially need PQ protection for anything verified **far in the future** — firmware and software-update signing, long-lived certificates, and archived documents — because a signature made today must still resist an attacker with tomorrow's hardware.

## How It Works
```
1. GenerateKey()  → (privateKey, publicKey)      # publish the public key
2. signature = Sign(privateKey, message)          # only the key holder can do this
3. Verify(publicKey, message, signature) → ok/err # anyone can check
```
A signature binds to the **exact** message: flip one bit of the message (or forge a signature without the private key) and verification fails — which CryptoLens demonstrates with an automatic tamper test.

## Sizes (the trade-off)
| Scheme | Public key | Signature |
|--------|-----------|-----------|
| **ML-DSA-44** | 1312 B | 2420 B |
| **ML-DSA-65** | 1952 B | 3309 B |
| **ML-DSA-87** | 2592 B | 4627 B |
| Ed25519 | 32 B | 64 B |
| RSA-2048 | ~270 B | 256 B |

Post-quantum signatures are **kilobytes, not bytes**. That growth hits certificate chains and TLS handshakes, which is why adoption is staged and often hybrid. Security levels: ML-DSA-44 ≈ AES-128, ML-DSA-65 ≈ AES-192, ML-DSA-87 ≈ AES-256.

## Usage
```
# Select from the main menu, then enter a message to sign
13. ML-DSA (Post-Quantum Signatures)
```
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto"

dsa := crypto.NewMLDSAProcessor()
dsa.Configure(map[string]interface{}{"level": 65}) // 44, 65 (default), or 87
result, steps, err := dsa.Process("Transfer $100 to Alice", "") // signs + verifies + tamper test
```

## Security Notes
- Gives authenticity/integrity, **not** confidentiality — pair with ML-KEM (menu 12) to encrypt.
- Keep the private key secret; anyone holding it can forge signatures.
- Deployments often use **hybrid** signatures (classical + PQ) during the transition.
- A signing **context** string can bind a signature to a specific protocol/purpose (domain separation).
- Standardized by NIST in 2024 (FIPS 204); with ML-KEM it forms a full post-quantum stack, replacing the RSA/ECDH + RSA/ECDSA pairing quantum computers would break.

## References
- [NIST FIPS 204 — ML-DSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [Go `crypto/mldsa` package](https://pkg.go.dev/crypto/mldsa)
- [Dilithium / CRYSTALS](https://pq-crystals.org/dilithium/)
