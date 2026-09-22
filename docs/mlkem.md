# ML-KEM (Post-Quantum Key Encapsulation) 🛡️

## Overview
ML-KEM (FIPS 203), formerly **Kyber**, is a **post-quantum key encapsulation mechanism** (KEM). It lets two parties agree on a shared secret over an open channel — the same goal as Diffie-Hellman (menu 8) and X25519 (menu 9) — but its security rests on **lattice** problems (Module-LWE) that are believed hard even for quantum computers. CryptoLens demonstrates the full encapsulate → decapsulate round trip and shows the size trade-off versus classical key exchange. Default parameter set: **ML-KEM-768**.

> **Key agreement, not encryption.** A KEM outputs a 32-byte shared secret; a KDF/AEAD then encrypts the actual data (the "KEM + DEM" pattern). On its own ML-KEM provides **no authentication** — pair it with a signature (ML-DSA, menu 13) or certificate.

## Why Post-Quantum?
A large quantum computer running **Shor's algorithm** would break RSA (menu 5) and elliptic-curve DH (X25519, menu 9) — the key exchanges securing the internet today. Lattice problems have no known efficient quantum attack. The urgency comes from **"harvest now, decrypt later"**: adversaries record encrypted traffic today to decrypt once quantum hardware exists, so key exchange needs PQ protection *now*.

## How a KEM Works
Unlike DH (where both sides exponentiate a shared group element), a KEM is asymmetric in roles:
```
1. Alice: (encapsulationKey, decapsulationKey) = GenerateKey()   # publishes encapsulationKey
2. Bob:   (sharedSecret, ciphertext) = Encapsulate(encapsulationKey)   # sends ciphertext
3. Alice: sharedSecret = Decapsulate(decapsulationKey, ciphertext)
   → both hold the same 32-byte secret; only the ciphertext crossed the wire
```

## Sizes (the trade-off)
| Scheme | Public key | Ciphertext | Shared secret |
|--------|-----------|------------|---------------|
| **ML-KEM-768** | 1184 B | 1088 B | 32 B |
| **ML-KEM-1024** | 1568 B | 1568 B | 32 B |
| X25519 | 32 B | — | 32 B |

Post-quantum keys/ciphertexts are ~30–50× larger; that extra handshake bandwidth is the price of quantum resistance. ML-KEM-768 ≈ AES-192 security; ML-KEM-1024 ≈ AES-256.

## Usage
```
# Select from the main menu, then press Enter to run the demonstration
12. ML-KEM (Post-Quantum Key Encapsulation)
```
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto"

kem := crypto.NewMLKEMProcessor()
kem.Configure(map[string]interface{}{"level": 768}) // 768 (default) or 1024
result, steps, err := kem.Process("", "") // text/operation ignored — it's a demo
```

## Security Notes
- Provides confidentiality of the agreed key, **not** authentication — combine with ML-DSA (menu 13) or a certificate to prevent MITM.
- Real deployments use **hybrid** key exchange (e.g. TLS 1.3's `X25519MLKEM768`): the session stays secure if *either* algorithm holds, hedging against both classical and quantum breaks.
- Use fresh (ephemeral) keys per session for forward secrecy.
- Standardized by NIST in 2024 (FIPS 203); already shipping in Chrome, major TLS libraries, and OpenSSH.

## References
- [NIST FIPS 203 — ML-KEM](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [Go `crypto/mlkem` package](https://pkg.go.dev/crypto/mlkem)
- [Kyber / CRYSTALS](https://pq-crystals.org/kyber/)
- [Cloudflare: The state of the post-quantum internet](https://blog.cloudflare.com/pq-2024/)
