# Diffie-Hellman (DH) Key Exchange 🔑

## Overview
Diffie-Hellman (1976) lets two parties who have never met agree on a shared secret over a channel an eavesdropper is fully watching — **without ever sending the secret**. It is *key agreement*, not encryption: the output is a shared key, which is then used with a symmetric cipher like AES. CryptoLens demonstrates the full authenticated flow — a live toy-math example, real 2048-bit exchange, RSA-signed public keys (anti-MITM), HKDF derivation, AES-GCM encryption, and an X25519 speed comparison.

> **Paint analogy:** Alice and Bob publicly agree on a base color, each mixes in a secret color, and they swap mixtures. Each stirs in their own secret again and both reach the *same* final color — but an observer who saw the swapped mixtures can't "un-mix" them to recover the secrets.

## The Math (worked example)
The real exchange uses 2048-bit numbers no one can follow, so CryptoLens computes it live on tiny numbers first:
```
Public:  prime p = 23, generator g = 5
Alice picks secret a = 6  → public A = 5^6  mod 23 = 8
Bob   picks secret b = 15 → public B = 5^15 mod 23 = 19
They swap A and B openly, then:
  Alice: B^a mod p = 19^6  mod 23 = 2
  Bob:   A^b mod p = 8^15  mod 23 = 2
Both get 2 = g^(a·b) mod p   ✅
```
An eavesdropper knows `p, g, A, B` but recovering `a` from `A = g^a mod p` is the **discrete logarithm problem** — infeasible for a large prime. That one-way asymmetry is the whole trick.

## Features
- Live toy-math worked example (verifiable by hand) before the real 2048-bit exchange
- Secure prime generation and management; configurable key size and generator
- RSA signatures for public key authentication (prevents MITM)
- HKDF-based key derivation feeding AES-GCM encryption
- Perfect Forward Secrecy explained
- Step-by-step visualization and an X25519 performance comparison

## Why It Matters: Perfect Forward Secrecy
Using **fresh, ephemeral** DH keys per session (DHE / ECDHE) means a later compromise of long-term keys **cannot** decrypt past recorded sessions — each session's secret vanished when its ephemeral keys were discarded. This is why TLS 1.3 mandates ephemeral (EC)DH and dropped static RSA key exchange. For new systems, prefer elliptic-curve DH (**X25519**, menu 9): smaller, faster, and safer defaults than classic modular-exponent DH.

## Usage

### Command Line Interface
```bash
# Select Diffie-Hellman from the main menu (Option 8)
8. Diffie-Hellman Key Exchange

# Press Enter to start key exchange demonstration...

Result:
Successfully demonstrated authenticated Diffie-Hellman key exchange and AES encryption

Processing Steps:
# (See below for detailed steps)
```

### Programmatic Usage
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto"

// Create DH processor
dhProcessor := crypto.NewDHProcessor()

// Configure the processor
config := map[string]interface{}{
    "keySize": 2048,           // Optional: key size in bits
    "generator": 2,            // Optional: generator value
    "primeFile": "keys/dh_prime.bin", // Optional: custom prime file path
}
dhProcessor.Configure(config)

// Run the key exchange demonstration
result, steps, err := dhProcessor.Process("", "")
```

## Technical Details

### Key Management
- Secure random prime generation (configurable size)
- File-based prime storage in `keys` directory
- Automatic prime generation if not exists
- Custom prime file path support

### Key Exchange Process
1. Prime and generator setup
2. Private key generation for Alice and Bob
3. Public key calculation
4. Public key authentication using RSA signatures
5. Shared secret calculation
6. Shared secret verification
7. Key derivation using HKDF
8. Demonstration of AES-GCM encryption with derived key
9. Performance comparison with X25519

### Security Features
- RSA signatures to authenticate public keys (prevents MITM)
- HKDF for secure key derivation
- AES-GCM for authenticated encryption
- Step-by-step verification and error handling

## Example: Step-by-Step Output

```
Diffie-Hellman Key Exchange
=============================
Note:  Diffie-Hellman is a method of securely exchanging cryptographic keys
Note:  It allows two parties to establish a shared secret over an insecure channel
Note:  The security is based on the difficulty of the discrete logarithm problem
----------------------------------------

Step 1: Prime Number Setup
------------------------
Parameters:
Prime (p):  <hexadecimal prime>
Generator (g):  2
Key Size:  2048 bits
----------------------------------------

Step 2: Private Key Generation
----------------------------
Alice's Private Key:  <hexadecimal>
Bob's Private Key:    <hexadecimal>
    ↓↓↓

Step 3: Public Key Calculation
----------------------------
Alice's Public Key:  <hexadecimal>
Bob's Public Key:    <hexadecimal>
    ↓↓↓

Step 4: Key Authentication
-------------------------
Note:  To prevent MITM attacks, we'll authenticate the public keys using RSA signatures
RSA Key Pairs Generated:
Alice's RSA Public Key:  <hex>
Bob's RSA Public Key:    <hex>
Signatures Created:
Alice's Signature:  <hex>
Bob's Signature:    <hex>
✅ Signatures Verified Successfully
Note:  This proves the public keys are authentic and haven't been tampered with
    ↓↓↓

Step 5: Shared Secret Calculation
-------------------------------
Alice's Shared Secret:  <hexadecimal>
Bob's Shared Secret:    <hexadecimal>
    ↓↓↓

Step 6: Shared Secret Verification
--------------------------------
✅ Shared secrets match!
----------------------------------------

Step 7: Key Derivation
---------------------
Derived key (using HKDF):  <hex>
----------------------------------------

Step 8: Using Shared Secret for AES Encryption
-------------------------------------------
Note:  Now we'll demonstrate how the shared secret can be used for symmetric encryption
Original Message:  Hello, this is a secret message!
Encrypted Message (Base64):  <base64>
Decrypted Message:  Hello, this is a secret message!
    ↓↓↓

⚡ Performance Comparison
=======================
Classic DH Execution Time:  <duration>
X25519 Execution Time:      <duration>
X25519 is <x> faster than Classic DH
----------------------------------------

How it works:
1. DH establishes a shared secret between Alice and Bob
2. RSA signatures authenticate the public keys
3. The shared secret is used to derive an AES key
4. The AES key is used to encrypt/decrypt messages
5. Both parties can encrypt/decrypt using the same key
----------------------------------------

🔒 Security Considerations
========================
1. Man-in-the-Middle (MITM) Attack Prevention:
   • RSA signatures authenticate public keys
   • Prevents attackers from substituting their own keys
   • Similar to how TLS uses certificates
----------------------------------------
2. Key Derivation Function (KDF):
   • Raw shared secret should never be used directly
   • KDF provides additional security properties:
     - Key stretching
     - Key separation
     - Key diversification
----------------------------------------
3. Best Practices:
   • Use authenticated key exchange (e.g., TLS)
   • Implement perfect forward secrecy
   • Use strong prime numbers
   • Regularly rotate keys
   • Verify all signatures
----------------------------------------
4. Real-World Usage Examples:
   • TLS/SSL handshake:
     - Server sends certificate (signed public key)
     - Client verifies certificate
     - DH key exchange follows
     - All messages authenticated
   • SSH key exchange
   • Signal Protocol
   • WireGuard VPN
----------------------------------------
```

## Best Practices
1. Always use authenticated key exchange (e.g., with signatures or certificates)
2. Use strong, random primes and generators
3. Never use the raw shared secret directly—always derive keys with a KDF
4. Regularly rotate keys and primes
5. Validate all signatures and public keys
6. Monitor key storage security
7. Use modern alternatives (e.g., X25519) for better performance and security

## Troubleshooting

### Common Issues
1. Prime File Issues
   - Check `keys` directory exists
   - Verify file permissions (0700)
   - Ensure prime file is readable

2. Signature Verification Failures
   - Ensure correct RSA keys are used
   - Validate public key hashes before signing
   - Check for tampering or MITM

3. Shared Secret Mismatch
   - Verify public/private key calculations
   - Ensure both parties use the same parameters

4. Configuration Errors
   - Valid key sizes: 1024, 2048, 4096, etc.
   - Valid generator values (commonly 2 or 5)
   - Proper directory permissions

## References
- [Diffie-Hellman Key Exchange (Wikipedia)](https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange)
- [RFC 3526: More Modular Exponential (MODP) Diffie-Hellman groups](https://datatracker.ietf.org/doc/html/rfc3526)
- [Go crypto/rand](https://pkg.go.dev/crypto/rand)
- [Go math/big](https://pkg.go.dev/math/big)
- [Go crypto/rsa](https://pkg.go.dev/crypto/rsa)
- [Go crypto/cipher](https://pkg.go.dev/crypto/cipher)
- [Go x/crypto/hkdf](https://pkg.go.dev/golang.org/x/crypto/hkdf)
- [X25519 (RFC 7748)](https://datatracker.ietf.org/doc/html/rfc7748) 