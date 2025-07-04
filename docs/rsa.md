# RSA (Rivest–Shamir–Adleman) 🔐

## Overview
RSA is an asymmetric encryption algorithm that uses a pair of keys: a public key for encryption and a private key for decryption. CryptoLens implements RSA with configurable key sizes (1024, 2048, or 4096 bits), defaulting to 2048 bits for a balance of security and performance.

## Features
- Configurable key sizes (1024/2048/4096 bits)
- Automatic key generation and file-based storage
- PEM-encoded public/private key files
- Base64 encoded output for ciphertext
- Step-by-step process visualization
- Secure key management

## Usage

### Command Line Interface
```bash
# Select RSA from the main menu (Option 5)
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

// Create RSA processor
rsaProcessor := crypto.NewRSAProcessor()

// Configure the processor
config := map[string]interface{}{
    "keySize": 2048,  // Optional: 1024, 2048, or 4096 bits
    "publicKeyFile": "keys/custom_rsa_public.pem",   // Optional: custom public key file path
    "privateKeyFile": "keys/custom_rsa_private.pem", // Optional: custom private key file path
}
rsaProcessor.Configure(config)

// Encrypt
encrypted, steps, err := rsaProcessor.Process("Your secret message", "encrypt")

// Decrypt
decrypted, steps, err := rsaProcessor.Process(encrypted, "decrypt")
```

## Technical Details

### Key Management
- Configurable key sizes (1024/2048/4096 bits)
- Secure random key generation
- File-based key storage in `keys` directory
- PEM-encoded key files for interoperability
- Automatic key generation if not exists
- Custom key file path support

### Encryption Process
1. Input validation
2. Convert text to bytes
3. Encrypt with public key (PKCS#1 v1.5 padding)
4. Base64 encode the ciphertext

### Decryption Process
1. Base64 decode the input
2. Decrypt with private key (PKCS#1 v1.5 padding)
3. Convert result to text

### Security Features
- Private key stored securely (0600 permissions)
- Public key can be shared freely
- Input validation and error handling
- Key size selection for desired security level
- Security notes and warnings in process steps

## Examples

### Encryption Example
```bash
Input: HelloRSA
Output: Y2lwaGVydGV4dA==

Processing Steps:
RSA Encryption Process
=============================
Note:  RSA is an asymmetric encryption algorithm
Note:  Using 2048-bit keys
----------------------------------------
Key Information:
Public Key Size: 2048 bits
Private Key Size: 2048 bits
----------------------------------------
Encryption Process:
1. Convert text to bytes
2. Use public key to encrypt
3. Base64 encode the result
----------------------------------------
Input Text:  HelloRSA
    ↓↓↓
Text as Bytes:  48 65 6c 6c 6f 52 53 41
    ↓↓↓
Encrypted Data:  ...
    ↓↓↓
Base64 Encoded Result:  Y2lwaGVydGV4dA==
----------------------------------------
Note:  Security Considerations:
Note:  1. RSA encryption uses the public key
Note:  2. The public key can be shared freely
Note:  3. RSA has a maximum message size based on key size
Note:  4. For large messages, use hybrid encryption (RSA + AES)
----------------------------------------
How RSA Works:
1. Generate two large prime numbers (p and q)
2. Calculate n = p * q
3. Calculate φ(n) = (p-1) * (q-1)
4. Choose public exponent e (usually 65537)
5. Calculate private exponent d where (d * e) mod φ(n) = 1
6. Public key is (n, e)
7. Private key is (n, d)
8. Encryption: c = m^e mod n
9. Decryption: m = c^d mod n
```

### Decryption Example
```bash
Input: Y2lwaGVydGV4dA==
Output: HelloRSA

Processing Steps:
RSA Encryption Process
=============================
Note:  RSA is an asymmetric encryption algorithm
Note:  Using 2048-bit keys
----------------------------------------
Key Information:
Public Key Size: 2048 bits
Private Key Size: 2048 bits
----------------------------------------
Decryption Process:
1. Base64 decode the input
2. Use private key to decrypt
3. Convert result to text
----------------------------------------
Encrypted Input (Base64):  Y2lwaGVydGV4dA==
    ↓↓↓
Decoded Data:  ...
    ↓↓↓
Decrypted Text:  HelloRSA
----------------------------------------
Note:  Security Considerations:
Note:  1. RSA decryption requires the private key
Note:  2. The private key must be kept secure
Note:  3. RSA is vulnerable to timing attacks if not properly implemented
Note:  4. The security depends on the key size and proper key management
```

## Implementation Details

### RSA Algorithm Steps
1. Key Generation
   - Generate two large prime numbers (p, q)
   - Compute modulus n = p * q
   - Compute totient φ(n) = (p-1)*(q-1)
   - Choose public exponent e (commonly 65537)
   - Compute private exponent d such that (d * e) mod φ(n) = 1
   - Public key: (n, e)
   - Private key: (n, d)

2. Encryption
   - Convert plaintext to integer m
   - Compute ciphertext c = m^e mod n

3. Decryption
   - Compute plaintext m = c^d mod n
   - Convert integer m back to text

### CryptoLens Implementation
- Uses Go's `crypto/rsa` and `crypto/x509` for key generation and encryption
- PEM-encoded key files for compatibility
- PKCS#1 v1.5 padding for encryption/decryption
- Base64 encoding for output
- Step-by-step visualization using CryptoLens visualizer

## Best Practices
1. Use at least 2048-bit keys for security
2. Keep private keys secure (never share or expose)
3. Public keys can be distributed freely
4. For large data, use hybrid encryption (RSA for key exchange, AES for data)
5. Regularly rotate keys and monitor key storage
6. Validate all input data and handle errors
7. Use secure random number generation for key creation

## Troubleshooting

### Common Issues
1. Key File Issues
   - Check `keys` directory exists
   - Verify file permissions (0600 for private key)
   - Ensure key files are readable and valid PEM format

2. Decryption Failures
   - Verify input is valid base64
   - Ensure correct key pair is used
   - Check for message size limits (RSA can only encrypt data smaller than key size minus padding)

3. Configuration Errors
   - Valid key sizes: 1024, 2048, 4096
   - Valid key file paths
   - Proper directory permissions

## References
- [RSA Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Go Crypto Package](https://pkg.go.dev/crypto/rsa)
- [PKCS#1 v1.5 Padding](https://datatracker.ietf.org/doc/html/rfc8017)
- [NIST Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) 