# AES (Advanced Encryption Standard) 🔐

## Overview
AES is a symmetric encryption algorithm that uses the same key for both encryption and decryption. CryptoLens implements AES-256, which uses a 256-bit key size for maximum security.

## Features
- AES-256 implementation
- Secure key generation
- IV (Initialization Vector) management
- Block cipher operations
- Base64 encoded output
- Step-by-step process visualization

## Usage

### Command Line
```bash
# Encryption
cryptolens aes encrypt "Your secret message"

# Decryption
cryptolens aes decrypt "encrypted_base64_string"
```

### Programmatic Usage
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto/aes"

// Create AES instance
aesCrypto := aes.New()

// Encrypt
encrypted, err := aesCrypto.Encrypt("Your secret message")

// Decrypt
decrypted, err := aesCrypto.Decrypt(encrypted)
```

## Technical Details

### Key Generation
- 256-bit key size
- Secure random number generation
- Key storage in `keys` directory
- Automatic key rotation support

### Encryption Process
1. Key generation/loading
2. IV generation
3. Padding application
4. Block encryption
5. Base64 encoding

### Security Considerations
- Never reuse IVs
- Secure key storage
- Proper key rotation
- Input validation
- Error handling

## Performance
- Block size: 128 bits
- Key size: 256 bits
- Mode: CBC (Cipher Block Chaining)
- Padding: PKCS7

## Examples

### Basic Encryption
```bash
$ cryptolens aes encrypt "Hello, World!"
Encrypted: U2FsdGVkX1+...
```

### Decryption
```bash
$ cryptolens aes decrypt "U2FsdGVkX1+..."
Decrypted: Hello, World!
```

## Best Practices
1. Always use unique IVs
2. Store keys securely
3. Implement proper key rotation
4. Validate input data
5. Handle errors appropriately
6. Use appropriate key sizes
7. Monitor performance

## Troubleshooting

### Common Issues
1. Key not found
   - Check `keys` directory
   - Verify permissions
   - Generate new key

2. Decryption failures
   - Verify IV
   - Check key
   - Validate input format

3. Performance issues
   - Check system resources
   - Verify input size
   - Monitor memory usage

## References
- [NIST AES Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [AES Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [Go Crypto Package](https://pkg.go.dev/crypto/aes) 