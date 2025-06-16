# AES (Advanced Encryption Standard) 🔐

## Overview
AES is a symmetric encryption algorithm that uses the same key for both encryption and decryption. CryptoLens implements AES with configurable key sizes (128, 192, or 256 bits), defaulting to AES-256 for maximum security.

## Features
- Configurable key sizes (128/192/256 bits)
- Secure key generation and management
- CBC (Cipher Block Chaining) mode
- PKCS7 padding
- Base64 encoded output
- Detailed step-by-step process visualization
- Secure IV (Initialization Vector) generation
- File-based key storage

## Usage

### Command Line Interface
```bash
# Select AES from the main menu (Option 3)
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

// Create AES processor
aesProcessor := crypto.NewAESProcessor()

// Configure the processor
config := map[string]interface{}{
    "keySize": 256,  // Optional: 128, 192, or 256 bits
    "keyFile": "keys/custom_aes_key.bin",  // Optional: custom key file path
}
aesProcessor.Configure(config)

// Encrypt
encrypted, steps, err := aesProcessor.Process("Your secret message", "encrypt")

// Decrypt
decrypted, steps, err := aesProcessor.Process(encrypted, "decrypt")
```

## Technical Details

### Key Management
- Configurable key sizes (128/192/256 bits)
- Secure random key generation
- File-based key storage in `keys` directory
- Automatic key generation if not exists
- Custom key file path support

### Encryption Process
1. Input validation
2. Random IV generation (16 bytes)
3. PKCS7 padding application
4. AES-CBC encryption
5. IV + ciphertext combination
6. Base64 encoding

### Decryption Process
1. Base64 decoding
2. IV extraction (first 16 bytes)
3. AES-CBC decryption
4. PKCS7 padding removal
5. Result conversion to text

### Security Features
- Unique IV for each encryption
- Secure key storage
- Input validation
- Error handling
- CBC mode for better security
- PKCS7 padding

## Examples

### Encryption Example
```bash
Input: Hi
Output: m3hn40pTG3gP+gyJ1ilJzl4RdsFx+6tGdkOdAzv4oNM=

Processing Steps:
1. Input Text: Hi
2. Generated IV: 9b 78 67 e3 4a 53 1b 78 0f fa 0c 89 d6 29 49 ce
3. Padded Input: 48 69 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e
4. Encrypted Data: 5e 11 76 c1 71 fb ab 46 76 43 9d 03 3b f8 a0 d3
5. Base64 Result: m3hn40pTG3gP+gyJ1ilJzl4RdsFx+6tGdkOdAzv4oNM=
```

### Decryption Example
```bash
Input: m3hn40pTG3gP+gyJ1ilJzl4RdsFx+6tGdkOdAzv4oNM=
Output: Hi

Processing Steps:
1. Base64 Decode
2. Extract IV: 9b 78 67 e3 4a 53 1b 78 0f fa 0c 89 d6 29 49 ce
3. Decrypt Data
4. Remove Padding
5. Final Text: Hi
```

## Implementation Details

### AES Algorithm Steps
1. Key Expansion
   - Generate round keys from main key
   - Number of rounds based on key size (10/12/14 for 128/192/256 bits)

2. Encryption Rounds
   - Initial Round: AddRoundKey
   - Main Rounds:
     - SubBytes: S-box substitution
     - ShiftRows: Row shifting
     - MixColumns: Column mixing
     - AddRoundKey: Key addition
   - Final Round (without MixColumns)

3. CBC Mode Operation
   - Each block XORed with previous ciphertext
   - First block uses IV
   - Provides better security than ECB

## Best Practices
1. Always use unique IVs for each encryption
2. Keep encryption keys secure
3. Use appropriate key sizes (256-bit recommended)
4. Validate all input data
5. Handle errors appropriately
6. Monitor key storage security
7. Regular key rotation
8. Secure key file permissions

## Troubleshooting

### Common Issues
1. Key File Issues
   - Check `keys` directory exists
   - Verify file permissions (0700)
   - Ensure key file is readable

2. Decryption Failures
   - Verify IV is correct
   - Check key matches
   - Validate base64 input
   - Ensure proper padding

3. Configuration Errors
   - Valid key sizes: 128, 192, 256
   - Valid key file paths
   - Proper directory permissions

## References
- [NIST AES Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [AES Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [Go Crypto Package](https://pkg.go.dev/crypto/aes)
- [CBC Mode Security](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC) 