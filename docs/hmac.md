# HMAC (Hash-based Message Authentication Code) 🔑

## Overview
HMAC is a cryptographic construction that combines a hash function with a secret key to provide both data integrity and authentication. CryptoLens implements HMAC with support for multiple hash algorithms, including SHA-1, SHA-256, SHA-512, BLAKE2b-256, BLAKE2b-512, and BLAKE3. HMAC is a one-way function: the original message cannot be recovered from the HMAC value.

## Features
- Multiple hash algorithm support (SHA-1, SHA-256, SHA-512, BLAKE2b-256, BLAKE2b-512, BLAKE3)
- Secure key generation and management
- File-based key storage
- Step-by-step process visualization
- Hexadecimal and Base64 output
- Benchmarking for all supported algorithms

## Usage

### Command Line Interface
```bash
# Select HMAC from the main menu (Option 6)
6. HMAC (Hash-based Message Authentication)

# Choose hash algorithm
1. SHA-1
2. SHA-256
3. SHA-512
4. BLAKE2b-256
5. BLAKE2b-512
6. BLAKE3
7. Run Benchmark

# Enter text to process
Enter text to process: Your message here
```

### Programmatic Usage
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto"

// Create HMAC processor
hmacProcessor := crypto.NewHMACProcessor()

// Configure the processor
config := map[string]interface{}{
    "hashAlgorithm": "sha256", // Optional: sha1, sha256, sha512, blake2b-256, blake2b-512, blake3
    "keyFile": "keys/custom_hmac_key.bin", // Optional: custom key file path
}
hmacProcessor.Configure(config)

// Generate HMAC
result, steps, err := hmacProcessor.Process("Your message here", "encrypt")
```

## Technical Details

### Key Management
- 256-bit key by default (for SHA-256)
- Secure random key generation
- File-based key storage in `keys` directory
- Automatic key generation if not exists
- Custom key file path support

### HMAC Process
1. Input validation
2. Key preparation (hash or pad to block size)
3. Inner and outer padding creation (XOR with 0x36 and 0x5c)
4. HMAC calculation using the selected hash algorithm
5. Output in hex and Base64

### Supported Hash Algorithms
- SHA-1: 160-bit (20 bytes) output (not recommended for security)
- SHA-256: 256-bit (32 bytes) output
- SHA-512: 512-bit (64 bytes) output
- BLAKE2b-256: 256-bit (32 bytes) output
- BLAKE2b-512: 512-bit (64 bytes) output
- BLAKE3: 256-bit (32 bytes) output by default

## Examples

### HMAC Example
```bash
Input: hi
Output:
Hex: fd4ec365c9180e8a31dbaa99043e38f0ac4e328f50375edb210e5583e0d982d3
Base64: /U7DZckYDoox26qZBD448KxOMo9QN17bIQ5Vg+DZgtM=

Processing Steps:
HMAC-sha256 Process
=============================
Note:  HMAC (Hash-based Message Authentication Code) is a specific type of message authentication code
Note:  It involves a cryptographic hash function and a secret cryptographic key
Note:  Using sha256 as the underlying hash function
Note:  Note: HMAC is a one-way function - the original message cannot be recovered from the HMAC value
----------------------------------------
Original Text:  hi
    ↓↓↓
HMAC Key:  15 45 17 52 1d f5 8a ca c4 03 4a 63 dd 5c 64 91 67 5b df 59 23 6c 5e c5 b8 18 44 ee 74 69 15 68
    ↓↓↓
Key Preparation:
1. If key length > block size, hash it
2. If key length < block size, pad with zeros
Block size for sha256:  64 bytes
Padded Key:  15 45 17 52 1d f5 8a ca c4 03 4a 63 dd 5c 64 91 67 5b df 59 23 6c 5e c5 b8 18 44 ee 74 69 15 68 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    ↓↓↓
Inner Padding Creation:
1. Create a block-sized buffer filled with 0x36
Inner Padding Buffer:  36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36
2. XOR the padded key with the inner padding
Inner Key (Key XOR 0x36):  23 73 21 64 2b c3 bc fc f2 35 7c 55 eb 6a 52 a7 51 6d e9 6f 15 5a 68 f3 8e 2e 72 d8 42 5f 23 5e 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36
    ↓↓↓
Outer Padding Creation:
1. Create a block-sized buffer filled with 0x5c
Outer Padding Buffer:  5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c
2. XOR the padded key with the outer padding
Outer Key (Key XOR 0x5c):  49 19 4b 0e 41 a9 d6 96 98 5f 16 3f 81 00 38 cd 3b 07 83 05 7f 30 02 99 e4 44 18 b2 28 35 49 34 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c
    ↓↓↓
Note:  Current algorithm (sha256) execution time: 0.504µs (avg of 1000 iterations)
HMAC Calculation:
1. Hash(innerKey || message)
2. Hash(outerKey || result)
    ↓↓↓
HMAC Result (Raw Bytes):  fd 4e c3 65 c9 18 0e 8a 31 db aa 99 04 3e 38 f0 ac 4e 32 8f 50 37 5e db 21 0e 55 83 e0 d9 82 d3
    ↓↓↓
HMAC Result (Hex) - 32 bytes:  fd4ec365c9180e8a31dbaa99043e38f0ac4e328f50375edb210e5583e0d982d3
HMAC Result (Base64) - 32 bytes:  /U7DZckYDoox26qZBD448KxOMo9QN17bIQ5Vg+DZgtM=
Hash Algorithm Information:
Selected Algorithm:  sha256
Block Size:  64 bytes
Output Size:  32 bytes

Available Algorithms:
  sha1
- SHA-1:  160-bit (20 bytes) output
- Note:  SHA-1 is considered cryptographically broken and should not be used for security-critical applications

→ sha256 (Currently Selected)
- SHA-256:  256-bit (32 bytes) output
- Part of the SHA-2 family
- Widely used in security applications and protocols

  sha512
- SHA-512:  512-bit (64 bytes) output
- Part of the SHA-2 family
- Provides higher security margin than SHA-256

  blake2b-256
- BLAKE2b-256:  256-bit (32 bytes) output
- Faster than SHA-256 on 64-bit platforms
- Used in many cryptocurrencies and security applications

  blake2b-512
- BLAKE2b-512:  512-bit (64 bytes) output
- Faster than SHA-512 on 64-bit platforms
- Used in many cryptocurrencies and security applications

  blake3
- BLAKE3:  256-bit (32 bytes) output by default
- Successor to BLAKE2, offering even better performance
- Features parallel processing and tree hashing
- Used in modern security applications and protocols

----------------------------------------
How HMAC Works:
1. Prepare the key (if needed, pad or hash it)
2. Create an inner padding by XORing the key with 0x36
3. Create an outer padding by XORing the key with 0x5c
4. Hash the inner padding concatenated with the message
5. Hash the outer padding concatenated with the result from step 4
6. The final hash is the HMAC value
----------------------------------------
Note:  Security Considerations:
Note:  1. HMAC provides both data integrity and authentication
Note:  2. The key must be kept secret and secure
Note:  3. HMAC is resistant to length extension attacks
Note:  4. The security depends on the underlying hash function
Note:  5. HMAC is a one-way function - the original message cannot be recovered
Note:  6. Using sha256 as the underlying hash function
```

### Benchmark Example
```bash
# Run benchmark for all algorithms
Select Hash Algorithm: 7
Enter sample text for benchmarking (default: 'Hello, World!'): hello, world!
Enter number of iterations (default: 10000): 1000

Result:

Processing Steps:
HMAC Benchmark
=============================
Note:  This benchmark will test all available HMAC algorithms
Note:  The test will use a sample text and run multiple iterations
----------------------------------------
Running benchmark with 1000 iterations...
Sample text:  hello, world!
----------------------------------------
Platform Information:
OS:  windows
Architecture:  amd64
CPU Cores:  16
Go Version:  go1.24.3
----------------------------------------
Benchmark Results:
1. HMAC-SHA256:
   • Time:  1000 ops in 296ms → avg: 296.9µs (baseline)
   • Memory:  18014398509479.54 KB per operation
   • Allocations:  86436.0 per operation
2. HMAC-SHA1:
   • Time:  1000 ops in 424ms → avg: 424.6µs (+43.0%)
   • Memory:  2.45 KB per operation
   • Allocations:  77345.2 per operation
3. HMAC-BLAKE3:
   • Time:  1000 ops in 496ms → avg: 496.9µs (+67.4%)
   • Memory:  18014398509481.71 KB per operation
   • Allocations:  139847.5 per operation
4. HMAC-SHA512:
   • Time:  1000 ops in 717ms → avg: 717.8µs (+141.8%)
   • Memory:  18014398509481.55 KB per operation
   • Allocations:  146193.6 per operation
5. HMAC-BLAKE2B-256:
   • Time:  1000 ops in 818ms → avg: 818.1µs (+175.6%)
   • Memory:  0.98 KB per operation
   • Allocations:  87420.0 per operation
6. HMAC-BLAKE2B-512:
   • Time:  1000 ops in 865ms → avg: 865.8µs (+191.6%)
   • Memory:  18014398509481.31 KB per operation
   • Allocations:  146626.5 per operation
----------------------------------------
Benchmark Visual Comparison:
HMAC-SHA256     █████████████████ (296.9µs)
HMAC-SHA1       ████████████████████████ (424.6µs)
HMAC-BLAKE3     ████████████████████████████ (496.9µs)
HMAC-SHA512     █████████████████████████████████████████ (717.8µs)
HMAC-BLAKE2B-256 ███████████████████████████████████████████████ (818.1µs)
HMAC-BLAKE2B-512 ██████████████████████████████████████████████████ (865.8µs)
----------------------------------------
Recommendations:
🚀 Fastest Algorithm:  SHA256
🛡️ Best Security (Balanced):  BLAKE2b-512 or SHA-256
💾 Most Memory Efficient:  SHA256
```

## Implementation Details

### HMAC Algorithm Steps
1. Prepare the key (hash or pad to block size)
2. Create inner padding (XOR key with 0x36)
3. Create outer padding (XOR key with 0x5c)
4. Hash inner padding concatenated with the message
5. Hash outer padding concatenated with the result from step 4
6. Output the final hash (HMAC value)

### Security Features
- Key must be kept secret and secure
- Resistant to length extension attacks
- Security depends on the underlying hash function
- HMAC is a one-way function

## Best Practices
1. Use strong, random keys
2. Keep keys secret and secure
3. Choose a secure hash algorithm (avoid SHA-1)
4. Rotate keys periodically
5. Validate all input data
6. Handle errors appropriately
7. Monitor key storage security
8. Use file permissions to protect key files

## Troubleshooting

### Common Issues
1. Key File Issues
   - Check `keys` directory exists
   - Verify file permissions (0700)
   - Ensure key file is readable
2. Output Issues
   - Check selected hash algorithm
   - Validate input text
   - Ensure correct key is used
3. Configuration Errors
   - Valid hash algorithms: sha1, sha256, sha512, blake2b-256, blake2b-512, blake3
   - Valid key file paths
   - Proper directory permissions

## References
- [RFC 2104: HMAC](https://datatracker.ietf.org/doc/html/rfc2104)
- [HMAC Wikipedia](https://en.wikipedia.org/wiki/HMAC)
- [Go crypto/hmac Package](https://pkg.go.dev/crypto/hmac)
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3)
- [BLAKE2b](https://blake2.net/) 