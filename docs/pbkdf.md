# PBKDF (Password-Based Key Derivation) 🔑

## Overview
PBKDF (Password-Based Key Derivation Function) is used to derive strong cryptographic keys from user passwords. CryptoLens implements multiple PBKDF algorithms: PBKDF2 (with SHA-256), Argon2id, and Scrypt. These algorithms are designed to make brute-force and dictionary attacks computationally expensive, providing enhanced security for password-based systems.

## Features
- Multiple algorithm support: PBKDF2 (SHA-256), Argon2id, Scrypt
- Configurable iterations and salt size
- Secure random salt generation
- Step-by-step process visualization
- Password strength analysis and warnings
- Benchmarking for all supported algorithms

## Usage

### Command Line Interface
```bash
# Select PBKDF from the main menu (Option 7)
7. PBKDF (Password-Based Key Derivation)

# Choose PBKDF Algorithm
1. PBKDF2 (Password-Based Key Derivation Function 2)
2. Argon2id (Memory-Hard Function)
3. Scrypt (Memory-Hard Function)
4. Run Benchmark on All

# Enter text to process (the password)
Enter text to process: Anophel.com
```

### Programmatic Usage
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto"

// Create PBKDF2 processor
pbkdf2Processor := crypto.NewPBKDFProcessor()

// Configure the processor
config := map[string]interface{}{
    "iterations": 100000, // Optional: number of iterations
    "saltSize": 16,       // Optional: salt size in bytes
    "keyFile": "keys/custom_pbkdf_key.bin", // Optional: custom key file path
}
pbkdf2Processor.Configure(config)

// Derive key
result, steps, err := pbkdf2Processor.Process("Anophel.com", "derive")
```

## Technical Details

### Key Derivation Algorithms
- **PBKDF2 (SHA-256)**: Iteratively applies SHA-256 to password and salt
- **Argon2id**: Memory-hard function, resistant to GPU/ASIC attacks
- **Scrypt**: Memory-hard function, designed to be computationally and memory expensive

### Key Management
- Secure random salt generation (default 16 bytes)
- Configurable iteration count (default 100,000 for PBKDF2)
- Derived key is 256 bits (32 bytes) by default
- Salt and derived key should be stored; never store the original password

### PBKDF2 Process Steps
1. Analyze password strength and warn if weak
2. Generate a random salt
3. Perform the configured number of iterations using SHA-256
4. Derive a 256-bit key
5. Base64 encode the result for safe transmission

### Security Features
- Unique salt for each password
- High iteration count to slow down brute-force attacks
- Password strength analysis and recommendations
- Designed to be computationally intensive

## Examples

### PBKDF2 Key Derivation Example
```bash
Input: Anophel.com
Output: 4x8Ce5+3OVAco0pXeavMkVgsniSCh8w7oD3zjGTgsrU=

Processing Steps:
PBKDF2-SHA256 Process
=============================
Note:  PBKDF2 (Password-Based Key Derivation Function 2) is used for key stretching
Note:  Using SHA-256 as the underlying hash function
----------------------------------------
Using PBKDF2-SHA256 for key derivation
⚠️  Warning: Password could be stronger
    Recommendation:  Use at least 12 characters
Generated salt (16 bytes)
Performed 100000 iterations
Derived key in 19.0139ms
Base64 encoded the result for safe transmission
Note:  PBKDF2 is designed to be computationally intensive to prevent brute-force attacks
----------------------------------------
How PBKDF2 Works:
1. Password and Salt:
   - Password is the input text
   - Salt is a random value to prevent rainbow table attacks
2. Iterations:
   - Performs 100000 iterations of SHA-256
   - Each iteration makes brute-force attacks more expensive
3. Key Derivation:
   - Combines password, salt, and iteration count
   - Produces a 256-bit (32-byte) key
4. Output:
   - The derived key is base64 encoded for safe transmission
----------------------------------------
Note:  Security Considerations:
Note:  1. The salt must be unique for each password
Note:  2. More iterations make the process slower but more secure
Note:  3. The derived key should be used as input to other cryptographic operations
Note:  4. Never store the original password, only the derived key and salt
Note:  5. The salt can be stored alongside the derived key
```

### Argon2id Key Derivation Example
```bash
Input: Anophel.com
Output: 3KOnqLT4PJG/rdhghamSrrL8Nqhu/rYj3JR01rChr9I=

Processing Steps:
Argon2id Process
=============================
Note:  Argon2id is a memory-hard password hashing function
Note:  Designed to resist GPU and ASIC attacks
----------------------------------------
Using Argon2id for key derivation
⚠️  Warning: Password could be stronger
    Recommendation:  Use at least 12 characters
Generated salt (16 bytes)
Performed 1 iteration (default)
Used 64MB memory (default)
Derived key in 36.2ms
Base64 encoded the result for safe transmission
Note:  Argon2id is recommended for new applications
----------------------------------------
How Argon2id Works:
1. Password and Salt:
   - Password is the input text
   - Salt is a random value to prevent rainbow table attacks
2. Memory and Iterations:
   - Uses significant memory to slow down attackers
   - Each iteration increases computational cost
3. Key Derivation:
   - Combines password, salt, memory, and iteration count
   - Produces a 256-bit (32-byte) key
4. Output:
   - The derived key is base64 encoded for safe transmission
----------------------------------------
Note:  Security Considerations:
Note:  1. Use high memory and iteration settings for best security
Note:  2. The salt must be unique for each password
Note:  3. Never store the original password, only the derived key and salt
```

### Scrypt Key Derivation Example
```bash
Input: Anophel.com
Output: 3KOnqLT4PJG/rdhghamSrrL8Nqhu/rYj3JR01rChr9I=

Processing Steps:
Scrypt Process
=============================
Note:  Scrypt is a memory-hard password hashing function
Note:  Designed to be expensive for hardware attacks
----------------------------------------
Using Scrypt for key derivation
⚠️  Warning: Password could be stronger
    Recommendation:  Use at least 12 characters
Generated salt (16 bytes)
N=16384, r=8, p=1 (default parameters)
Derived key in 266ms
Base64 encoded the result for safe transmission
Note:  Scrypt is suitable for applications requiring high security
----------------------------------------
How Scrypt Works:
1. Password and Salt:
   - Password is the input text
   - Salt is a random value to prevent rainbow table attacks
2. Parameters:
   - N (CPU/memory cost), r (block size), p (parallelization)
   - High values increase security
3. Key Derivation:
   - Combines password, salt, and parameters
   - Produces a 256-bit (32-byte) key
4. Output:
   - The derived key is base64 encoded for safe transmission
----------------------------------------
Note:  Security Considerations:
Note:  1. Use high N, r, p values for best security
Note:  2. The salt must be unique for each password
Note:  3. Never store the original password, only the derived key and salt
```

## Benchmarking

CryptoLens provides a benchmarking tool to compare the performance of PBKDF2, Argon2id, and Scrypt on your system.

### Example Benchmark Output
```bash
PBKDF Benchmark
=============================
Note:  This benchmark will test all available PBKDF algorithms
Note:  The test will use a sample text and run multiple iterations
----------------------------------------
Running benchmark with 100 iterations...
Sample text:  Anophel
Estimated time:  31.7s
----------------------------------------
Platform Information:
OS:  windows
Architecture:  amd64
CPU Cores:  16
Go Version:  go1.24.3
----------------------------------------
Benchmark Results:
1. PBKDF2:
   • Time:  100 ops in 1695ms → avg: 16.96ms (baseline)
   • Memory:  0.01 MB per operation
   • Allocations:  7334.2 per operation
2. SCRYPT:
   • Time:  100 ops in 1707ms → avg: 17.08ms (+0.7%)
   • Memory:  0.01 MB per operation
   • Allocations:  7328.6 per operation
3. ARGON2ID:
   • Time:  100 ops in 1715ms → avg: 17.16ms (+1.2%)
   • Memory:  0.01 MB per operation
   • Allocations:  7329.4 per operation
----------------------------------------
Benchmark Visual Comparison:
PBKDF2     █████████████████████████████████████████████████ (17.0ms)
SCRYPT     █████████████████████████████████████████████████ (17.1ms)
ARGON2ID   ██████████████████████████████████████████████████ (17.2ms)
----------------------------------------
Recommendations:
🚀 Fastest Algorithm:  PBKDF2
🛡️ Most Secure:  Argon2id (Memory-hard function with better resistance to GPU attacks)
💾 Most Memory Efficient:  PBKDF2
----------------------------------------
Performance Comparison:
• PBKDF2 is 0.7% faster than Argon2id
• PBKDF2 is 1.2% faster than Scrypt
```

## Best Practices
1. Use strong, unique passwords
2. Always use a unique, random salt for each password
3. Choose high iteration/memory settings for best security
4. Never store the original password; only store the salt and derived key
5. Regularly review and update PBKDF parameters as hardware improves
6. Benchmark on your own hardware to select optimal parameters
7. Protect key and salt storage with proper file permissions

## Troubleshooting

### Common Issues
1. **Weak Passwords**
   - Use at least 12 characters, including letters, numbers, and symbols
   - Avoid common passwords and patterns
2. **Performance**
   - High iteration/memory settings may slow down processing
   - Benchmark to find a balance between security and usability
3. **Salt Management**
   - Always generate a new salt for each password
   - Store the salt securely alongside the derived key
4. **Configuration Errors**
   - Ensure valid parameter values for each algorithm
   - Check file permissions for key/salt storage

## References
- [PBKDF2 RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018)
- [Argon2 RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106)
- [Scrypt Paper](https://www.tarsnap.com/scrypt/scrypt.pdf)
- [Go x/crypto/pbkdf2](https://pkg.go.dev/golang.org/x/crypto/pbkdf2)
- [Go x/crypto/argon2](https://pkg.go.dev/golang.org/x/crypto/argon2)
- [Go x/crypto/scrypt](https://pkg.go.dev/golang.org/x/crypto/scrypt) 