# Caesar Cipher 🔄

## Overview
The Caesar cipher is one of the oldest and simplest encryption techniques, where each letter in the plaintext is shifted by a fixed number of positions down the alphabet. CryptoLens implements the Caesar cipher with configurable shift values and detailed step-by-step process visualization.

## Features
- Configurable shift value (default: 3)
- Detailed step-by-step process visualization
- Character position tracking
- Alphabet reference
- Case preservation
- Non-alphabetic character handling
- Security considerations

## Usage

### Command Line Interface
```bash
# Select Caesar Cipher from the main menu (Option 2)
2. Caesar Cipher

# Choose operation
1. Encrypt
2. Decrypt

# Enter text to process
Enter text to process: Your text here
```

### Programmatic Usage
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto"

// Create Caesar processor
caesarProcessor := crypto.NewCaesarProcessor()

// Configure the processor (optional)
config := map[string]interface{}{
    "shift": 5,  // Optional: custom shift value
}
caesarProcessor.Configure(config)

// Encrypt
encrypted, steps, err := caesarProcessor.Process("Your text", "encrypt")

// Decrypt
decrypted, steps, err := caesarProcessor.Process(encrypted, "decrypt")
```

## Technical Details

### Alphabet Reference
```
A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25
```

### Encryption Process
1. Input validation
2. Character position calculation
3. Shift application
4. Alphabet wrapping
5. Case preservation
6. Non-alphabetic character handling

### Decryption Process
1. Input validation
2. Character position calculation
3. Reverse shift application
4. Alphabet wrapping
5. Case preservation
6. Non-alphabetic character handling

### Features
- Detailed character transformation steps
- Position tracking
- Shift value visualization
- Case-sensitive processing
- Non-alphabetic character preservation

## Examples

### Encryption Example
```bash
Input: hi
Output: kl

Processing Steps:
1. Character 'h':
   Position: 7
   Shift: +3
   New Position: (7 + 3) % 26 = 10
   Result: 'k'

2. Character 'i':
   Position: 8
   Shift: +3
   New Position: (8 + 3) % 26 = 11
   Result: 'l'
```

### Decryption Example
```bash
Input: kl
Output: hi

Processing Steps:
1. Character 'k':
   Position: 10
   Shift: -3
   New Position: (10 - 3 + 26) % 26 = 7
   Result: 'h'

2. Character 'l':
   Position: 11
   Shift: -3
   New Position: (11 - 3 + 26) % 26 = 8
   Result: 'i'
```

## Implementation Details

### Caesar Cipher Algorithm Steps
1. Character Processing
   - Calculate character position in alphabet
   - Apply shift value
   - Handle alphabet wrapping
   - Preserve case
   - Handle non-alphabetic characters

2. Shift Application
   - Encryption: Add shift value
   - Decryption: Subtract shift value
   - Use modulo 26 for wrapping

### Key Characteristics
- Fixed shift value for all characters
- Alphabet wrapping (Z → A)
- Case preservation
- Non-alphabetic characters unchanged
- Simple substitution cipher

## Security Considerations

### Limitations
1. Key Space
   - Only 25 possible keys (shifts)
   - Limited security options

2. Vulnerabilities
   - Frequency analysis
   - Brute force attacks
   - No key management
   - Same shift for all messages

### Best Practices
1. Not recommended for real-world security
2. Use only for educational purposes
3. Consider modern encryption for actual security needs
4. Be aware of the limited key space
5. Understand the vulnerability to frequency analysis

## Troubleshooting

### Common Issues
1. Shift Value Problems
   - Verify shift is between 1-25
   - Check for proper wrapping
   - Validate character positions

2. Character Handling
   - Check case preservation
   - Verify non-alphabetic handling
   - Validate alphabet wrapping

3. Decryption Failures
   - Verify shift value matches encryption
   - Check for proper wrapping
   - Validate character positions

## References
- [Caesar Cipher Wikipedia](https://en.wikipedia.org/wiki/Caesar_cipher)
- [Substitution Cipher](https://en.wikipedia.org/wiki/Substitution_cipher)
- [Cryptography Basics](https://en.wikipedia.org/wiki/Cryptography) 