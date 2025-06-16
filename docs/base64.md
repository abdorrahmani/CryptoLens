# Base64 Encoding/Decoding 📝

## Overview
Base64 is a binary-to-text encoding scheme that represents binary data in an ASCII string format. CryptoLens implements Base64 encoding and decoding with detailed step-by-step process visualization.

## Features
- Standard Base64 encoding/decoding
- Detailed step-by-step process visualization
- ASCII value representation
- Binary data visualization
- Comprehensive alphabet reference
- Padding handling
- Error handling

## Usage

### Command Line Interface
```bash
# Select Base64 from the main menu (Option 1)
1. Base64 Encoding/Decoding

# Choose operation
1. Encrypt
2. Decrypt

# Enter text to process
Enter text to process: Your text here
```

### Programmatic Usage
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto"

// Create Base64 processor
base64Processor := crypto.NewBase64Processor()

// Configure the processor (no configuration needed for Base64)
config := map[string]interface{}{}
base64Processor.Configure(config)

// Encode
encoded, steps, err := base64Processor.Process("Your text", "encrypt")

// Decode
decoded, steps, err := base64Processor.Process(encoded, "decrypt")
```

## Technical Details

### Base64 Alphabet
- A-Z (65-90): Uppercase letters
- a-z (97-122): Lowercase letters
- 0-9 (48-57): Numbers
- Special characters: + (43), / (47), = (61) for padding

### Encoding Process
1. Input validation
2. Text to bytes conversion
3. 6-bit chunk grouping
4. Base64 character conversion
5. Padding application if needed

### Decoding Process
1. Input validation
2. Padding removal
3. Base64 to 6-bit conversion
4. 8-bit byte grouping
5. Text conversion

### Features
- Detailed ASCII value display
- Binary representation
- Step-by-step visualization
- Comprehensive alphabet reference
- Padding handling
- Error handling

## Examples

### Encoding Example
```bash
Input: Hi
Output: SGk=

Processing Steps:
1. Input Text: Hi
2. ASCII Values:
   'H' = 72
   'i' = 105
3. Binary: 01001000 01101001
4. Base64 Result: SGk=
```

### Decoding Example
```bash
Input: SGk=
Output: Hi

Processing Steps:
1. Base64 Input: SGk=
2. ASCII Values:
   'S' = 83
   'G' = 71
   'k' = 107
   '=' = 61
3. Decoded Binary: 01001000 01101001
4. Decoded Text: Hi
```

## Implementation Details

### Base64 Algorithm Steps
1. Encoding Process
   - Convert text to bytes
   - Group bytes into 6-bit chunks
   - Convert chunks to Base64 characters
   - Add padding if needed

2. Decoding Process
   - Remove padding characters
   - Convert Base64 to 6-bit values
   - Group into 8-bit bytes
   - Convert to text

### Key Characteristics
- Each Base64 character represents 6 bits
- Four Base64 characters = 24 bits = 3 bytes
- Padding (=) used when input length not divisible by 3
- Last group may have 1 or 2 padding characters
- Encoding increases data size by ~33%

## Best Practices
1. Validate input data
2. Handle padding correctly
3. Check for invalid characters
4. Consider data size increase
5. Use appropriate error handling
6. Validate output format

## Troubleshooting

### Common Issues
1. Invalid Characters
   - Check for non-Base64 characters
   - Verify padding format
   - Ensure proper character set

2. Padding Issues
   - Verify padding characters
   - Check input length
   - Validate padding format

3. Decoding Failures
   - Check input format
   - Verify padding
   - Validate character set

## References
- [Base64 Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [RFC 4648](https://tools.ietf.org/html/rfc4648)
- [Go Base64 Package](https://pkg.go.dev/encoding/base64) 