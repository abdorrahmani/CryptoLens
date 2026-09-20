# Base64 Encoding/Decoding 📝

## Overview
Base64 is a binary-to-text encoding scheme that represents arbitrary binary data using 64 printable ASCII characters. It exists so binary data can pass safely through text-only channels — email headers, URLs, JSON, and JWTs. CryptoLens implements standard Base64 (RFC 4648) encoding and decoding with a detailed, step-by-step visualization that shows the actual bit-level transformation on your input.

> **Base64 is not security.** It is not encryption, hashing, or compression. Anyone can decode it, and it makes data ~33% larger. Use it for transport, never to protect sensitive data.

## Features
- Standard Base64 encoding/decoding (RFC 4648)
- Index-based alphabet reference (the value that actually drives encoding)
- A worked, bit-by-bit example on the first block of your input
- Full binary representation of the input/output
- Per-input padding analysis (why you get `=`, `==`, or none)
- Clear reverse walkthrough for decoding
- Base64URL explanation (the JWT-safe variant)
- Error handling for invalid input

## Usage

### Terminal User Interface
```
# Select Base64 from the main menu
1. Base64 Encoding/Decoding

# Choose operation
1. Encrypt   (encode)
2. Decrypt   (decode)

# Enter text to process
Enter text to process: Your text here
```

The step-by-step output renders in a scrollable pane — use ↑/↓ to scroll long output, and esc/enter to return to the menu.

### Programmatic Usage
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto"

base64Processor := crypto.NewBase64Processor()

// Encode
encoded, steps, err := base64Processor.Process("Your text", crypto.OperationEncrypt)

// Decode
decoded, steps, err := base64Processor.Process(encoded, crypto.OperationDecrypt)
```
`steps` is the ordered slice of explanation lines the TUI renders; `encoded`/`decoded` is the result.

## How Base64 Works

### The core idea: 3 bytes ↔ 4 characters
3 bytes are 24 bits, and 24 bits divide evenly into **4 groups of 6 bits**. Each 6-bit group is a number from **0 to 63** that selects one character from the Base64 alphabet. So every 3 input bytes become exactly 4 output characters.

### The alphabet is indexed, not ASCII
A 6-bit group's value is an **index** into the alphabet, not the character's ASCII code. This is the single most common point of confusion, so the visualization shows indices:

| Index range | Characters |
|-------------|------------|
| 0–25        | `A`–`Z`    |
| 26–51       | `a`–`z`    |
| 52–61       | `0`–`9`    |
| 62, 63      | `+`, `/`   |
| padding     | `=`        |

For example, index `0` is `A` — whereas `A` in ASCII is `65`. The encoding uses the index.

### Padding
Padding fills the final block so the output length is always a multiple of 4. It depends on `input_length mod 3`:

| `len mod 3` | Final block | Output | Padding |
|-------------|-------------|--------|---------|
| 0           | 3 bytes     | 4 chars | none    |
| 2           | 2 bytes     | 3 chars | `=`     |
| 1           | 1 byte      | 2 chars | `==`    |

## Worked Examples

### Encoding `Hi` → `SGk=`
```
Character:    H          i
Decimal:      72         105
8-bit byte:   01001000   01101001

Concatenate into 16 bits:
  0100100001101001
Re-slice into 6-bit groups (2 zero bits appended to complete the last group):
  010010 000110 100100
Group value:  18   6    36
Base64 char:  S    G    k

Only 2 bytes of data in the final block → 1 '=' appended.
Result: SGk=
```

### Decoding `SGk=` → `Hi`
```
Character:      S        G        k        (padding '=' dropped first)
Index (0-63):   18       6        36
6-bit value:    010010   000110   100100

Concatenate into 18 bits:
  010010000110100100
Re-slice into 8-bit bytes (2 leftover padding bits discarded):
  01001000 01101001
Byte value:     72       105
Character:      H        i

Result: Hi
```

## Base64URL (the JWT variant)
Standard Base64 uses `+` and `/`, which have special meaning in URLs. **Base64URL** swaps them for `-` and `_` and often drops the `=` padding, making the output safe to place directly in URLs and HTTP tokens. This is the encoding used for the header and payload segments of a JWT — see the [JWT documentation](jwt.md).

## Error Handling
Decoding validates the input against the Base64 alphabet and padding rules. Invalid input (illegal characters, wrong padding) returns an error of the form:
```
invalid base64 string: illegal base64 data at input byte N
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| "illegal base64 data" | Non-alphabet character (e.g. a space, `-`, or `_`) | Check for whitespace; if the string came from a URL/JWT it may be Base64URL, not standard Base64 |
| Decodes to garbage | Input was not Base64 to begin with | Verify the source actually produced Base64 |
| Length not a multiple of 4 | Padding was stripped | Re-add `=` padding, or use a Base64URL decoder |

## References
- [RFC 4648 — The Base16, Base32, and Base64 Data Encodings](https://tools.ietf.org/html/rfc4648)
- [Base64 — Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [Go `encoding/base64` package](https://pkg.go.dev/encoding/base64)
