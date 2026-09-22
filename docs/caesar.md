# Caesar Cipher 🔄

## Overview
The Caesar cipher — named after Julius Caesar, who used it for military dispatches — is one of the oldest known encryption techniques. It is a **monoalphabetic substitution cipher**: every letter of the plaintext is replaced by the letter a fixed number of positions further along the alphabet, wrapping from Z back to A. CryptoLens implements it with a configurable shift and a detailed, teaching-oriented visualization that shows the substitution table, the per-letter arithmetic, and a live brute-force attack on the result.

> **Not secure.** With only 25 usable keys, the Caesar cipher is broken instantly by brute force and leaks its key to basic frequency analysis. Use it to learn, never to protect real data.

## Features
- Configurable shift value (default: 3), with automatic normalization of negative and out-of-range shifts
- Full plaintext↔ciphertext **substitution table** for the chosen shift
- Per-character transformation with the exact modular arithmetic
- Built-in **cryptanalysis**: brute-forces all 25 shifts and marks the real key
- ROT13 and zero-shift special cases called out
- Case preservation and non-alphabetic passthrough

## Usage

### Terminal User Interface
```
# Select Caesar Cipher from the main menu
2. Caesar Cipher

# Choose operation
1. Encrypt
2. Decrypt

# Enter text to process
Enter text to process: Your text here
```
The default shift comes from `config.yaml` (`caesar.defaultShift`). Long output scrolls in the result pane (↑/↓); esc/enter returns to the menu.

### Programmatic Usage
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto"

caesar := crypto.NewCaesarProcessor()
caesar.Configure(map[string]interface{}{"shift": 5}) // optional; default is 3

encrypted, steps, err := caesar.Process("Your text", crypto.OperationEncrypt)
decrypted, steps, err := caesar.Process(encrypted, crypto.OperationDecrypt)
```

## How It Works

### The formula
Number each letter `A=0, B=1, … Z=25`. Then:

```
Encrypt:  C = (P + shift) mod 26
Decrypt:  P = (C − shift + 26) mod 26
```

The `+ 26` and `mod 26` keep the result within 0–25 — that is the alphabet wrap-around (Z → A). Decrypting with shift *k* is identical to encrypting with shift `26 − k`.

### The substitution table
A shift fully defines a fixed letter-for-letter mapping. For shift 3:

```
Plain:  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
Cipher: D E F G H I J K L M N O P Q R S T U V W X Y Z A B C
```

Because every `A` becomes `D`, every `E` becomes `H`, and so on, the letter-frequency pattern of the language survives — which is exactly what cryptanalysis exploits.

### Shift normalization
Only the shift *modulo 26* affects the output:
- Shift **27** ≡ shift **1**
- Shift **−3** ≡ shift **23**
- Shift **0** (or 26) leaves text unchanged
- Shift **13** is **ROT13**, its own inverse: applying it twice restores the original, so one operation both encodes and decodes.

## Examples

### Encryption (`Hi!`, shift 3 → `Kl!`)
```
'H' (pos  7) → (7 + 3) mod 26 = 10 → 'K'
'i' (pos  8) → (8 + 3) mod 26 = 11 → 'l'
'!'          → '!'  (non-letter, unchanged)
```

### Decryption via brute force (`KHOOR`, all shifts)
```
shift  1: JGNNQ
shift  2: IFMMP
shift  3: HELLO   ← the real key
shift  4: GDKKN
...
```
The reader can see the attack succeed: only shift 3 produces readable English.

## Security Considerations

| Weakness | Why it matters |
|----------|----------------|
| Tiny key space (25 keys) | Brute force tries every key in microseconds |
| Frequency preserved | `E`, `T`, `A` stand out; the shift is recoverable without brute force |
| No diffusion | A letter always maps to the same output; patterns leak |
| No key management | The same shift is reused for every message |

**Historical progression:** the Vigenère cipher (a Caesar cipher whose shift changes per letter via a keyword) was the next step and resisted simple frequency analysis for centuries. Modern confidentiality uses AES (menu option 3) or ChaCha20-Poly1305 (option 11).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Decryption gives gibberish | Shift doesn't match the one used to encrypt | Use the brute-force output to find the readable shift |
| Output identical to input | Shift is 0 or a multiple of 26 | Choose a shift of 1–25 |
| Numbers/symbols unchanged | By design — only A–Z/a–z are shifted | Expected behavior |

## References
- [Caesar Cipher — Wikipedia](https://en.wikipedia.org/wiki/Caesar_cipher)
- [Substitution Cipher — Wikipedia](https://en.wikipedia.org/wiki/Substitution_cipher)
- [Frequency Analysis — Wikipedia](https://en.wikipedia.org/wiki/Frequency_analysis)
- [ROT13 — Wikipedia](https://en.wikipedia.org/wiki/ROT13)
