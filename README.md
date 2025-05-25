# CryptoLens

CryptoLens is an educational CLI tool designed to help users understand various encryption methods and their underlying principles. It provides step-by-step explanations of different encryption algorithms and their processes.

## Features

- Multiple encryption methods:
  - Base64 (encoding)
  - Caesar Cipher (classical encryption)
  - AES (symmetric encryption)
  - SHA-256 (one-way hashing)
- Interactive CLI interface
- Step-by-step encryption process visualization
- Detailed explanations of each algorithm

## Installation

```bash
go install github.com/abdorrahmani/cryptolens@latest
```

## Usage

Run the program:

```bash
cryptolens
```

Follow the interactive menu to:
1. Choose an encryption method
2. Enter your text
3. View the encryption process and explanation

## Project Structure

- `cmd/cryptolens/main.go` - Main entry point
- `internal/` - Core package implementations
  - `crypto/` - Encryption implementations
  - `cli/` - CLI interface
  - `utils/` - Utility functions

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License 