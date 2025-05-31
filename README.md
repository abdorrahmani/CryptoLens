# CryptoLens 🔐

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/abdorrahmani/cryptolens)](https://goreportcard.com/report/github.com/abdorrahmani/cryptolens)
[![GoDoc](https://godoc.org/github.com/abdorrahmani/cryptolens?status.svg)](https://godoc.org/github.com/abdorrahmani/cryptolens)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

<div align="center">
  <img src="assets/logo.png" alt="CryptoLens Logo" width="200"/>
  
  *Your Interactive Cryptography Learning Tool*
</div>

## 📖 Overview

CryptoLens is an educational CLI tool designed to help users understand various encryption methods and their underlying principles. It provides step-by-step visual explanations of different encryption algorithms and their processes, making cryptography concepts more accessible and easier to understand.

## ✨ Features

### 🔄 Multiple Encryption Methods
- **Base64 Encoding**
  - Binary-to-text encoding
  - Step-by-step visualization of the encoding process
  - ASCII and binary representations
  - Support for both encoding and decoding operations

- **Caesar Cipher**
  - Classical substitution cipher
  - Character-by-character transformation
  - Alphabet shift visualization
  - Customizable shift value
  - Support for both encryption and decryption

- **AES Encryption**
  - Modern symmetric encryption (AES-256)
  - Block cipher operations
  - Secure key and IV handling
  - Support for both encryption and decryption
  - Automatic key generation

- **SHA-256 Hashing**
  - Cryptographic hash function
  - One-way transformation
  - Hash value generation
  - Input validation and error handling

- **RSA Encryption**
  - Asymmetric encryption (RSA-2048)
  - Public/private key pair generation
  - Secure key storage in project directory
  - Support for both encryption and decryption
  - Automatic key pair management
  - Base64 encoded output for encrypted data

### 🎯 Key Features
- Interactive CLI interface with intuitive menu system
- Real-time step-by-step encryption process visualization
- Detailed explanations of each algorithm's principles
- Binary, hexadecimal, and ASCII representations
- Educational notes and security considerations
- Input validation and error handling
- Factory pattern for encryption method selection
- Modular and extensible architecture
- Secure key storage in project directory
- Cross-platform compatibility (Windows, Linux, macOS)

## 🚀 Installation

### Prerequisites
- Go 1.21 or higher
- Git (for installation from source)

### Using Go Install
```bash
go install github.com/abdorrahmani/cryptolens@latest
```

### From Source
```bash
# Clone the repository
git clone https://github.com/abdorrahmani/cryptolens.git

# Navigate to project directory
cd cryptolens

# Build the project
go build -o cryptolens cmd/cryptolens/main.go

# Move the binary to your PATH (optional)
mv cryptolens /usr/local/bin/
```

## 💻 Usage

### Basic Usage
Run the program:
```bash
cryptolens
```

### Interactive Menu
The program will present you with an interactive menu:
1. Choose an encryption method (1-5)
2. Enter your text
3. View the detailed encryption process and explanation
4. See the final result

### Key Storage
- Encryption keys are stored in the `keys` directory in the project root
- RSA keys are stored as PEM files
- AES keys are stored as binary files
- The `keys` directory is automatically created on first run
- Keys are securely stored with appropriate file permissions

### Example Output
```
Encryption Process Visualization:
=================================
Base64 Encoding Process
=====================
Original Text: Hello
    ↓
ASCII Values: 48 65 6c 6c 6f
    ↓
Binary Representation: 01001000 01100101 01101100 01101100 01101111
    ↓
Base64 Encoded: SGVsbG8=
=================================

Decryption Process Visualization:
=================================
Base64 Decoding Process
=====================
Base64 Encoded Text: SGVsbG8=
    ↓
ASCII Values: 48 65 6c 6c 6f
    ↓
Binary Representation: 01001000 01100101 01101100 01101100 01101111
    ↓
Decoded Text: Hello
=================================

RSA Encryption Example:
=================================
Encryption Process
Using RSA key size: 2048 bits
    ↓
Encrypted with public key: [base64 encoded data]
    ↓
Decrypted with private key: Hello
=================================
```

## 📁 Project Structure

```
cryptolens/
├── cmd/
│   └── cryptolens/
│       └── main.go           # Application entry point
├── internal/
│   ├── crypto/              # Encryption implementations
│   │   ├── base64.go        # Base64 encoding/decoding
│   │   ├── caesar.go        # Caesar cipher implementation
│   │   ├── aes.go           # AES encryption/decryption
│   │   ├── sha256.go        # SHA-256 hashing
│   │   ├── rsa.go           # RSA encryption/decryption
│   │   └── processor.go     # Encryption processor interface
│   ├── cli/                 # CLI interface components
│   │   ├── menu.go          # Interactive menu system
│   │   ├── display.go       # Output formatting
│   │   ├── input.go         # User input handling
│   │   ├── interfaces.go    # Interface definitions
│   │   └── factory.go       # Encryption method factory
│   └── utils/              # Utility functions
│       └── visualizer.go    # Process visualization
├── keys/                   # Encryption keys storage
│   ├── rsa_private.pem     # RSA private key
│   ├── rsa_public.pem      # RSA public key
│   └── aes_key.bin         # AES key
├── assets/                 # Project assets
├── LICENSE
└── README.md
```

## 🔧 Development

### Building from Source
```bash
# Clone the repository
git clone https://github.com/abdorrahmani/cryptolens.git

# Navigate to project directory
cd cryptolens

# Build the project
go build -o cryptolens cmd/cryptolens/main.go

# Run tests
go test ./...
```

### Adding New Features
1. Create a new encryption implementation in `internal/crypto/`
2. Implement the required interfaces
3. Add the new method to the factory in `internal/cli/factory.go`
4. Update the menu system in `internal/cli/menu.go`
5. Add appropriate tests

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please make sure to:
- Update tests as appropriate
- Follow the existing code style
- Add documentation for new features
- Update the README if necessary

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Go Standard Library for cryptographic functions
- The cryptography community for educational resources
- All contributors who help improve this project

## 📫 Contact

- GitHub: [@abdorrahmani](https://github.com/abdorrahmani)
- Project Link: [https://github.com/abdorrahmani/cryptolens](https://github.com/abdorrahmani/cryptolens) 