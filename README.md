# CryptoLens 🔐

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/abdorrahmani/cryptolens)](https://goreportcard.com/report/github.com/abdorrahmani/cryptolens)
[![GoDoc](https://godoc.org/github.com/abdorrahmani/cryptolens?status.svg)](https://godoc.org/github.com/abdorrahmani/cryptolens)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

<div align="center">
  <img src="assets/CryptoLens.png" alt="CryptoLens Logo" width="250"/>
  
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

- **HMAC Authentication**
  - Hash-based Message Authentication Code
  - Multiple hash algorithm support:
    - SHA-1 (legacy, not recommended)
    - SHA-256 (widely used)
    - SHA-512 (higher security margin)
    - BLAKE2b-256 (faster alternative)
    - BLAKE2b-512 (high performance)
    - BLAKE3 (latest generation)
  - Real-time performance measurements
  - Detailed algorithm information
  - Step-by-step HMAC process visualization
  - Secure key management
  - Output in both Hex and Base64 formats
  - Built-in benchmarking tool:
    - Compare performance of all HMAC algorithms
    - Customizable number of iterations
    - Sample text input
    - Performance recommendations
    - Detailed timing statistics
    - Percentage-based performance comparison
    - Interactive loading animation

- **Password-Based Key Derivation**
  - Multiple algorithm support:
    - PBKDF2 (Password-Based Key Derivation Function 2)
    - Argon2id (Memory-Hard Function)
    - Scrypt (Memory-Hard Function)
  - Configurable parameters:
    - Iterations/work factor
    - Memory usage (for Argon2id and Scrypt)
    - Threads (for Argon2id)
    - Key length
  - Secure salt generation
  - One-way key derivation
  - Detailed parameter information
  - Security recommendations
  - Base64 encoded output

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
- Performance measurements for HMAC algorithms
- Comprehensive algorithm information display
- Interactive loading animations for long operations

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
1. Choose an encryption method (1-7)
2. Enter your text
3. View the detailed encryption process and explanation
4. See the final result

### Key Storage
- Encryption keys are stored in the `keys` directory in the project root
- RSA keys are stored as PEM files
- AES keys are stored as binary files
- HMAC keys are stored as binary files
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

HMAC Example (SHA-256):
=================================
HMAC Process
Input Text: Hello
    ↓
HMAC Key: [secure key]
    ↓
HMAC Result (Hex): [64 characters]
HMAC Result (Base64): [44 characters]
=================================

PBKDF Example (Argon2id):
=================================
Using argon2id for key derivation
Salt (base64): [random salt]
    ↓
Argon2id Parameters:
- Iterations: 100000
- Memory: 65536 KB
- Threads: 4
- Key Length: 256 bits
    ↓
Derived Key (base64): [derived key]
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
│   │   ├── hmac.go          # HMAC implementation
│   │   ├── pbkdf.go         # PBKDF implementation
│   │   ├── processor.go     # Encryption processor interface
│   │   └── keymanager.go    # Key management
│   ├── cli/                 # CLI interface components
│   │   ├── menu.go          # Interactive menu system
│   │   ├── display.go       # Output formatting
│   │   ├── input.go         # User input handling
│   │   ├── interfaces.go    # Interface definitions
│   │   └── factory.go       # Encryption method factory
│   ├── config/             # Configuration management
│   │   └── config.go       # Configuration handling
│   └── utils/              # Utility functions
│       ├── visualizer.go    # Process visualization
│       └── theme.go         # Color theme management
├── keys/                   # Encryption keys storage
│   ├── rsa_private.pem     # RSA private key
│   ├── rsa_public.pem      # RSA public key
│   ├── aes_key.bin         # AES key
│   └── hmac_key.bin        # HMAC key
├── assets/                 # Project assets
├── config/                 # Configuration files
│   └── config.yaml         # Default configuration
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
6. Update configuration in `config/config.yaml`

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
- BLAKE3 team for their fast and secure hash function
- All contributors who help improve this project

## 📫 Contact

- GitHub: [@abdorrahmani](https://github.com/abdorrahmani)
- Project Link: [https://github.com/abdorrahmani/cryptolens](https://github.com/abdorrahmani/cryptolens) 