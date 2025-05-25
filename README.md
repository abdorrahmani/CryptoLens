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

- **Caesar Cipher**
  - Classical substitution cipher
  - Character-by-character transformation
  - Alphabet shift visualization

- **AES Encryption**
  - Modern symmetric encryption
  - Block cipher operations
  - Key and IV handling

- **SHA-256 Hashing**
  - Cryptographic hash function
  - One-way transformation
  - Hash value generation

### 🎯 Key Features
- Interactive CLI interface
- Real-time step-by-step encryption process visualization
- Detailed explanations of each algorithm
- Binary, hexadecimal, and ASCII representations
- Educational notes and security considerations

## 🚀 Installation

### Using Go Install
```bash
go install github.com/abdorrahmani/cryptolens@latest
```

### From Source
```bash
git clone https://github.com/abdorrahmani/cryptolens.git
cd cryptolens
go build -o cryptolens cmd/cryptolens/main.go
```

## 💻 Usage

Run the program:
```bash
cryptolens
```

Follow the interactive menu to:
1. Choose an encryption method (1-4)
2. Enter your text
3. View the detailed encryption process and explanation
4. See the final result

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
```

## 📁 Project Structure

```
cryptolens/
├── cmd/
│   └── cryptolens/
│       └── main.go           # Main entry point
├── internal/
│   ├── crypto/              # Encryption implementations
│   │   ├── base64.go
│   │   ├── caesar.go
│   │   ├── aes.go
│   │   └── sha256.go
│   ├── cli/                 # CLI interface
│   │   └── menu.go
│   └── utils/              # Utility functions
│       └── visualizer.go
├── assets/                 # Project assets
├── LICENSE
└── README.md
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please make sure to update tests as appropriate.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Go Standard Library for cryptographic functions
- The cryptography community for educational resources
- All contributors who help improve this project

## 📫 Contact

- GitHub: [@abdorrahmani](https://github.com/abdorrahmani)
- Project Link: [https://github.com/abdorrahmani/cryptolens](https://github.com/abdorrahmani/cryptolens) 