# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-05-26

### Added
- Initial release of CryptoLens
- Base64 encoding/decoding with step-by-step visualization
- Caesar Cipher encryption/decryption with customizable shift
- AES-256 encryption/decryption in CBC mode
- SHA-256 hashing functionality
- Interactive CLI interface with color-coded output
- Configuration system with YAML support
- Real-time process visualization
- Educational notes and security considerations
- Factory pattern for encryption method selection
- Modular and extensible architecture

### Features
- **Base64**
  - Binary-to-text encoding/decoding
  - ASCII and binary representations
  - Customizable padding character

- **Caesar Cipher**
  - Classical substitution cipher
  - Character-by-character transformation
  - Alphabet shift visualization
  - Configurable shift value

- **AES**
  - AES-256 in CBC mode
  - PKCS7 padding
  - Secure key and IV handling
  - Automatic key generation

- **SHA-256**
  - Cryptographic hash function
  - 256-bit output
  - One-way transformation

### Technical
- Go 1.21+ support
- Cross-platform builds (Linux, Windows, macOS)
- AMD64 and ARM64 architecture support
- Automated release process with GoReleaser
- GitHub Actions integration
- Comprehensive test coverage
- Code linting with golangci-lint

[1.0.0]: https://github.com/abdorrahmani/cryptolens/releases/tag/v1.0.0 