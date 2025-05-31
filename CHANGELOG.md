# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-05-31

### Added
- RSA encryption/decryption support
  - RSA-2048 asymmetric encryption
  - Public/private key pair generation
  - Secure key storage in project directory
  - Base64 encoded output for encrypted data
- Secure key storage system
  - Dedicated `keys` directory in project root
  - Automatic directory creation
  - Proper file permissions
  - Cross-platform compatibility
- Updated configuration system
  - RSA key size configuration
  - Key file path management
  - Improved error handling

### Changed
- Updated menu system to include RSA encryption
- Improved key storage security
- Enhanced documentation
- Updated project structure

### Fixed
- Key storage path issues
- Cross-platform compatibility for key storage
- File permission handling

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

[1.1.0]: https://github.com/abdorrahmani/cryptolens/releases/tag/v1.1.0
[1.0.0]: https://github.com/abdorrahmani/cryptolens/releases/tag/v1.0.0 