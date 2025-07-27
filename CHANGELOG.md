# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2025-07-27

### Added
- **JWT None Algorithm Attack simulation**
  - Demonstrates JWT signature bypass techniques
  - Algorithm manipulation vulnerability demonstration
  - Comprehensive security implications analysis
  - Prevention methods and best practices
  - Real-world examples and historical vulnerabilities
- **ChaCha20-Poly1305 AEAD**
  - Full processor implementation with encryption/decryption
  - Secure key/nonce management and detailed visualization
  - Manual key/nonce entry with strong security warnings
  - Interactive tampering test with step-by-step guide
  - Enhanced documentation with key/nonce/tag details
- **Enhanced Attack Simulations**
  - ECB mode vulnerability demo with pattern leakage detection
  - Nonce reuse attack for AEAD ciphers with XOR demonstration
  - Brute force attack with dictionary attack on weak PBKDF
  - Timing attack with ETA calculation and accuracy stats
- **Benchmark Enhancements**
  - Memory usage tracking and platform information
  - Cross-platform comparison and memory efficiency tips
- **Display & CLI Improvements**
  - Centered ASCII art and welcome messages
  - Enhanced step visualization with section headers and indicators
  - Improved formatting and color standardization

### Changed
- **Key Management Overhaul**
  - All key file paths now use dedicated `keys` directory
  - Automatic creation of `keys` directory across all processors
- **Code Structure Refactoring**
  - Attack processors refactored for modularity and SOLID principles
  - Consistent configuration handling and reusable methods
  - Standardized attack demonstration flow and progress tracking
- **Test Coverage Improvements**
  - 91%+ coverage for config package with robust error handling
  - Comprehensive test suites for ChaCha20-Poly1305 and ECB attack processors

### Fixed
- Handled unchecked error returns in nonce reuse and ChaCha20-Poly1305 tests
- Improved error handling and validation throughout attacks and crypto modules
- Fixed step reordering and formatting issues in display/visualizer

### Documentation
- **New & Enhanced Documentation**
  - JWT None Algorithm Attack: comprehensive vulnerability explanation
  - AES, Base64, Caesar, ChaCha20-Poly1305, DH, HMAC, JWT, PBKDF, RSA, SHA-256, X25519
  - README updates with CLI interface image and attack simulations
  - Detailed CLI usage, encryption examples, and troubleshooting guides

## [1.3.0] - 2025-06-08

### Added
- **Version number display** in welcome message
- **Diffie-Hellman key exchange with authentication**
  - RSA key pairs for Alice and Bob
  - SHA-256 hashing before RSA signing
  - Signature verification for key authenticity
  - AES-GCM encryption demo using derived shared secret
  - Enhanced TLS-like protocol with authentication steps
- **Modern Curve25519 (X25519) key exchange implementation**
  - X25519Processor with Curve25519 key exchange
  - HKDF key derivation and AES-GCM encryption demo
  - Performance comparison with traditional DH
- **JWT support in CLI menu**
  - JWT algorithm selection (HS256, RS256, EdDSA)
  - JWT processor configuration
  - Secret key prompt for HS256 algorithm
- **Enhanced benchmark visualization**
  - Colored ASCII art visualization for benchmarks
  - Visual bar chart for HMAC and PBKDF comparisons
  - Proportional scaling for performance bars
  - Average time display with appropriate units
  - Enhanced readability with aligned algorithm names and coloring

### Fixed
- Unhandled errors in HMAC and PBKDF implementations
- Parameter naming conflicts (max → maxValue, min → minValue)

### Changed
- **Code Refactoring**
  - Split menu.go into modular packages for better maintainability
  - Simplified output formatting and removed tablewriter dependency

### Documentation
- **Comprehensive TLS 1.3 connection flow documentation**
- **Professional ASCII diagram for X25519 key exchange flow**
- **Critical security warnings and best practices**
- Enhanced documentation with:
  - Authentication requirements
  - Constant-time implementation details
  - Certificate management guidelines
  - Monitoring recommendations
  - Common pitfalls
  - Key management requirements
  - Visual legend for key exchange components

### Security
- **MITM prevention details**
- **Enhanced key exchange security with authentication**
- **Improved signature verification process**
- **Proper scalar validation for private keys**

## [1.2.1] - 2025-06-03

### Fixed
- All linter errors across the codebase
- Text input prompt after operation selection in the menu
- Error handling in processor.Process calls
- Improved error messages and context

### Changed
- **Technical Improvements**
  - Enhanced code quality through linter compliance
  - Improved error handling patterns
  - Better user experience with clearer input prompts
  - More robust error propagation

### Documentation
- Updated error handling documentation
- Added comments for linter directives

## [1.2.0] - 2025-06-03

### Added
- **HMAC Implementation**
  - HMAC (Hash-based Message Authentication Code) support
  - Multiple hash algorithm options:
    - SHA-256 (default)
    - SHA-1 (legacy)
    - SHA-512
    - BLAKE2b-256
    - BLAKE2b-512
    - BLAKE3
  - Real-time performance measurements
  - Detailed algorithm information display
  - Step-by-step HMAC process visualization
  - Secure key management
  - Output in both Hex and Base64 formats
- **Password-Based Key Derivation (PBKDF)**
  - PBKDF2 implementation
  - Configurable parameters:
    - Iterations (default: 1000)
    - Salt size (default: 8 bytes)
    - Key length
  - Secure salt generation
  - One-way key derivation
  - Detailed parameter information
  - Security recommendations
  - Base64 encoded output

### Changed
- **Code Refactoring & Architecture**
  - Implemented SOLID principles throughout the codebase
  - Interface Segregation: Created focused interfaces for each component
  - Improved code organization and modularity
  - Enhanced maintainability and testability
  - Reduced code duplication
  - Better separation of concerns
  - Cleaner and more consistent code structure
- **Testing Infrastructure**
  - Added comprehensive test for all crypto processors
  - Unit tests for all new features
  - Test coverage for error cases
- **Security Enhancements**
  - Secure key generation for HMAC
  - Proper salt generation for PBKDF
  - Enhanced password strength analysis
  - Security recommendations in output
  - Detailed security notes in visualization

### Fixed
- Enhanced error messages
- Fixed visualization formatting issues

### Documentation
- Updated README with HMAC and PBKDF features
- Added algorithm comparison guides
- Updated configuration documentation
- Added test coverage documentation
- Improved usage examples

### Dependencies
- Added HMAC dependencies
- Added PBKDF2 dependencies
- Updated test dependencies
- Added benchmark dependencies

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

[1.4.0]: https://github.com/abdorrahmani/cryptolens/releases/tag/v1.4.0
[1.3.0]: https://github.com/abdorrahmani/cryptolens/releases/tag/v1.3.0
[1.2.1]: https://github.com/abdorrahmani/cryptolens/releases/tag/v1.2.1
[1.2.0]: https://github.com/abdorrahmani/cryptolens/releases/tag/v1.2.0
[1.1.0]: https://github.com/abdorrahmani/cryptolens/releases/tag/v1.1.0
[1.0.0]: https://github.com/abdorrahmani/cryptolens/releases/tag/v1.0.0 