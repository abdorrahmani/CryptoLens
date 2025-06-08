# Security Policy

## Supported Versions

We currently support the following versions with security updates:

| Version | Supported          | Security Status |
| ------- | ------------------ | --------------- |
| 1.3.0   | :white_check_mark: | Active          |
| 1.2.1   | :white_check_mark: | Active          |
| 1.2.0   | :white_check_mark: | Active          |
| 1.1.0   | :white_check_mark: | Active          |
| 1.0.0   | :white_check_mark: | Active          |

### Version Support Details

- **1.3.0**: Latest version with all security features
  - Authenticated key exchange
  - X25519 implementation
  - JWT security enhancements
  - MITM prevention measures
  - Enhanced signature verification

- **1.2.1**: Security patches and bug fixes
  - Fixed HMAC and PBKDF error handling
  - Improved parameter validation
  - Enhanced error messages
  - Better security logging

- **1.2.0**: Major security improvements
  - Enhanced key management
  - Improved RSA implementation
  - Better AES key handling
  - Enhanced HMAC security

- **1.1.0**: Security feature additions
  - Added PBKDF2 support
  - Enhanced RSA key generation
  - Improved AES implementation
  - Better key storage security

- **1.0.0**: Initial release
  - Basic encryption features
  - Standard security measures
  - Core cryptographic functions
  - Initial key management

## Reporting a Vulnerability

We take the security of CryptoLens seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to [info@anophel.com].

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information in your report:
- Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

This information will help us triage your report more quickly.

## Security Measures

### Code Security
- All code changes are reviewed for security implications
- Regular security audits are performed
- Dependencies are regularly updated to patch known vulnerabilities
- Static code analysis tools are used to identify potential security issues
- Automated security scanning in CI/CD pipeline
- Regular penetration testing
- Code signing for releases

### Data Security
- Sensitive data is encrypted at rest
- Secure communication protocols are used for data in transit
- Access controls are implemented to protect sensitive information
- Regular backups are performed with encryption
- RSA keys are stored with proper file permissions (0600 for private keys)
- AES keys are stored securely in binary format
- All encryption keys are stored in a dedicated `keys` directory
- Key rotation policies are enforced
- Secure key backup procedures

### Key Management
- RSA key pairs are generated with 2048-bit minimum key size
- Private keys are stored with restricted permissions (0600)
- Public keys are stored with read-only permissions (0644)
- Keys are stored in the project's `keys` directory
- Automatic key generation with secure random number generation
- Key files are stored in PEM format for RSA keys
- Cross-platform key storage compatibility
- Regular key rotation schedule
- Secure key backup and recovery procedures
- Key usage monitoring and logging

### Access Control
- Principle of least privilege is followed
- Multi-factor authentication is required for sensitive operations
- Regular access reviews are conducted
- Session management and timeout policies are enforced
- File system permissions are properly set for key storage
- Role-based access control (RBAC)
- Regular security training for contributors
- Incident response procedures

## Security Updates

Security updates will be released as soon as possible after a vulnerability is confirmed. The process typically includes:

1. Acknowledging the vulnerability report
2. Investigating and confirming the issue
3. Developing a fix
4. Testing the fix
5. Releasing the update
6. Notifying users about the security update
7. Publishing security advisories
8. Updating documentation

## Best Practices

We recommend following these security best practices:

1. Keep your software and dependencies up to date
2. Use strong, unique passwords
3. Enable two-factor authentication when available
4. Regularly review access logs and permissions
5. Report any suspicious activity immediately
6. Keep your encryption keys secure and backed up
7. Use the latest version of CryptoLens
8. Regularly rotate encryption keys
9. Monitor the `keys` directory for unauthorized changes
10. Follow secure coding guidelines
11. Implement proper error handling
12. Use secure communication channels
13. Regular security audits
14. Keep security documentation updated

## Contact

For any security-related questions or concerns, please contact us at [info@anophel.com]. 