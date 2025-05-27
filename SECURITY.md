# Security Policy

## Supported Versions

We currently support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

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

### Data Security
- Sensitive data is encrypted at rest
- Secure communication protocols are used for data in transit
- Access controls are implemented to protect sensitive information
- Regular backups are performed with encryption

### Access Control
- Principle of least privilege is followed
- Multi-factor authentication is required for sensitive operations
- Regular access reviews are conducted
- Session management and timeout policies are enforced

## Security Updates

Security updates will be released as soon as possible after a vulnerability is confirmed. The process typically includes:

1. Acknowledging the vulnerability report
2. Investigating and confirming the issue
3. Developing a fix
4. Testing the fix
5. Releasing the update
6. Notifying users about the security update

## Best Practices

We recommend following these security best practices:

1. Keep your software and dependencies up to date
2. Use strong, unique passwords
3. Enable two-factor authentication when available
4. Regularly review access logs and permissions
5. Report any suspicious activity immediately

## Contact

For any security-related questions or concerns, please contact us at [info@anophel.com]. 