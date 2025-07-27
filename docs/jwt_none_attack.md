# JWT None Algorithm Attack

## Overview

The JWT None Algorithm Attack is a critical security vulnerability that allows attackers to bypass JWT signature verification by exploiting the "none" algorithm. This attack can lead to complete authentication bypass and privilege escalation.

## How JWT Works

JWT (JSON Web Token) consists of three parts:
1. **Header** - Contains metadata about the token (algorithm, type)
2. **Payload** - Contains the claims (user data, permissions, etc.)
3. **Signature** - Cryptographic signature to verify authenticity

The header specifies which algorithm was used to sign the token, such as:
- `HS256` (HMAC-SHA256) - Symmetric key signing
- `RS256` (RSA-SHA256) - Asymmetric key signing
- `EdDSA` (Edwards-curve Digital Signature Algorithm)

## The Vulnerability

The JWT specification includes a special algorithm called "none" which indicates that no signature is present. This was intended for use cases where the token is transmitted over secure channels (like HTTPS) and doesn't require cryptographic verification.

However, if a JWT library is improperly configured, it may:
1. Trust the algorithm specified in the token header
2. Skip signature verification when the algorithm is "none"
3. Accept tokens without any cryptographic validation

## Attack Process

### Step 1: Obtain a Valid JWT Token
The attacker first needs to obtain a valid JWT token, typically by:
- Logging into the application normally
- Intercepting a token in transit
- Finding a token in logs or error messages

### Step 2: Analyze the Token
The attacker decodes the JWT to understand its structure:
```
Header: {"alg":"HS256","typ":"JWT"}
Payload: {"sub":"1234567890","name":"John Doe","role":"user","iat":1516239022,"exp":1516242622}
Signature: [HMAC-SHA256 signature]
```

### Step 3: Create Malicious Token
The attacker creates a new token with:
1. **Modified Header**: Changes algorithm from "HS256" to "none"
2. **Same Payload**: Keeps the original claims (or modifies them)
3. **Empty Signature**: Removes the signature entirely

```
Malicious Header: {"alg":"none","typ":"JWT"}
Payload: {"sub":"1234567890","name":"John Doe","role":"user","iat":1516239022,"exp":1516242622}
Signature: (empty)
```

### Step 4: Submit the Malicious Token
The attacker submits the malicious token to the application. If the JWT library is vulnerable:
1. It reads the "alg" field from the header
2. Sees "none" and skips signature verification
3. Accepts the token as valid
4. Grants access based on the claims

## Real-World Impact

### Privilege Escalation
An attacker can modify the "role" claim to gain elevated privileges:
```json
{"role":"user"} → {"role":"admin"}
```

### Session Hijacking
The attacker can impersonate any user by modifying the "sub" (subject) claim:
```json
{"sub":"1234567890"} → {"sub":"admin_user_id"}
```

### Token Forgery
The attacker can create completely new tokens with any claims without knowing the secret key.

## Vulnerable Code Examples

### ❌ Vulnerable Implementation
```python
# Python - PyJWT (vulnerable configuration)
import jwt

# This is vulnerable - it trusts the algorithm from the token
token_data = jwt.decode(token, options={"verify_signature": False})
```

```javascript
// JavaScript - jsonwebtoken (vulnerable configuration)
const jwt = require('jsonwebtoken');

// This is vulnerable - no algorithm whitelist
const decoded = jwt.verify(token, secret);
```

### ✅ Secure Implementation
```python
# Python - PyJWT (secure configuration)
import jwt

# Explicitly specify allowed algorithms
token_data = jwt.decode(token, secret, algorithms=["HS256", "RS256"])
```

```javascript
// JavaScript - jsonwebtoken (secure configuration)
const jwt = require('jsonwebtoken');

// Explicitly specify allowed algorithms
const decoded = jwt.verify(token, secret, { algorithms: ['HS256', 'RS256'] });
```

## Detection and Prevention

### Detection
1. **Code Review**: Check JWT library configuration
2. **Penetration Testing**: Attempt to use "none" algorithm tokens
3. **Log Analysis**: Monitor for unusual JWT patterns
4. **Security Scanning**: Use automated tools to detect vulnerabilities

### Prevention

#### 1. Algorithm Whitelisting
Always explicitly specify which algorithms are allowed:
```python
# Only allow specific algorithms
jwt.decode(token, secret, algorithms=["HS256", "RS256"])
```

#### 2. Never Trust the Header
Never rely on the algorithm specified in the token header:
```python
# ❌ Don't do this
algorithm = token_header.get("alg")
jwt.decode(token, secret, algorithms=[algorithm])

# ✅ Do this instead
jwt.decode(token, secret, algorithms=["HS256", "RS256"])
```

#### 3. Use Secure JWT Libraries
Choose libraries with secure defaults:
- **Python**: PyJWT with explicit algorithm specification
- **JavaScript**: jsonwebtoken with algorithm whitelist
- **Go**: golang-jwt/jwt with proper validation
- **Java**: jjwt with algorithm constraints

#### 4. Implement Additional Validation
```python
# Additional security checks
def validate_jwt(token):
    # Check algorithm whitelist
    if token_header["alg"] not in ["HS256", "RS256"]:
        raise SecurityException("Invalid algorithm")
    
    # Check token expiration
    if token_payload["exp"] < time.time():
        raise SecurityException("Token expired")
    
    # Check issuer
    if token_payload["iss"] != "trusted_issuer":
        raise SecurityException("Invalid issuer")
```

#### 5. Use Asymmetric Algorithms
Prefer asymmetric algorithms (RS256, EdDSA) over symmetric ones:
- Private key for signing (server-side only)
- Public key for verification (can be shared)
- Better key management
- More secure for multi-party applications

#### 6. Implement Token Blacklisting
```python
# Blacklist compromised tokens
def is_token_blacklisted(token_id):
    return token_id in blacklisted_tokens

def validate_token(token):
    if is_token_blacklisted(token["jti"]):
        raise SecurityException("Token blacklisted")
```

## Testing the Attack

### Manual Testing
1. Obtain a valid JWT token
2. Decode the token to see its structure
3. Modify the header to use "none" algorithm
4. Remove the signature
5. Submit the modified token
6. Check if the application accepts it

### Automated Testing
```python
import jwt
import base64
import json

def test_none_algorithm_attack(original_token):
    # Split the token
    header_b64, payload_b64, signature = original_token.split('.')
    
    # Decode header
    header = json.loads(base64.b64decode(header_b64 + '=='))
    
    # Create malicious header
    malicious_header = {"alg": "none", "typ": "JWT"}
    malicious_header_b64 = base64.b64encode(json.dumps(malicious_header).encode()).decode().rstrip('=')
    
    # Create malicious token
    malicious_token = f"{malicious_header_b64}.{payload_b64}."
    
    return malicious_token
```

## Historical Examples

### 1. Auth0 Vulnerability (2015)
Auth0's JWT library had a vulnerability where it would accept "none" algorithm tokens if the secret was not provided.

### 2. Multiple JWT Libraries (2016-2018)
Several JWT libraries were found to be vulnerable to this attack:
- PyJWT (Python)
- jsonwebtoken (Node.js)
- jose4j (Java)
- go-jose (Go)

### 3. Real-World Exploits
- **GitHub**: Used to bypass authentication in some applications
- **APIs**: Used to gain unauthorized access to REST APIs
- **Web Applications**: Used for session hijacking

## Security Best Practices Summary

1. **Always whitelist allowed algorithms**
2. **Never trust the algorithm from the token header**
3. **Use secure JWT libraries with proper defaults**
4. **Implement additional validation checks**
5. **Use asymmetric algorithms when possible**
6. **Set short token expiration times**
7. **Implement token blacklisting**
8. **Monitor for suspicious token patterns**
9. **Regular security audits and penetration testing**
10. **Keep JWT libraries updated**

## References

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [JWT Security Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
- [JWT None Algorithm Attack](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html) 