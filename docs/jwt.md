# JWT (JSON Web Token) 🪪

## Overview
JWT (JSON Web Token) is a compact, URL-safe means of representing claims between two parties. CryptoLens implements JWT with support for multiple algorithms: HS256 (HMAC with SHA-256), RS256 (RSA with SHA-256), and EdDSA (Ed25519). JWTs are widely used for authentication and secure information exchange.

## Features
- Multiple algorithm support: HS256, RS256, EdDSA
- Secure key generation and management
- File-based key storage for asymmetric keys
- Step-by-step process visualization
- Educational breakdown of JWT structure
- Signature verification and claim validation

## Usage

### Command Line Interface
```bash
# Select JWT from the main menu (Option 10)
10. JWT (JSON Web Token)

# Choose operation
1. Encrypt
2. Decrypt

# Select JWT Algorithm
1. HS256 (HMAC with SHA-256)
2. RS256 (RSA with SHA-256)
3. EdDSA (Ed25519)

# Enter text to process (for encryption, provide JSON claims)
Enter text to process: {"id":1,"username":"anophel"}
```

### Programmatic Usage
```go
import "github.com/abdorrahmani/cryptolens/internal/crypto"

// Create JWT processor
jwtProcessor := crypto.NewJWTProcessor()

// Configure the processor
config := map[string]interface{}{
    "algorithm": "RS256", // Optional: HS256, RS256, EdDSA
    "keyFile": "keys/custom_jwt_key.bin", // Optional: for HS256 custom key file
    "secretKey": "my-secret-key", // Optional: for HS256
}
jwtProcessor.Configure(config)

// Encrypt (create JWT)
result, steps, err := jwtProcessor.Process("{\"id\":1,\"username\":\"anophel\"}", "encrypt")

// Decrypt (verify and decode JWT)
decoded, steps, err := jwtProcessor.Process(result, "decrypt")
```

## Technical Details

### Key Management
- **HS256**: Uses a 256-bit secret key (default or user-provided)
- **RS256**: Uses RSA 2048-bit key pair (private for signing, public for verification)
- **EdDSA**: Uses Ed25519 key pair (private for signing, public for verification)
- Keys are stored in the `keys` directory and generated automatically if not present
- Custom key file support for HS256

### JWT Structure
A JWT consists of three parts:
1. **Header**: Specifies the algorithm and token type
2. **Payload**: Contains the claims (data)
3. **Signature**: Ensures integrity and authenticity

Format: `header.payload.signature` (Base64URL encoded)

### Encryption (JWT Creation) Process
1. Parse input JSON as claims
2. Add standard claims (`iat`, `exp`) if missing
3. Create JWT header with selected algorithm
4. Sign the token using the appropriate key
5. Output the JWT string and detailed steps

### Decryption (JWT Verification) Process
1. Parse JWT string into header, payload, and signature
2. Decode and display header and claims
3. Verify the signature using the correct key
4. Validate standard claims (e.g., expiration)
5. Output the decoded claims and verification steps

### Supported Algorithms
- **HS256**: HMAC with SHA-256 (symmetric)
- **RS256**: RSA with SHA-256 (asymmetric)
- **EdDSA**: Ed25519 (asymmetric, modern)

## Examples

### JWT Creation Example (RS256)
```bash
Input: {"id":1,"username":"anophel"}
Output: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTE2MzgyNzcsImlhdCI6MTc1MTU1MTg3NywiaWQiOjEsInVzZXJuYW1lIjoiYW5vcGhlbCJ9.X-2C4a825HpA2hB7zhsef8S87YpYKosOKoHeMnLBK9Wyj41NCEwnEWlnYOzxI9WHu58DfIP0p0DFrxTkbe65RfIH4F7gZfWaY0eqSUz2dDnql1vZ2uOAVumXEquNZZEyPttDmRFMcj-Tw6zcqzRYiO98joF1XW-_UPFpK_736zb_Mu9F8pIcGoCsi7w-MkEB_RQiEl5QsW4BBPrJ0Ce_z8T2DZQcYvFGYN5IJl8NKbAVol6lrXpVpeT76KjVX4Phrqui32LWWkW4B1MngJO_7NKzrWpaF_bAtn-VpyAsYjK9cZuC0QiAktx98W8cwK5oVEfOkKBL7eR19juc5gvoew

Processing Steps:
JWT (JSON Web Token) Processing
=============================
Note:  JWT is a compact, URL-safe means of representing claims between two parties
Note:  A JWT consists of three parts: Header, Payload, and Signature
----------------------------------------
JWT Algorithm Information:
RSA-SHA256 (Asymmetric Key)
Uses public/private key pair
Private key for signing, public key for verification
Public Key (PEM format):
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA1WV8ctNKXasokiTeT5GPxVNarYJu4lUjSDglKIkWf+poODYA5y6X
PCWuBk+o0wZbOgA1TnnPqKRtLI0d73dKE6itGUodxFmoDQvh9rQ3QSUHRBk9ipc9
TT/BagJo9wPGtH9cyS9fcqsN07OVVZaYUMpUj2k8X0yh+7VIzNgHSgBJFrnWm302
kn/lDjw0b9UiasebEIgwnbBeGM5hvbJoAmxonh/JV+BphBegwhBWu8icin7suZDS
9OzDTqqWrKQlFBEtD418T6zTUrfrZlF0PkqtoIxPA7N+T78AC65MGmfqwm9pXMFp
+8XeHJffHGScUEE6BwPTWkbIWt/Qb7TrewIDAQAB
-----END RSA PUBLIC KEY-----

Token Validation:
1. Extract the token header and payload
2. Verify the signature using the public key
3. Check the token expiration and other claims
Security:  Private key must be kept secure, public key can be shared
Use case:  Multi-party applications, API authentication
----------------------------------------
Token Header:
Algorithm:  RS256
Type:  JWT
----------------------------------------
Token Claims:
exp:  2025-07-04T17:41:17+03:30
iat:  2025-07-03T17:41:17+03:30
id:  1
username:  anophel
----------------------------------------
Token Signature:
Algorithm:  RS256
Signature:  X-2C4a825HpA2hB7zhsef8S87YpYKosOKoHeMnLBK9Wyj41NCEwnEWlnYOzxI9WHu58DfIP0p0DFrxTkbe65RfIH4F7gZfWaY0eqSUz2dDnql1vZ2uOAVumXEquNZZEyPttDmRFMcj-Tw6zcqzRYiO98joF1XW-_UPFpK_736zb_Mu9F8pIcGoCsi7w-MkEB_RQiEl5QsW4BBPrJ0Ce_z8T2DZQcYvFGYN5IJl8NKbAVol6lrXpVpeT76KjVX4Phrqui32LWWkW4B1MngJO_7NKzrWpaF_bAtn-VpyAsYjK9cZuC0QiAktx98W8cwK5oVEfOkKBL7eR19juc5gvoew
----------------------------------------
Complete JWT:
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTE2MzgyNzcsImlhdCI6MTc1MTU1MTg3NywiaWQiOjEsInVzZXJuYW1lIjoiYW5vcGhlbCJ9.X-2C4a825HpA2hB7zhsef8S87YpYKosOKoHeMnLBK9Wyj41NCEwnEWlnYOzxI9WHu58DfIP0p0DFrxTkbe65RfIH4F7gZfWaY0eqSUz2dDnql1vZ2uOAVumXEquNZZEyPttDmRFMcj-Tw6zcqzRYiO98joF1XW-_UPFpK_736zb_Mu9F8pIcGoCsi7w-MkEB_RQiEl5QsW4BBPrJ0Ce_z8T2DZQcYvFGYN5IJl8NKbAVol6lrXpVpeT76KjVX4Phrqui32LWWkW4B1MngJO_7NKzrWpaF_bAtn-VpyAsYjK9cZuC0QiAktx98W8cwK5oVEfOkKBL7eR19juc5gvoew
```

### JWT Verification Example (RS256)
```bash
Input: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTE2MzgyNzcsImlhdCI6MTc1MTU1MTg3NywiaWQiOjEsInVzZXJuYW1lIjoiYW5vcGhlbCJ9.X-2C4a825HpA2hB7zhsef8S87YpYKosOKoHeMnLBK9Wyj41NCEwnEWlnYOzxI9WHu58DfIP0p0DFrxTkbe65RfIH4F7gZfWaY0eqSUz2dDnql1vZ2uOAVumXEquNZZEyPttDmRFMcj-Tw6zcqzRYiO98joF1XW-_UPFpK_736zb_Mu9F8pIcGoCsi7w-MkEB_RQiEl5QsW4BBPrJ0Ce_z8T2DZQcYvFGYN5IJl8NKbAVol6lrXpVpeT76KjVX4Phrqui32LWWkW4B1MngJO_7NKzrWpaF_bAtn-VpyAsYjK9cZuC0QiAktx98W8cwK5oVEfOkKBL7eR19juc5gvoew
Output:
{
  "exp": 1751638277,
  "iat": 1751551877,
  "id": 1,
  "username": "anophel"
}

Processing Steps:
JWT (JSON Web Token) Processing
=============================
Note:  JWT is a compact, URL-safe means of representing claims between two parties
Note:  A JWT consists of three parts: Header, Payload, and Signature
----------------------------------------
Token Header:
Algorithm:  RS256
Type:  JWT
----------------------------------------
Token Claims:
exp:  2025-07-04T17:41:17+03:30
iat:  2025-07-03T17:41:17+03:30
id:  1
username:  anophel
----------------------------------------
✅ Signature Verification Successful
----------------------------------------
Token Signature:
Algorithm:  RS256
Signature:  X-2C4a825HpA2hB7zhsef8S87YpYKosOKoHeMnLBK9Wyj41NCEwnEWlnYOzxI9WHu58DfIP0p0DFrxTkbe65RfIH4F7gZfWaY0eqSUz2dDnql1vZ2uOAVumXEquNZZEyPttDmRFMcj-Tw6zcqzRYiO98joF1XW-_UPFpK_736zb_Mu9F8pIcGoCsi7w-MkEB_RQiEl5QsW4BBPrJ0Ce_z8T2DZQcYvFGYN5IJl8NKbAVol6lrXpVpeT76KjVX4Phrqui32LWWkW4B1MngJO_7NKzrWpaF_bAtn-VpyAsYjK9cZuC0QiAktx98W8cwK5oVEfOkKBL7eR19juc5gvoew
```

## Implementation Details

### JWT Algorithm Steps
1. Prepare claims (add `iat`, `exp` if missing)
2. Create header with selected algorithm
3. Base64URL encode header and payload
4. Sign the header and payload with the selected algorithm/key
5. Concatenate header, payload, and signature
6. For verification: decode, verify signature, and validate claims

### Security Features
- Private keys are securely stored and never exposed
- Public keys can be shared for verification (RS256, EdDSA)
- HS256 secret key must be kept confidential
- Automatic key generation and file-based storage
- Signature verification ensures token integrity

## Best Practices
1. Use strong, random keys
2. Keep private keys and secrets secure
3. Choose the appropriate algorithm for your use case
4. Validate all input data and claims
5. Handle errors appropriately
6. Monitor key storage security
7. Use file permissions to protect key files
8. Rotate keys periodically

## Troubleshooting

### Common Issues
1. **Key File Issues**
   - Check `keys` directory exists
   - Verify file permissions (0700)
   - Ensure key files are readable
2. **Signature Verification Fails**
   - Ensure correct algorithm and key are used
   - Check token expiration (`exp` claim)
   - Validate input JWT format
3. **Configuration Errors**
   - Valid algorithms: HS256, RS256, EdDSA
   - Valid key file paths
   - Proper directory permissions

## References
- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [JWT Wikipedia](https://en.wikipedia.org/wiki/JSON_Web_Token)
- [Go golang-jwt/jwt Package](https://pkg.go.dev/github.com/golang-jwt/jwt/v5) 