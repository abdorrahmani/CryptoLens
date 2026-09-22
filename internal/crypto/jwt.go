package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/abdorrahmani/cryptolens/internal/utils"
	"github.com/golang-jwt/jwt/v5"
)

// JWTProcessor implements the Processor interface for JWT operations
type JWTProcessor struct {
	BaseConfigurableProcessor
	keyManager KeyManager
	algorithm  string
	secretKey  string
}

// NewJWTProcessor creates a new JWT processor
func NewJWTProcessor() *JWTProcessor {
	return &JWTProcessor{
		algorithm: "HS256",
		secretKey: "my-secret-key", // Default secret key
	}
}

// Configure configures the JWT processor with the given settings
func (p *JWTProcessor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}

	if algorithm, ok := config["algorithm"].(string); ok {
		// Validate algorithm
		switch algorithm {
		case "HS256", "RS256", "EdDSA":
			p.algorithm = algorithm
		default:
			return fmt.Errorf("unsupported algorithm: %s", algorithm)
		}
	}

	if keyFile, ok := config["keyFile"].(string); ok {
		p.keyManager = NewFileKeyManager(256, keyFile)
	}

	if secretKey, ok := config["secretKey"].(string); ok {
		p.secretKey = secretKey
	}

	return nil
}

// Process implements the Processor interface for JWT
func (p *JWTProcessor) Process(text string, operation string) (string, []string, error) {
	if operation != OperationEncrypt && operation != OperationDecrypt {
		return "", nil, fmt.Errorf("invalid operation: %s (must be 'encrypt' to sign or 'decrypt' to verify)", operation)
	}

	v := utils.NewVisualizer()
	addJWTIntro(v)

	if operation == OperationEncrypt {
		return p.encodeJWT(text, v)
	}
	return p.decodeJWT(text, v)
}

// addJWTIntro explains what a JWT is and, crucially, that it is signed — not
// encrypted.
func addJWTIntro(v *utils.Visualizer) {
	v.AddStep("📌 What is a JWT?")
	v.AddStep("A JSON Web Token is a compact, URL-safe token that carries CLAIMS (facts about a")
	v.AddStep("user or session) between parties. It is the standard for stateless auth: a server")
	v.AddStep("issues a signed token, the client presents it, and the server trusts it without a")
	v.AddStep("database lookup because the signature proves it was not tampered with.")
	v.AddSeparator()

	v.AddStep("🔢 Anatomy: three Base64URL parts joined by dots")
	v.AddStep("  header . payload . signature")
	v.AddStep("• Header  — which signing algorithm and token type (e.g. {\"alg\":\"HS256\",\"typ\":\"JWT\"})")
	v.AddStep("• Payload — the claims (JSON): who, what, and when it expires")
	v.AddStep("• Signature — signs base64url(header)+\".\"+base64url(payload) so tampering is detectable")
	v.AddStep("Header and payload use Base64URL (menu 1's URL-safe variant), NOT encryption.")
	v.AddNote("⚠️ A JWT is SIGNED, not ENCRYPTED. Anyone can Base64-decode and read the payload —")
	v.AddNote("never put passwords or secrets in it. The signature only proves integrity + origin.")
	v.AddSeparator()
}

// addJWTSecurity covers the JWT-specific pitfalls that cause real breaches.
func addJWTSecurity(v *utils.Visualizer) {
	v.AddSeparator()
	v.AddStep("🔒 JWT security pitfalls")
	v.AddStep("• The 'alg: none' attack: some libraries once accepted a token whose header said")
	v.AddStep("  alg=none and skipped signature checks entirely — instant forgery. Always pin the")
	v.AddStep("  expected algorithm (this tool rejects a token whose alg ≠ the configured one).")
	v.AddStep("  See the JWT None Algorithm attack simulation (menu 12).")
	v.AddStep("• Algorithm-confusion (RS256→HS256): an attacker signs with the PUBLIC RSA key while")
	v.AddStep("  the server verifies HMAC using that same public key as the secret. Pinning alg stops it.")
	v.AddStep("• Always verify exp/nbf and the signature; never trust an unverified payload.")
	v.AddStep("• HS256 secrets must be long and random; short secrets are brute-forceable offline.")
	v.AddNote("The payload is readable by anyone — treat it as public, integrity-protected data.")
}

func (p *JWTProcessor) encodeJWT(text string, v *utils.Visualizer) (string, []string, error) {
	// Parse the input text as JSON for claims
	var claims jwt.MapClaims
	if err := json.Unmarshal([]byte(text), &claims); err != nil {
		return "", nil, fmt.Errorf("invalid JSON claims: %w", err)
	}

	// Add standard claims if not present
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(24 * time.Hour).Unix()
	}

	// Create token
	token := jwt.NewWithClaims(p.getSigningMethod(), claims)

	// Get signing key based on algorithm
	signingKey, err := p.getSigningKey()
	if err != nil {
		return "", nil, err
	}

	// Add educational information based on algorithm
	v.AddStep("JWT Algorithm Information:")
	switch p.algorithm {
	case "HS256":
		v.AddStep("HMAC-SHA256 (Symmetric Key)")
		v.AddStep("Uses a single secret key for both signing and verification")
		v.AddStep("Key length: 256 bits (32 bytes)")
		if key, ok := signingKey.([]byte); ok {
			hash := sha256.Sum256(key)
			v.AddStep(fmt.Sprintf("HMAC Key Digest (SHA-256): %x", hash))
		}
		v.AddStep("Security: Key must be kept secret and shared securely")
		v.AddStep("Use case: Single-party applications or trusted environments")
	case "RS256":
		v.AddStep("RSA-SHA256 (Asymmetric Key)")
		v.AddStep("Uses public/private key pair")
		v.AddStep("Private key for signing, public key for verification")
		if key, ok := signingKey.(*rsa.PrivateKey); ok {
			// Save public key to PEM for educational purposes
			pubBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
			pubPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: pubBytes,
			})
			v.AddStep("Public Key (PEM format):")
			v.AddStep(string(pubPEM))
			v.AddStep("Token Validation:")
			v.AddStep("1. Extract the token header and payload")
			v.AddStep("2. Verify the signature using the public key")
			v.AddStep("3. Check the token expiration and other claims")
		}
		v.AddStep("Security: Private key must be kept secure, public key can be shared")
		v.AddStep("Use case: Multi-party applications, API authentication")
	case "EdDSA":
		v.AddStep("EdDSA with Ed25519 (Asymmetric Key)")
		v.AddStep("Uses Ed25519 curve for digital signatures")
		v.AddStep("Optimized for speed and security")
		v.AddStep("Key length: 32 bytes (256 bits)")
		v.AddStep("Unlike RSA, EdDSA:")
		v.AddStep("- Does not use modulus/exponent math")
		v.AddStep("- Has constant-time operations")
		v.AddStep("- Provides better performance")
		v.AddStep("- Has smaller key sizes")
		v.AddStep("Security: Private key must be kept secure, public key can be shared")
		v.AddStep("Use case: High-performance applications, modern APIs")
	}
	v.AddSeparator()

	// Sign the token
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign token: %w", err)
	}

	// Display token parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", nil, fmt.Errorf("invalid token format")
	}

	// Decode and display header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode header: %w", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", nil, fmt.Errorf("failed to parse header: %w", err)
	}

	v.AddStep("Token Header:")
	v.AddStep(fmt.Sprintf("Algorithm: %s", header["alg"]))
	v.AddStep(fmt.Sprintf("Type: %s", header["typ"]))
	v.AddSeparator()

	// Decode and display claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode claims: %w", err)
	}
	var decodedClaims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &decodedClaims); err != nil {
		return "", nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	v.AddStep("Token Claims:")
	for key, value := range decodedClaims {
		if key == "iat" || key == "exp" {
			if timestamp, ok := value.(float64); ok {
				t := time.Unix(int64(timestamp), 0)
				v.AddStep(fmt.Sprintf("%s: %s", key, t.Format(time.RFC3339)))
			}
		} else {
			v.AddStep(fmt.Sprintf("%s: %v", key, value))
		}
	}
	v.AddSeparator()

	v.AddStep("📈 What actually gets signed")
	v.AddStep("The signing input is the header and payload, Base64URL-encoded and joined by a dot:")
	v.AddStep(fmt.Sprintf("  signing input = %s.%s", parts[0], parts[1]))
	v.AddStep(fmt.Sprintf("  signature = Sign(%s, signing input) = %s", p.algorithm, parts[2]))
	v.AddNote("Change one byte of the header or payload and the signature no longer matches —")
	v.AddNote("that is what makes the claims trustworthy without storing them server-side.")
	v.AddSeparator()

	v.AddStep("Complete JWT (header.payload.signature):")
	v.AddStep(tokenString)

	addJWTSecurity(v)
	return tokenString, v.GetSteps(), nil
}

func (p *JWTProcessor) decodeJWT(tokenString string, v *utils.Visualizer) (string, []string, error) {
	// Split token into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", nil, fmt.Errorf("invalid token format")
	}

	// Decode and display header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode header: %w", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", nil, fmt.Errorf("failed to parse header: %w", err)
	}

	v.AddStep("Token Header:")
	v.AddStep(fmt.Sprintf("Algorithm: %s", header["alg"]))
	v.AddStep(fmt.Sprintf("Type: %s", header["typ"]))
	v.AddSeparator()

	// Decode and display claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode claims: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return "", nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	v.AddStep("Token Claims:")
	for key, value := range claims {
		if key == "iat" || key == "exp" {
			if timestamp, ok := value.(float64); ok {
				t := time.Unix(int64(timestamp), 0)
				v.AddStep(fmt.Sprintf("%s: %s", key, t.Format(time.RFC3339)))
			}
		} else {
			v.AddStep(fmt.Sprintf("%s: %v", key, value))
		}
	}
	v.AddSeparator()

	// Verify signature
	verificationKey, err := p.getVerificationKey()
	if err != nil {
		return "", nil, err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != p.getSigningMethod().Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return verificationKey, nil
	})

	if err != nil {
		v.AddStep("❌ Signature Verification Failed:")
		v.AddStep(fmt.Sprintf("Error: %v", err))
		return "", v.GetSteps(), err
	} else if !token.Valid {
		v.AddStep("❌ Token Invalid")
		return "", v.GetSteps(), fmt.Errorf("token is invalid")
	}

	v.AddStep("✅ Signature Verification Successful")
	v.AddStep(fmt.Sprintf("Recomputed the %s signature over base64url(header).base64url(payload)", p.algorithm))
	v.AddStep("and it matched — the token is authentic and its claims are untampered.")
	v.AddNote("Verification also enforces exp/nbf: an expired or not-yet-valid token is rejected")
	v.AddNote("here even if the signature is correct.")
	v.AddSeparator()
	v.AddStep("Token Signature:")
	v.AddStep(fmt.Sprintf("Algorithm: %s", p.algorithm))
	v.AddStep(fmt.Sprintf("Signature: %s", parts[2]))

	// Return the decoded claims as JSON
	claimsJSON, err = json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	return string(claimsJSON), v.GetSteps(), nil
}

func (p *JWTProcessor) getSigningMethod() jwt.SigningMethod {
	switch p.algorithm {
	case "HS256":
		return jwt.SigningMethodHS256
	case "RS256":
		return jwt.SigningMethodRS256
	case "EdDSA":
		return jwt.SigningMethodEdDSA
	default:
		return jwt.SigningMethodHS256
	}
}

func (p *JWTProcessor) getSigningKey() (interface{}, error) {
	// Ensure keys directory exists
	if err := os.MkdirAll("keys", 0700); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	switch p.algorithm {
	case "HS256":
		if p.keyManager == nil {
			p.keyManager = NewFileKeyManager(256, "keys/jwt_key.bin")
		}
		if err := p.keyManager.LoadOrGenerateKey(); err != nil {
			return nil, fmt.Errorf("failed to load/generate HMAC key: %w", err)
		}
		// Use the secret key if provided, otherwise use the key from keyManager
		if p.secretKey != "" {
			return []byte(p.secretKey), nil
		}
		return p.keyManager.GetKey(), nil

	case "RS256":
		privFile := "keys/jwt_rsa_private.pem"
		pubFile := "keys/jwt_rsa_public.pem"
		// Try to load existing private key
		privData, err := os.ReadFile(privFile)
		if err != nil {
			// Generate new key pair
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
			}
			// Save private key
			privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
			privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
			if err := os.WriteFile(privFile, privPEM, 0600); err != nil {
				return nil, fmt.Errorf("failed to save private key: %w", err)
			}
			// Save public key
			pubBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
			pubPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})
			if err := os.WriteFile(pubFile, pubPEM, 0600); err != nil {
				return nil, fmt.Errorf("failed to save public key: %w", err)
			}
			return privateKey, nil
		}
		// Parse PEM
		block, _ := pem.Decode(privData)
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return nil, fmt.Errorf("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
		}
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		return privateKey, nil

	case "EdDSA":
		privFile := "keys/jwt_ed25519_private.pem"
		pubFile := "keys/jwt_ed25519_public.pem"

		// Try to load existing private key
		privData, err := os.ReadFile(privFile)
		if err != nil {
			// Generate new key pair
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
			}

			// Save private key
			privPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "ED25519 PRIVATE KEY",
				Bytes: privateKey,
			})
			if err := os.WriteFile(privFile, privPEM, 0600); err != nil {
				return nil, fmt.Errorf("failed to save private key: %w", err)
			}

			// Save public key
			pubPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "ED25519 PUBLIC KEY",
				Bytes: publicKey,
			})
			if err := os.WriteFile(pubFile, pubPEM, 0600); err != nil {
				return nil, fmt.Errorf("failed to save public key: %w", err)
			}

			return privateKey, nil
		}

		// Parse PEM
		block, _ := pem.Decode(privData)
		if block == nil || block.Type != "ED25519 PRIVATE KEY" {
			return nil, fmt.Errorf("invalid key: Key must be a PEM encoded Ed25519 private key")
		}

		return ed25519.PrivateKey(block.Bytes), nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", p.algorithm)
	}
}

func (p *JWTProcessor) getVerificationKey() (interface{}, error) {
	switch p.algorithm {
	case "HS256":
		// Use the secret key if provided, otherwise use the key from keyManager
		if p.secretKey != "" {
			return []byte(p.secretKey), nil
		}
		return p.getSigningKey()

	case "RS256":
		pubFile := "keys/jwt_rsa_public.pem"
		pubData, err := os.ReadFile(pubFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read RSA public key: %w", err)
		}
		block, _ := pem.Decode(pubData)
		if block == nil || block.Type != "RSA PUBLIC KEY" {
			return nil, fmt.Errorf("invalid key: Key must be a PEM encoded PKCS1 public key")
		}
		publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		return publicKey, nil

	case "EdDSA":
		pubFile := "keys/jwt_ed25519_public.pem"
		pubData, err := os.ReadFile(pubFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read Ed25519 public key: %w", err)
		}

		block, _ := pem.Decode(pubData)
		if block == nil || block.Type != "ED25519 PUBLIC KEY" {
			return nil, fmt.Errorf("invalid key: Key must be a PEM encoded Ed25519 public key")
		}

		return ed25519.PublicKey(block.Bytes), nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", p.algorithm)
	}
}
