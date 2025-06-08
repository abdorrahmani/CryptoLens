package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
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
		p.algorithm = algorithm
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
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep("JWT (JSON Web Token) Processing")
	v.AddStep("=============================")
	v.AddNote("JWT is a compact, URL-safe means of representing claims between two parties")
	v.AddNote("A JWT consists of three parts: Header, Payload, and Signature")
	v.AddSeparator()

	if operation == "encrypt" {
		return p.encodeJWT(text, v)
	}
	return p.decodeJWT(text, v)
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

	v.AddStep("Token Signature:")
	v.AddStep(fmt.Sprintf("Algorithm: %s", p.algorithm))
	v.AddStep(fmt.Sprintf("Signature: %s", parts[2]))
	v.AddSeparator()

	v.AddStep("Complete JWT:")
	v.AddStep(tokenString)

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
	} else if token.Valid {
		v.AddStep("✅ Signature Verification Successful")
	} else {
		v.AddStep("❌ Token Invalid")
	}

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
	switch p.algorithm {
	case "HS256":
		if p.keyManager == nil {
			p.keyManager = NewFileKeyManager(256, "jwt_key.bin")
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
		privFile := "jwt_rsa_private.pem"
		pubFile := "jwt_rsa_public.pem"
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
			if err := os.WriteFile(pubFile, pubPEM, 0644); err != nil {
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
		privFile := "jwt_ed25519_private.pem"
		pubFile := "jwt_ed25519_public.pem"

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
			if err := os.WriteFile(pubFile, pubPEM, 0644); err != nil {
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
		pubFile := "jwt_rsa_public.pem"
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
		pubFile := "jwt_ed25519_public.pem"
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
