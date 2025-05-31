package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// RSAProcessor implements RSA encryption/decryption
type RSAProcessor struct {
	keySize        int
	publicKeyFile  string
	privateKeyFile string
	publicKey      *rsa.PublicKey
	privateKey     *rsa.PrivateKey
}

// NewRSAProcessor creates a new RSA processor
func NewRSAProcessor() *RSAProcessor {
	return &RSAProcessor{
		keySize:        2048,
		publicKeyFile:  "rsa_public.pem",
		privateKeyFile: "rsa_private.pem",
	}
}

// Configure sets up the RSA processor with the given configuration
func (p *RSAProcessor) Configure(config map[string]interface{}) error {
	if keySize, ok := config["keySize"].(int); ok {
		// Ensure minimum key size of 2048 bits for security
		if keySize < 2048 {
			keySize = 2048
		}
		p.keySize = keySize
	}
	if publicKeyFile, ok := config["publicKeyFile"].(string); ok {
		p.publicKeyFile = publicKeyFile
	}
	if privateKeyFile, ok := config["privateKeyFile"].(string); ok {
		p.privateKeyFile = privateKeyFile
	}

	// Generate or load keys
	if err := p.ensureKeys(); err != nil {
		return fmt.Errorf("failed to ensure RSA keys: %w", err)
	}

	return nil
}

// ensureKeys generates or loads RSA keys
func (p *RSAProcessor) ensureKeys() error {
	// Ensure minimum key size
	if p.keySize < 2048 {
		p.keySize = 2048
	}

	// Create directory for keys if it doesn't exist
	keysDir := filepath.Dir(p.privateKeyFile)
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Try to load existing keys
	if err := p.loadKeys(); err == nil {
		return nil
	}

	// Generate new keys if loading failed
	privateKey, err := rsa.GenerateKey(rand.Reader, p.keySize)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	// Save private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err := os.WriteFile(p.privateKeyFile, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save public key
	publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	if err := os.WriteFile(p.publicKeyFile, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	p.privateKey = privateKey
	p.publicKey = &privateKey.PublicKey
	return nil
}

// loadKeys loads existing RSA keys from files
func (p *RSAProcessor) loadKeys() error {
	// Load private key
	privateKeyPEM, err := os.ReadFile(p.privateKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Load public key
	publicKeyPEM, err := os.ReadFile(p.publicKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ = pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode public key PEM")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	p.privateKey = privateKey
	p.publicKey = publicKey
	return nil
}

// Process handles RSA encryption/decryption
func (p *RSAProcessor) Process(input string, operation string) (string, []string, error) {
	var steps []string

	if p.privateKey == nil || p.publicKey == nil {
		return "", nil, fmt.Errorf("RSA keys not initialized")
	}

	steps = append(steps, fmt.Sprintf("Using RSA key size: %d bits", p.keySize))

	if operation == OperationEncrypt {
		// Encrypt with public key
		encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, p.publicKey, []byte(input))
		if err != nil {
			return "", nil, fmt.Errorf("failed to encrypt: %w", err)
		}

		// Convert to base64 for display
		encoded := base64.StdEncoding.EncodeToString(encrypted)
		steps = append(steps, fmt.Sprintf("Encrypted with public key: %s", encoded))

		// Decrypt with private key to verify
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, p.privateKey, encrypted)
		if err != nil {
			return "", nil, fmt.Errorf("failed to decrypt: %w", err)
		}

		steps = append(steps, fmt.Sprintf("Decrypted with private key: %s", string(decrypted)))
		return encoded, steps, nil
	} else {
		// Decrypt with private key
		decoded, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			return "", nil, fmt.Errorf("failed to decode base64: %w", err)
		}

		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, p.privateKey, decoded)
		if err != nil {
			return "", nil, fmt.Errorf("failed to decrypt: %w", err)
		}

		steps = append(steps, fmt.Sprintf("Decrypted with private key: %s", string(decrypted)))
		return string(decrypted), steps, nil
	}
}
