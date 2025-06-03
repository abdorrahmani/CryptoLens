package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// RSAProcessor implements RSA encryption/decryption
type RSAProcessor struct {
	BaseConfigurableProcessor
	keySize    int
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// NewRSAProcessor creates a new RSA processor
func NewRSAProcessor() *RSAProcessor {
	return &RSAProcessor{
		keySize: 2048, // Default to 2048-bit keys
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *RSAProcessor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}

	// Configure key size if provided
	if keySize, ok := config["keySize"].(int); ok {
		switch keySize {
		case 1024, 2048, 4096:
			p.keySize = keySize
		default:
			return fmt.Errorf("invalid key size: %d (must be 1024, 2048, or 4096)", keySize)
		}
	}

	// Get key file paths
	publicKeyFile := "rsa_public.pem"
	privateKeyFile := "rsa_private.pem"
	if pub, ok := config["publicKeyFile"].(string); ok {
		publicKeyFile = pub
	}
	if priv, ok := config["privateKeyFile"].(string); ok {
		privateKeyFile = priv
	}

	// Generate or load keys
	if err := p.loadOrGenerateKeys(publicKeyFile, privateKeyFile); err != nil {
		return fmt.Errorf("failed to load/generate keys: %w", err)
	}

	return nil
}

// loadOrGenerateKeys loads existing keys or generates new ones
func (p *RSAProcessor) loadOrGenerateKeys(publicKeyFile, privateKeyFile string) error {
	// Try to load existing keys
	if p.loadKeys(publicKeyFile, privateKeyFile) == nil {
		return nil
	}

	// Generate new key pair
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
	if err := os.WriteFile(privateKeyFile, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save public key
	publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	if err := os.WriteFile(publicKeyFile, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	p.privateKey = privateKey
	p.publicKey = &privateKey.PublicKey
	return nil
}

// loadKeys attempts to load existing keys
func (p *RSAProcessor) loadKeys(publicKeyFile, privateKeyFile string) error {
	// Load private key
	privateKeyData, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return err
	}
	privateKeyBlock, _ := pem.Decode(privateKeyData)
	if privateKeyBlock == nil {
		return fmt.Errorf("failed to decode private key PEM block")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Load public key
	publicKeyData, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return err
	}
	publicKeyBlock, _ := pem.Decode(publicKeyData)
	if publicKeyBlock == nil {
		return fmt.Errorf("failed to decode public key PEM block")
	}
	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	p.privateKey = privateKey
	p.publicKey = publicKey
	return nil
}

// Process handles RSA encryption/decryption
func (p *RSAProcessor) Process(text string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep("RSA Encryption Process")
	v.AddStep("=============================")
	v.AddNote("RSA is an asymmetric encryption algorithm")
	v.AddNote(fmt.Sprintf("Using %d-bit keys", p.keySize))
	v.AddSeparator()

	// Show key information
	v.AddStep("Key Information:")
	v.AddStep(fmt.Sprintf("Public Key Size: %d bits", p.keySize))
	v.AddStep(fmt.Sprintf("Private Key Size: %d bits", p.keySize))
	v.AddSeparator()

	if operation == OperationDecrypt {
		// Add decryption steps
		v.AddStep("Decryption Process:")
		v.AddStep("1. Base64 decode the input")
		v.AddStep("2. Use private key to decrypt")
		v.AddStep("3. Convert result to text")
		v.AddSeparator()

		// Show input
		v.AddTextStep("Encrypted Input (Base64)", text)
		v.AddArrow()

		// Decode from base64
		data, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return "", nil, fmt.Errorf("invalid base64 string: %w", err)
		}
		v.AddHexStep("Decoded Data", data)
		v.AddArrow()

		// Decrypt
		plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, p.privateKey, data)
		if err != nil {
			return "", nil, fmt.Errorf("failed to decrypt: %w", err)
		}
		v.AddTextStep("Decrypted Text", string(plaintext))

		// Add security notes
		v.AddSeparator()
		v.AddNote("Security Considerations:")
		v.AddNote("1. RSA decryption requires the private key")
		v.AddNote("2. The private key must be kept secure")
		v.AddNote("3. RSA is vulnerable to timing attacks if not properly implemented")
		v.AddNote("4. The security depends on the key size and proper key management")

		return string(plaintext), v.GetSteps(), nil
	}

	// Add encryption steps
	v.AddStep("Encryption Process:")
	v.AddStep("1. Convert text to bytes")
	v.AddStep("2. Use public key to encrypt")
	v.AddStep("3. Base64 encode the result")
	v.AddSeparator()

	// Show input
	v.AddTextStep("Input Text", text)
	v.AddArrow()

	// Show text as bytes
	v.AddHexStep("Text as Bytes", []byte(text))
	v.AddArrow()

	// Encrypt
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, p.publicKey, []byte(text))
	if err != nil {
		return "", nil, fmt.Errorf("failed to encrypt: %w", err)
	}
	v.AddHexStep("Encrypted Data", ciphertext)
	v.AddArrow()

	// Base64 encode the result
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	v.AddTextStep("Base64 Encoded Result", encoded)

	// Add security notes
	v.AddSeparator()
	v.AddNote("Security Considerations:")
	v.AddNote("1. RSA encryption uses the public key")
	v.AddNote("2. The public key can be shared freely")
	v.AddNote("3. RSA has a maximum message size based on key size")
	v.AddNote("4. For large messages, use hybrid encryption (RSA + AES)")

	// Add how it works
	v.AddSeparator()
	v.AddStep("How RSA Works:")
	v.AddStep("1. Generate two large prime numbers (p and q)")
	v.AddStep("2. Calculate n = p * q")
	v.AddStep("3. Calculate φ(n) = (p-1) * (q-1)")
	v.AddStep("4. Choose public exponent e (usually 65537)")
	v.AddStep("5. Calculate private exponent d where (d * e) mod φ(n) = 1")
	v.AddStep("6. Public key is (n, e)")
	v.AddStep("7. Private key is (n, d)")
	v.AddStep("8. Encryption: c = m^e mod n")
	v.AddStep("9. Decryption: m = c^d mod n")

	return encoded, v.GetSteps(), nil
}
