package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/abdorrahmani/cryptolens/internal/utils"
	"golang.org/x/crypto/curve25519"
)

// DHProcessor implements the Processor interface for Diffie-Hellman key exchange
type DHProcessor struct {
	keySize    int
	generator  *big.Int
	prime      *big.Int
	keyManager KeyManager
}

// NewDHProcessor creates a new Diffie-Hellman processor
func NewDHProcessor() *DHProcessor {
	return &DHProcessor{
		keySize:    2048,
		generator:  big.NewInt(2),
		keyManager: NewFileKeyManager(2048, "keys/dh_prime.bin"),
	}
}

// Configure configures the DH processor with the given settings
func (p *DHProcessor) Configure(config map[string]interface{}) error {
	if keySize, ok := config["keySize"].(int); ok {
		p.keySize = keySize
	} else if _, ok := config["keySize"].(string); ok {
		return fmt.Errorf("invalid keySize type: expected int, got string")
	}

	if generator, ok := config["generator"].(int); ok {
		p.generator = big.NewInt(int64(generator))
	} else if _, ok := config["generator"].(string); ok {
		return fmt.Errorf("invalid generator type: expected int, got string")
	}

	if primeFile, ok := config["primeFile"].(string); ok {
		// Create a new key manager with the specified file
		p.keyManager = NewFileKeyManager(p.keySize, primeFile)
	}
	return nil
}

// loadOrGeneratePrime loads or generates a prime number
func (p *DHProcessor) loadOrGeneratePrime() (*big.Int, error) {
	if err := p.keyManager.LoadOrGenerateKey(); err != nil {
		return nil, fmt.Errorf("failed to load/generate prime: %w", err)
	}
	return new(big.Int).SetBytes(p.keyManager.GetKey()), nil
}

// generatePrivateKey generates a private key
func (p *DHProcessor) generatePrivateKey() (*big.Int, error) {
	private, err := rand.Int(rand.Reader, p.prime)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	return private, nil
}

// Process implements the Processor interface for Diffie-Hellman
func (p *DHProcessor) Process(_ string, _ string) (string, []string, error) {
	v := utils.NewVisualizer()
	startTime := time.Now()

	// Introduction
	v.AddStep("Diffie-Hellman Key Exchange")
	v.AddStep("=============================")
	v.AddNote("Diffie-Hellman is a method of securely exchanging cryptographic keys")
	v.AddNote("It allows two parties to establish a shared secret over an insecure channel")
	v.AddNote("The security is based on the difficulty of the discrete logarithm problem")
	v.AddSeparator()

	// Step 1: Generate or load prime number
	v.AddStep("Step 1: Prime Number Setup")
	v.AddStep("------------------------")
	prime, err := p.loadOrGeneratePrime()
	if err != nil {
		return "", nil, fmt.Errorf("failed to setup prime: %w", err)
	}
	p.prime = prime

	// Show parameters
	v.AddStep("Parameters:")
	v.AddStep(fmt.Sprintf("Prime (p): %s", p.prime.Text(16)))
	v.AddStep(fmt.Sprintf("Generator (g): %s", p.generator.Text(16)))
	v.AddStep(fmt.Sprintf("Key Size: %d bits", p.keySize))
	v.AddSeparator()

	// Step 2: Generate private keys
	v.AddStep("Step 2: Private Key Generation")
	v.AddStep("----------------------------")
	alicePrivate, err := p.generatePrivateKey()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate Alice's private key: %w", err)
	}
	bobPrivate, err := p.generatePrivateKey()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate Bob's private key: %w", err)
	}
	v.AddStep(fmt.Sprintf("Alice's Private Key: %s", alicePrivate.Text(16)))
	v.AddStep(fmt.Sprintf("Bob's Private Key: %s", bobPrivate.Text(16)))
	v.AddArrow()

	// Step 3: Calculate public keys
	v.AddStep("Step 3: Public Key Calculation")
	v.AddStep("----------------------------")
	alicePublic := new(big.Int).Exp(p.generator, alicePrivate, prime)
	bobPublic := new(big.Int).Exp(p.generator, bobPrivate, prime)
	v.AddStep(fmt.Sprintf("Alice's Public Key: %s", alicePublic.Text(16)))
	v.AddStep(fmt.Sprintf("Bob's Public Key: %s", bobPublic.Text(16)))
	v.AddArrow()

	// Step 4: Key Authentication (Preventing MITM)
	v.AddStep("Step 4: Key Authentication")
	v.AddStep("-------------------------")
	v.AddNote("To prevent MITM attacks, we'll authenticate the public keys using RSA signatures")

	// Generate RSA key pairs for Alice and Bob
	aliceRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate Alice's RSA key: %w", err)
	}
	bobRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate Bob's RSA key: %w", err)
	}

	// Sign public keys with RSA private keys
	alicePublicBytes := alicePublic.Bytes()
	bobPublicBytes := bobPublic.Bytes()

	// Hash the public keys before signing
	aliceHash := sha256.Sum256(alicePublicBytes)
	bobHash := sha256.Sum256(bobPublicBytes)

	aliceSignature, err := rsa.SignPKCS1v15(rand.Reader, aliceRSAKey, crypto.SHA256, aliceHash[:])
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign Alice's public key: %w", err)
	}

	bobSignature, err := rsa.SignPKCS1v15(rand.Reader, bobRSAKey, crypto.SHA256, bobHash[:])
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign Bob's public key: %w", err)
	}

	v.AddStep("RSA Key Pairs Generated:")
	v.AddStep(fmt.Sprintf("Alice's RSA Public Key: %x", aliceRSAKey.PublicKey.N.Bytes()[:16]))
	v.AddStep(fmt.Sprintf("Bob's RSA Public Key: %x", bobRSAKey.PublicKey.N.Bytes()[:16]))
	v.AddStep("Signatures Created:")
	v.AddStep(fmt.Sprintf("Alice's Signature: %x", aliceSignature[:16]))
	v.AddStep(fmt.Sprintf("Bob's Signature: %x", bobSignature[:16]))

	// Verify signatures
	err = rsa.VerifyPKCS1v15(&aliceRSAKey.PublicKey, crypto.SHA256, aliceHash[:], aliceSignature)
	if err != nil {
		return "", nil, fmt.Errorf("failed to verify Alice's signature: %w", err)
	}

	err = rsa.VerifyPKCS1v15(&bobRSAKey.PublicKey, crypto.SHA256, bobHash[:], bobSignature)
	if err != nil {
		return "", nil, fmt.Errorf("failed to verify Bob's signature: %w", err)
	}

	v.AddStep("✅ Signatures Verified Successfully")
	v.AddNote("This proves the public keys are authentic and haven't been tampered with")
	v.AddArrow()

	// Step 5: Calculate shared secrets
	v.AddStep("Step 5: Shared Secret Calculation")
	v.AddStep("-------------------------------")
	aliceShared := new(big.Int).Exp(bobPublic, alicePrivate, prime)
	bobShared := new(big.Int).Exp(alicePublic, bobPrivate, prime)
	v.AddStep(fmt.Sprintf("Alice's Shared Secret: %s", aliceShared.Text(16)))
	v.AddStep(fmt.Sprintf("Bob's Shared Secret: %s", bobShared.Text(16)))
	v.AddArrow()

	// Step 6: Verify shared secrets match
	v.AddStep("Step 6: Shared Secret Verification")
	v.AddStep("--------------------------------")
	if aliceShared.Cmp(bobShared) == 0 {
		v.AddStep("✅ Shared secrets match!")
	} else {
		return "", nil, fmt.Errorf("shared secrets do not match")
	}
	v.AddSeparator()

	// Step 7: Key Derivation Function (KDF)
	v.AddStep("Step 7: Key Derivation")
	v.AddStep("---------------------")
	// Use HKDF to derive a secure key from the shared secret
	hkdf := hkdf.New(sha256.New, aliceShared.Bytes(), []byte("CryptoLens-DH-KDF"), []byte("CryptoLens-DH-Info"))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		return "", nil, fmt.Errorf("failed to derive key: %w", err)
	}
	v.AddStep(fmt.Sprintf("Derived key (using HKDF): %x", derivedKey))
	v.AddSeparator()

	// Step 8: Demonstrate AES Encryption with Shared Secret
	v.AddStep("Step 8: Using Shared Secret for AES Encryption")
	v.AddStep("-------------------------------------------")
	v.AddNote("Now we'll demonstrate how the shared secret can be used for symmetric encryption")

	// Create a sample message
	sampleMessage := "Hello, this is a secret message!"
	v.AddStep(fmt.Sprintf("Original Message: %s", sampleMessage))

	// Create AES cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the message
	ciphertext := gcm.Seal(nonce, nonce, []byte(sampleMessage), nil)
	v.AddStep(fmt.Sprintf("Encrypted Message (Base64): %s", base64.StdEncoding.EncodeToString(ciphertext)))

	// Decrypt the message
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext = ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	v.AddStep(fmt.Sprintf("Decrypted Message: %s", string(plaintext)))
	v.AddArrow()

	// Performance Comparison
	v.AddStep("⚡ Performance Comparison")
	v.AddStep("=======================")
	dhDuration := time.Since(startTime)
	v.AddStep(fmt.Sprintf("Classic DH Execution Time: %v", dhDuration))

	// Measure X25519 performance without running the full process
	x25519Start := time.Now()
	alicePrivateX := make([]byte, 32)
	bobPrivateX := make([]byte, 32)
	if _, err := rand.Read(alicePrivateX); err != nil {
		return "", nil, fmt.Errorf("failed to generate Alice's private key: %w", err)
	}
	if _, err := rand.Read(bobPrivateX); err != nil {
		return "", nil, fmt.Errorf("failed to generate Bob's private key: %w", err)
	}
	alicePrivateX[0] &= 248
	alicePrivateX[31] &= 127
	alicePrivateX[31] |= 64
	bobPrivateX[0] &= 248
	bobPrivateX[31] &= 127
	bobPrivateX[31] |= 64
	alicePublicX, _ := curve25519.X25519(alicePrivateX, curve25519.Basepoint)
	bobPublicX, _ := curve25519.X25519(bobPrivateX, curve25519.Basepoint)
	_, _ = curve25519.X25519(alicePrivateX, bobPublicX)
	_, _ = curve25519.X25519(bobPrivateX, alicePublicX)
	x25519Duration := time.Since(x25519Start)
	v.AddStep(fmt.Sprintf("X25519 Execution Time: %v", x25519Duration))
	v.AddStep(fmt.Sprintf("X25519 is %.2fx faster than Classic DH", float64(dhDuration)/float64(x25519Duration)))
	v.AddSeparator()

	// Explain the process
	v.AddStep("How it works:")
	v.AddStep("1. DH establishes a shared secret between Alice and Bob")
	v.AddStep("2. RSA signatures authenticate the public keys")
	v.AddStep("3. The shared secret is used to derive an AES key")
	v.AddStep("4. The AES key is used to encrypt/decrypt messages")
	v.AddStep("5. Both parties can encrypt/decrypt using the same key")
	v.AddSeparator()

	// Security Considerations
	v.AddStep("🔒 Security Considerations")
	v.AddStep("========================")
	v.AddStep("1. Man-in-the-Middle (MITM) Attack Prevention:")
	v.AddStep("   • RSA signatures authenticate public keys")
	v.AddStep("   • Prevents attackers from substituting their own keys")
	v.AddStep("   • Similar to how TLS uses certificates")
	v.AddSeparator()

	v.AddStep("2. Key Derivation Function (KDF):")
	v.AddStep("   • Raw shared secret should never be used directly")
	v.AddStep("   • KDF provides additional security properties:")
	v.AddStep("     - Key stretching")
	v.AddStep("     - Key separation")
	v.AddStep("     - Key diversification")
	v.AddSeparator()

	v.AddStep("3. Best Practices:")
	v.AddStep("   • Use authenticated key exchange (e.g., TLS)")
	v.AddStep("   • Implement perfect forward secrecy")
	v.AddStep("   • Use strong prime numbers")
	v.AddStep("   • Regularly rotate keys")
	v.AddStep("   • Verify all signatures")
	v.AddSeparator()

	v.AddStep("4. Real-World Usage Examples:")
	v.AddStep("   • TLS/SSL handshake:")
	v.AddStep("     - Server sends certificate (signed public key)")
	v.AddStep("     - Client verifies certificate")
	v.AddStep("     - DH key exchange follows")
	v.AddStep("     - All messages authenticated")
	v.AddStep("   • SSH key exchange")
	v.AddStep("   • Signal Protocol")
	v.AddStep("   • WireGuard VPN")
	v.AddSeparator()

	// Final result
	result := "Successfully demonstrated authenticated Diffie-Hellman key exchange and AES encryption"
	return result, v.GetSteps(), nil
}
