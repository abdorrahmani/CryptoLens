package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// X25519Processor implements the Processor interface for X25519 key exchange
type X25519Processor struct {
	keyManager KeyManager
}

// NewX25519Processor creates a new X25519 processor
func NewX25519Processor() *X25519Processor {
	return &X25519Processor{
		keyManager: NewFileKeyManager(32, "x25519_private.bin"), // 32 bytes for X25519 private key
	}
}

// Configure configures the X25519 processor with the given settings
func (p *X25519Processor) Configure(config map[string]interface{}) error {
	if privateKeyFile, ok := config["privateKeyFile"].(string); ok {
		p.keyManager = NewFileKeyManager(32, privateKeyFile)
	}
	return nil
}

// Process implements the Processor interface for X25519
func (p *X25519Processor) Process(_ string, _ string) (string, []string, error) {
	v := utils.NewVisualizer()
	startTime := time.Now()

	// Introduction
	v.AddStep("X25519 Key Exchange (Curve25519)")
	v.AddStep("=============================")
	v.AddNote("X25519 is a modern key exchange protocol based on Curve25519")
	v.AddNote("It's designed to be more secure and efficient than classic Diffie-Hellman")
	v.AddNote("Widely used in modern protocols like TLS 1.3, Signal, and WireGuard")
	v.AddSeparator()

	// Tutorial Section
	v.AddStep("📚 Tutorial: Why X25519 Replaced Classic Diffie-Hellman")
	v.AddStep("=================================================")
	v.AddStep("1. Enhanced Security:")
	v.AddStep("   • Resistant to side-channel attacks")
	v.AddStep("   • Better protection against timing attacks")
	v.AddStep("   • Constant-time operations by design")
	v.AddStep("   • No known practical attacks against Curve25519")
	v.AddStep("   • Smaller attack surface due to simpler implementation")
	v.AddSeparator()

	v.AddStep("2. Implementation Advantages:")
	v.AddStep("   • Designed to prevent common implementation errors")
	v.AddStep("   • No need to validate curve points (built-in safety)")
	v.AddStep("   • Simpler parameter selection (fixed curve)")
	v.AddStep("   • No need to generate or validate prime numbers")
	v.AddStep("   • Reduced risk of weak parameter choices")
	v.AddSeparator()

	v.AddStep("3. Performance Benefits:")
	v.AddStep("   • Faster computation (especially on modern CPUs)")
	v.AddStep("   • Lower power consumption")
	v.AddStep("   • Better performance on embedded devices")
	v.AddStep("   • Smaller key sizes (32 bytes vs 2048+ bits)")
	v.AddStep("   • More efficient for mobile and IoT devices")
	v.AddSeparator()

	v.AddStep("4. Real-World Adoption:")
	v.AddStep("   • TLS 1.3 (replaced DH with X25519)")
	v.AddStep("   • Signal Protocol")
	v.AddStep("   • WireGuard VPN")
	v.AddStep("   • Modern SSH implementations")
	v.AddStep("   • Many other secure messaging apps")
	v.AddSeparator()

	// Step 1: Generate private keys
	v.AddStep("Step 1: Private Key Generation")
	v.AddStep("---------------------------")
	alicePrivate := make([]byte, 32)
	bobPrivate := make([]byte, 32)
	if _, err := rand.Read(alicePrivate); err != nil {
		return "", nil, fmt.Errorf("failed to generate Alice's private key: %w", err)
	}
	if _, err := rand.Read(bobPrivate); err != nil {
		return "", nil, fmt.Errorf("failed to generate Bob's private key: %w", err)
	}

	// Ensure private keys are valid scalars
	alicePrivate[0] &= 248
	alicePrivate[31] &= 127
	alicePrivate[31] |= 64
	bobPrivate[0] &= 248
	bobPrivate[31] &= 127
	bobPrivate[31] |= 64

	v.AddStep(fmt.Sprintf("Alice's Private Key: %x", alicePrivate))
	v.AddStep(fmt.Sprintf("Bob's Private Key: %x", bobPrivate))
	v.AddArrow()

	// Step 2: Calculate public keys
	v.AddStep("Step 2: Public Key Calculation")
	v.AddStep("----------------------------")
	alicePublic, err := curve25519.X25519(alicePrivate, curve25519.Basepoint)
	if err != nil {
		return "", nil, fmt.Errorf("failed to calculate Alice's public key: %w", err)
	}
	bobPublic, err := curve25519.X25519(bobPrivate, curve25519.Basepoint)
	if err != nil {
		return "", nil, fmt.Errorf("failed to calculate Bob's public key: %w", err)
	}
	v.AddStep(fmt.Sprintf("Alice's Public Key: %x", alicePublic))
	v.AddStep(fmt.Sprintf("Bob's Public Key: %x", bobPublic))
	v.AddArrow()

	// Step 3: Calculate shared secrets
	v.AddStep("Step 3: Shared Secret Calculation")
	v.AddStep("-------------------------------")
	aliceShared, err := curve25519.X25519(alicePrivate, bobPublic)
	if err != nil {
		return "", nil, fmt.Errorf("failed to calculate Alice's shared secret: %w", err)
	}
	bobShared, err := curve25519.X25519(bobPrivate, alicePublic)
	if err != nil {
		return "", nil, fmt.Errorf("failed to calculate Bob's shared secret: %w", err)
	}
	v.AddStep(fmt.Sprintf("Alice's Shared Secret: %x", aliceShared))
	v.AddStep(fmt.Sprintf("Bob's Shared Secret: %x", bobShared))
	v.AddArrow()

	// Step 4: Verify shared secrets match
	v.AddStep("Step 4: Shared Secret Verification")
	v.AddStep("--------------------------------")
	if bytes.Equal(aliceShared, bobShared) {
		v.AddStep("✅ Shared secrets match!")
	} else {
		return "", nil, fmt.Errorf("shared secrets do not match")
	}
	v.AddSeparator()

	// Step 5: Key Derivation Function (KDF)
	v.AddStep("Step 5: Key Derivation")
	v.AddStep("---------------------")
	// Use HKDF to derive a secure key from the shared secret
	hkdf := hkdf.New(sha256.New, aliceShared, []byte("CryptoLens-X25519-KDF"), []byte("CryptoLens-X25519-Info"))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		return "", nil, fmt.Errorf("failed to derive key: %w", err)
	}
	v.AddStep(fmt.Sprintf("Derived key (using HKDF): %x", derivedKey))
	v.AddSeparator()

	// Step 6: Demonstrate AES Encryption with Shared Secret
	v.AddStep("Step 6: Using Shared Secret for AES Encryption")
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
	x25519Duration := time.Since(startTime)
	v.AddStep(fmt.Sprintf("X25519 Execution Time: %v", x25519Duration))

	// Measure DH performance without running the full process
	dhStart := time.Now()
	prime := new(big.Int).SetInt64(2)
	prime.Exp(prime, big.NewInt(2048), nil)
	prime.Sub(prime, big.NewInt(1))
	generator := big.NewInt(2)
	alicePrivateDH, _ := rand.Int(rand.Reader, prime)
	bobPrivateDH, _ := rand.Int(rand.Reader, prime)
	alicePublicDH := new(big.Int).Exp(generator, alicePrivateDH, prime)
	bobPublicDH := new(big.Int).Exp(generator, bobPrivateDH, prime)
	_ = new(big.Int).Exp(bobPublicDH, alicePrivateDH, prime) // Calculate shared secret
	_ = new(big.Int).Exp(alicePublicDH, bobPrivateDH, prime) // Calculate shared secret
	dhDuration := time.Since(dhStart)
	v.AddStep(fmt.Sprintf("Classic DH Execution Time: %v", dhDuration))
	v.AddStep(fmt.Sprintf("X25519 is %.2fx faster than Classic DH", float64(dhDuration)/float64(x25519Duration)))
	v.AddSeparator()

	// Explain the process
	v.AddStep("How it works:")
	v.AddStep("1. X25519 establishes a shared secret between Alice and Bob")
	v.AddStep("2. The shared secret is used to derive an AES key")
	v.AddStep("3. The AES key is used to encrypt/decrypt messages")
	v.AddStep("4. Both parties can encrypt/decrypt using the same key")
	v.AddSeparator()

	// Security Considerations
	v.AddStep("🔒 Security Considerations")
	v.AddStep("========================")
	v.AddStep("1. Key Exchange Security:")
	v.AddStep("   • Curve25519 is designed to be secure by default")
	v.AddStep("   • No need for complex parameter validation")
	v.AddStep("   • Built-in protection against common attacks")
	v.AddStep("   • Constant-time operations prevent timing attacks")
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
	v.AddStep("   • Use strong random number generation")
	v.AddStep("   • Regularly rotate keys")
	v.AddStep("   • Verify all signatures in production")
	v.AddSeparator()

	v.AddStep("4. Real-World Usage Examples:")
	v.AddStep("   • TLS 1.3 handshake:")
	v.AddStep("     - Server sends certificate")
	v.AddStep("     - Client verifies certificate")
	v.AddStep("     - X25519 key exchange follows")
	v.AddStep("     - All messages authenticated")
	v.AddStep("   • Signal Protocol")
	v.AddStep("   • WireGuard VPN")
	v.AddStep("   • Modern SSH implementations")
	v.AddSeparator()

	// Final result
	result := "Successfully demonstrated X25519 key exchange and AES encryption"
	return result, v.GetSteps(), nil
}
