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

	// Add ASCII Diagram
	v.AddStep("Key Exchange Flow:")
	v.AddStep("┌─────────┐                    ┌─────────┐")
	v.AddStep("│  Alice  │                    │   Bob   │")
	v.AddStep("└────┬────┘                    └────┬────┘")
	v.AddStep("     │                               │")
	v.AddStep("     │  PrivKey_A            PrivKey_B│")
	v.AddStep("     │      │                    │    │")
	v.AddStep("     │      v                    v    │")
	v.AddStep("     │  PubKey_A ────────────> PubKey_B")
	v.AddStep("     │      │                    │    │")
	v.AddStep("     │      v                    v    │")
	v.AddStep("     │  SharedSecret_A == SharedSecret_B")
	v.AddStep("     │      │                    │    │")
	v.AddStep("     │      v                    v    │")
	v.AddStep("     │  HKDF -> AES Key    HKDF -> AES Key")
	v.AddStep("     │      │                    │    │")
	v.AddStep("     │      v                    v    │")
	v.AddStep("     │  Encrypt/Decrypt    Encrypt/Decrypt")
	v.AddStep("     │                               │")
	v.AddStep("┌────┴────┐                    ┌────┴────┐")
	v.AddStep("│  Alice  │                    │   Bob   │")
	v.AddStep("└─────────┘                    └─────────┘")
	v.AddSeparator()

	v.AddStep("Legend:")
	v.AddStep("• PrivKey_X: Private key (never shared)")
	v.AddStep("• PubKey_X:  Public key (exchanged)")
	v.AddStep("• SharedSecret_X: Computed shared secret")
	v.AddStep("• HKDF: Key derivation function")
	v.AddStep("• AES Key: Derived encryption key")
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

	// Add TLS 1.3 Connection Section
	v.AddStep("🔐 TLS 1.3 Connection Example")
	v.AddStep("==========================")
	v.AddStep("In TLS 1.3, only modern key exchange algorithms are allowed:")
	v.AddStep("1. X25519 (Curve25519)")
	v.AddStep("2. P-256 (NIST P-256)")
	v.AddStep("3. P-384 (NIST P-384)")
	v.AddStep("4. P-521 (NIST P-521)")
	v.AddStep("5. X448 (Curve448)")
	v.AddStep("6. FFDHE2048 (Finite Field DH)")
	v.AddStep("7. FFDHE3072 (Finite Field DH)")
	v.AddStep("8. FFDHE4096 (Finite Field DH)")
	v.AddSeparator()

	v.AddStep("TLS 1.3 Connection Flow:")
	v.AddStep("1. Client Hello:")
	v.AddStep("   • Supported cipher suites")
	v.AddStep("   • Supported key exchange groups")
	v.AddStep("   • Random nonce")
	v.AddStep("2. Server Hello:")
	v.AddStep("   • Selected cipher suite")
	v.AddStep("   • Selected key exchange group")
	v.AddStep("   • Random nonce")
	v.AddStep("3. Key Exchange:")
	v.AddStep("   • Server's ephemeral public key")
	v.AddStep("   • Server's signature")
	v.AddStep("4. Client Key Exchange:")
	v.AddStep("   • Client's ephemeral public key")
	v.AddStep("5. Finished:")
	v.AddStep("   • Both parties verify the handshake")
	v.AddStep("   • Derive session keys")
	v.AddSeparator()

	v.AddStep("Security Requirements:")
	v.AddStep("1. Perfect Forward Secrecy (PFS)")
	v.AddStep("   • Ephemeral key pairs for each session")
	v.AddStep("   • Keys are never reused")
	v.AddStep("2. Key Exchange Security")
	v.AddStep("   • Must use approved curves")
	v.AddStep("   • Must implement proper validation")
	v.AddStep("3. Authentication")
	v.AddStep("   • Server authentication via certificates")
	v.AddStep("   • Optional client authentication")
	v.AddStep("4. Key Derivation")
	v.AddStep("   • HKDF for key derivation")
	v.AddStep("   • Separate keys for different purposes")
	v.AddSeparator()

	v.AddStep("Production Considerations:")
	v.AddStep("1. Certificate Management")
	v.AddStep("   • Use trusted Certificate Authorities")
	v.AddStep("   • Regular certificate rotation")
	v.AddStep("   • Proper key storage")
	v.AddStep("2. Protocol Configuration")
	v.AddStep("   • Disable legacy protocols")
	v.AddStep("   • Enforce strong cipher suites")
	v.AddStep("   • Configure proper timeouts")
	v.AddStep("3. Monitoring and Logging")
	v.AddStep("   • Track handshake failures")
	v.AddStep("   • Monitor certificate expiration")
	v.AddStep("   • Log security events")
	v.AddSeparator()

	// Add Security Warnings Section
	v.AddStep("⚠️ CRITICAL SECURITY WARNINGS")
	v.AddStep("==========================")
	v.AddStep("1. Authentication is REQUIRED:")
	v.AddStep("   • X25519 is ONLY for key exchange")
	v.AddStep("   • MUST be combined with authentication")
	v.AddStep("   • Common authentication methods:")
	v.AddStep("     - Digital signatures (RSA, ECDSA)")
	v.AddStep("     - TLS certificates")
	v.AddStep("     - Pre-shared keys")
	v.AddStep("   • Without authentication, vulnerable to MITM attacks")
	v.AddStep("   • Example: TLS 1.3 uses X25519 + certificates")
	v.AddSeparator()

	v.AddStep("2. Implementation Security:")
	v.AddStep("   • MUST use constant-time implementation")
	v.AddStep("   • Curve25519 is designed for constant-time operations")
	v.AddStep("   • Never implement your own curve arithmetic")
	v.AddStep("   • Use well-audited libraries (like golang.org/x/crypto/curve25519)")
	v.AddStep("   • Avoid side-channel attacks:")
	v.AddStep("     - Timing attacks")
	v.AddStep("     - Power analysis")
	v.AddStep("     - Cache attacks")
	v.AddSeparator()

	v.AddStep("3. Key Management:")
	v.AddStep("   • Generate private keys securely")
	v.AddStep("   • Never reuse private keys")
	v.AddStep("   • Use proper key derivation (HKDF)")
	v.AddStep("   • Store private keys securely")
	v.AddStep("   • Implement key rotation")
	v.AddSeparator()

	v.AddStep("4. Common Pitfalls:")
	v.AddStep("   • Using X25519 without authentication")
	v.AddStep("   • Reusing private keys")
	v.AddStep("   • Implementing custom curve arithmetic")
	v.AddStep("   • Using non-constant-time operations")
	v.AddStep("   • Skipping key validation")
	v.AddStep("   • Not using proper key derivation")
	v.AddSeparator()

	v.AddStep("5. Best Practices:")
	v.AddStep("   • Always use authenticated key exchange")
	v.AddStep("   • Use constant-time implementations")
	v.AddStep("   • Implement proper key validation")
	v.AddStep("   • Use secure random number generation")
	v.AddStep("   • Follow protocol specifications exactly")
	v.AddStep("   • Regular security audits")
	v.AddSeparator()

	// Final result
	result := "Successfully demonstrated X25519 key exchange and AES encryption"
	return result, v.GetSteps(), nil
}
