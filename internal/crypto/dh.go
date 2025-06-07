package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"

	"github.com/abdorrahmani/cryptolens/internal/utils"
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
		keyManager: NewFileKeyManager(2048, "dh_prime.bin"),
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
func (p *DHProcessor) Process(input string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

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

	// Step 4: Calculate shared secrets
	v.AddStep("Step 4: Shared Secret Calculation")
	v.AddStep("-------------------------------")
	aliceShared := new(big.Int).Exp(bobPublic, alicePrivate, prime)
	bobShared := new(big.Int).Exp(alicePublic, bobPrivate, prime)
	v.AddStep(fmt.Sprintf("Alice's Shared Secret: %s", aliceShared.Text(16)))
	v.AddStep(fmt.Sprintf("Bob's Shared Secret: %s", bobShared.Text(16)))
	v.AddArrow()

	// Step 5: Verify shared secrets match
	v.AddStep("Step 5: Shared Secret Verification")
	v.AddStep("--------------------------------")
	if aliceShared.Cmp(bobShared) == 0 {
		v.AddStep("✅ Shared secrets match!")
	} else {
		return "", nil, fmt.Errorf("shared secrets do not match")
	}
	v.AddSeparator()

	// Step 6: Key Derivation Function (KDF)
	v.AddStep("Step 6: Key Derivation")
	v.AddStep("---------------------")
	// Use HKDF to derive a secure key from the shared secret
	hkdf := hkdf.New(sha256.New, aliceShared.Bytes(), []byte("CryptoLens-DH-KDF"), []byte("CryptoLens-DH-Info"))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		return "", nil, fmt.Errorf("failed to derive key: %w", err)
	}
	v.AddStep(fmt.Sprintf("Derived key (using HKDF): %x", derivedKey))
	v.AddSeparator()

	// Security Considerations
	v.AddStep("🔒 Security Considerations")
	v.AddStep("========================")
	v.AddStep("1. Man-in-the-Middle (MITM) Attack Vulnerability:")
	v.AddStep("   • DH alone is vulnerable to MITM attacks")
	v.AddStep("   • An attacker can intercept and modify public keys")
	v.AddStep("   • Solution: Combine DH with authentication (e.g., digital signatures)")
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
	v.AddSeparator()

	v.AddStep("4. Real-World Usage Examples:")
	v.AddStep("   • TLS/SSL handshake")
	v.AddStep("   • SSH key exchange")
	v.AddStep("   • Signal Protocol")
	v.AddStep("   • WireGuard VPN")
	v.AddSeparator()

	// Final result
	result := "Successfully established shared secret and derived key using Diffie-Hellman key exchange"
	return result, v.GetSteps(), nil
}
