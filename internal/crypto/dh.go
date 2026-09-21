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

// addDHIntro explains what DH is and the intuition behind it.
func addDHIntro(v *utils.Visualizer) {
	v.AddStep("📌 What is Diffie-Hellman?")
	v.AddStep("Diffie-Hellman (1976) lets two parties who have never met agree on a shared secret")
	v.AddStep("over a channel an eavesdropper is fully watching — without ever sending the secret.")
	v.AddStep("It is KEY AGREEMENT, not encryption: the output is a shared key, which is then")
	v.AddStep("used with a symmetric cipher like AES.")
	v.AddNote("Paint analogy: Alice and Bob publicly agree on a base color, each mixes in a secret")
	v.AddNote("color, and they swap the mixtures. Each adds their own secret again → both reach the")
	v.AddNote("same final mix. An observer can't 'un-mix' the paints to recover the secrets.")
	v.AddSeparator()

	v.AddStep("📈 Why it is secure: the discrete logarithm problem")
	v.AddStep("Computing A = g^a mod p is easy. Going backwards — finding a from g, p and A — is")
	v.AddStep("infeasible when p is a large prime. That one-way function is what protects the secret.")
	v.AddSeparator()
}

// addDHToyExample runs the DH math on tiny numbers so the shared-secret trick is
// concrete and verifiable.
func addDHToyExample(v *utils.Visualizer) {
	p := big.NewInt(23) // small prime
	g := big.NewInt(5)  // generator
	a := big.NewInt(6)  // Alice secret
	b := big.NewInt(15) // Bob secret

	A := new(big.Int).Exp(g, a, p)  // 8
	B := new(big.Int).Exp(g, b, p)  // 19
	sA := new(big.Int).Exp(B, a, p) // 2
	sB := new(big.Int).Exp(A, b, p) // 2
	gab := new(big.Int).Exp(g, new(big.Int).Mul(a, b), p)

	v.AddStep("📚 Worked example with tiny numbers (real p is 2048 bits)")
	v.AddStep(fmt.Sprintf("Public agreement:  prime p = %s, generator g = %s", p, g))
	v.AddStep(fmt.Sprintf("Alice's secret a = %s → public A = g^a mod p = 5^%s mod 23 = %s", a, a, A))
	v.AddStep(fmt.Sprintf("Bob's   secret b = %s → public B = g^b mod p = 5^%s mod 23 = %s", b, b, B))
	v.AddStep("They exchange A and B in the open, then each combines with their own secret:")
	v.AddStep(fmt.Sprintf("  Alice: B^a mod p = %s^%s mod 23 = %s", B, a, sA))
	v.AddStep(fmt.Sprintf("  Bob:   A^b mod p = %s^%s mod 23 = %s", A, b, sB))
	v.AddStep(fmt.Sprintf("Both get %s, which equals g^(a·b) mod p = %s ✅", sA, gab))
	v.AddNote("The eavesdropper knows p=23, g=5, A=8, B=19 but still cannot cheaply find a or b")
	v.AddNote("to compute the shared 2 — and with a 2048-bit prime it is hopeless.")
	v.AddSeparator()
}

// Process implements the Processor interface for Diffie-Hellman
func (p *DHProcessor) Process(_ string, _ string) (string, []string, error) {
	v := utils.NewVisualizer()
	startTime := time.Now()

	// Introduction
	addDHIntro(v)
	addDHToyExample(v)

	// Step 1: Generate or load prime number
	v.AddStep("Step 1: Prime Number Setup")
	v.AddStep("------------------------")
	prime, err := p.loadOrGeneratePrime()
	if err != nil {
		return "", nil, fmt.Errorf("failed to setup prime: %w", err)
	}
	p.prime = prime

	// Show parameters
	v.AddStep("Parameters (the real exchange — same math, huge numbers):")
	v.AddStep(fmt.Sprintf("Prime (p): %d-bit value, first hex digits: %.32s…", p.prime.BitLen(), p.prime.Text(16)))
	v.AddStep(fmt.Sprintf("Generator (g): %s", p.generator.Text(10)))
	v.AddNote("p and g are public. The prime is large so the discrete-log problem is infeasible.")
	v.AddSeparator()

	// Step 2: Generate private keys
	v.AddStep("Step 2: Private Key Generation")
	v.AddStep("----------------------------")
	v.AddNote("Each party picks a random SECRET exponent and never reveals it.")
	alicePrivate, err := p.generatePrivateKey()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate Alice's private key: %w", err)
	}
	bobPrivate, err := p.generatePrivateKey()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate Bob's private key: %w", err)
	}
	v.AddStep(fmt.Sprintf("Alice's private a (secret): %.24s…", alicePrivate.Text(16)))
	v.AddStep(fmt.Sprintf("Bob's private b (secret):   %.24s…", bobPrivate.Text(16)))
	v.AddArrow()

	// Step 3: Calculate public keys
	v.AddStep("Step 3: Public Key Calculation")
	v.AddStep("----------------------------")
	v.AddStep("Each computes their public value  A = g^a mod p  (B = g^b mod p) and shares it.")
	alicePublic := new(big.Int).Exp(p.generator, alicePrivate, prime)
	bobPublic := new(big.Int).Exp(p.generator, bobPrivate, prime)
	v.AddStep(fmt.Sprintf("Alice's public A = g^a mod p: %.24s…", alicePublic.Text(16)))
	v.AddStep(fmt.Sprintf("Bob's public   B = g^b mod p: %.24s…", bobPublic.Text(16)))
	v.AddNote("Recovering a from A means solving the discrete logarithm — infeasible for large p.")
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
	v.AddStep("Each raises the OTHER's public value to their own secret:")
	v.AddStep("  Alice: s = B^a mod p     Bob: s = A^b mod p")
	v.AddStep("Both equal g^(a·b) mod p — the same number, never sent over the wire.")
	aliceShared := new(big.Int).Exp(bobPublic, alicePrivate, prime)
	bobShared := new(big.Int).Exp(alicePublic, bobPrivate, prime)
	v.AddStep(fmt.Sprintf("Alice computes B^a mod p: %.24s…", aliceShared.Text(16)))
	v.AddStep(fmt.Sprintf("Bob computes   A^b mod p: %.24s…", bobShared.Text(16)))
	v.AddArrow()

	// Step 6: Verify shared secrets match
	v.AddStep("Step 6: Shared Secret Verification")
	v.AddStep("--------------------------------")
	if aliceShared.Cmp(bobShared) == 0 {
		v.AddStep("✅ Shared secrets match! Both derived g^(a·b) mod p independently.")
	} else {
		return "", nil, fmt.Errorf("shared secrets do not match")
	}
	v.AddNote("An eavesdropper sees p, g, A and B — but computing g^(a·b) from those requires a")
	v.AddNote("secret exponent. That asymmetry is the entire magic of Diffie-Hellman.")
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

	v.AddStep("3. Perfect Forward Secrecy (PFS):")
	v.AddStep("   • Use fresh, EPHEMERAL DH keys per session (this is DHE / ECDHE).")
	v.AddStep("   • Then a later key compromise cannot decrypt past recorded sessions —")
	v.AddStep("     each session's secret vanished when its ephemeral keys were discarded.")
	v.AddStep("   • This is why TLS 1.3 mandates ephemeral (EC)DH and dropped static RSA key exchange.")
	v.AddSeparator()

	v.AddStep("4. Best Practices:")
	v.AddStep("   • Use authenticated key exchange (e.g., TLS)")
	v.AddStep("   • Use strong, standardized prime groups (RFC 3526/7919), not homemade ones")
	v.AddStep("   • Prefer elliptic-curve DH (X25519, menu 9) — smaller, faster, safer defaults")
	v.AddStep("   • Verify all signatures")
	v.AddSeparator()

	v.AddStep("5. Real-World Usage Examples:")
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
