package attacks

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/utils"
	"golang.org/x/crypto/chacha20poly1305"
)

// NonceReuseProcessor implements the nonce reuse attack simulation
type NonceReuseProcessor struct {
	keySize int
	key     []byte
}

// NewNonceReuseProcessor creates a new nonce reuse attack processor
func NewNonceReuseProcessor() *NonceReuseProcessor {
	return &NonceReuseProcessor{
		keySize: 256, // Default to ChaCha20-Poly1305 key size
	}
}

// Configure configures the nonce reuse processor
func (p *NonceReuseProcessor) Configure(config map[string]interface{}) error {
	if keySize, ok := config["keySize"].(int); ok {
		if keySize != 256 {
			return fmt.Errorf("invalid key size: %d (must be 256 bits for ChaCha20-Poly1305)", keySize)
		}
		p.keySize = keySize
	}

	// Generate a random key
	p.key = make([]byte, p.keySize/8)
	if _, err := rand.Read(p.key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	return nil
}

// Process demonstrates the nonce reuse vulnerability in AEAD ciphers
func (p *NonceReuseProcessor) Process(text string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep("🔒 Nonce Reuse in AEAD Ciphers")
	v.AddStep("============================")
	v.AddNote("AEAD (Authenticated Encryption with Associated Data) ciphers")
	v.AddNote("require unique nonces for each encryption operation")
	v.AddNote("Reusing a nonce with the same key completely breaks security")
	v.AddSeparator()

	// Show input
	v.AddTextStep("First Message", text)
	v.AddHexStep("Plaintext 1 (hex)", []byte(text))
	v.AddArrow()

	// Get second message
	v.AddStep("Step 1: Message Collection")
	v.AddStep("----------------------")
	fmt.Printf("\n%s", utils.DefaultTheme.Format("Enter a second message to encrypt with the same nonce: ", "brightGreen"))
	var secondMessage string
	fmt.Scanln(&secondMessage)
	if secondMessage == "" {
		secondMessage = "This is a different message encrypted with the same nonce!"
	}
	v.AddTextStep("Second Message", secondMessage)
	v.AddHexStep("Plaintext 2 (hex)", []byte(secondMessage))
	v.AddArrow()

	// Show XOR of plaintexts
	v.AddStep("XOR of Plaintexts (P1 ⊕ P2):")
	pt1 := []byte(text)
	pt2 := []byte(secondMessage)
	ptXored := make([]byte, max(len(pt1), len(pt2)))
	for i := range ptXored {
		var b1, b2 byte
		if i < len(pt1) {
			b1 = pt1[i]
		}
		if i < len(pt2) {
			b2 = pt2[i]
		}
		ptXored[i] = b1 ^ b2
	}
	v.AddHexStep("Plaintext XOR Result", ptXored)
	v.AddStep("Note: Non-zero bytes show where the messages differ!")
	v.AddArrow()

	// Create ChaCha20-Poly1305 cipher
	v.AddStep("Step 2: Cipher Initialization")
	v.AddStep("---------------------------")
	aead, err := chacha20poly1305.New(p.key)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	v.AddStep("✅ Cipher initialized successfully")
	v.AddArrow()

	// Generate a single nonce to be reused
	v.AddStep("Step 3: Nonce Generation")
	v.AddStep("---------------------")
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	v.AddStep("⚠️ WARNING: Using the same nonce for both messages")
	v.AddStep("This is a critical security vulnerability!")
	v.AddHexStep("Reused Nonce", nonce)
	v.AddArrow()

	// Encrypt both messages with the same nonce
	v.AddStep("Step 4: Encryption")
	v.AddStep("----------------")
	ciphertext1 := aead.Seal(nil, nonce, []byte(text), nil)
	ciphertext2 := aead.Seal(nil, nonce, []byte(secondMessage), nil)

	v.AddHexStep("First Ciphertext (with tag)", ciphertext1)
	v.AddArrow()
	v.AddHexStep("Second Ciphertext (with tag)", ciphertext2)
	v.AddArrow()

	// Demonstrate the attack
	v.AddStep("Step 5: Nonce Reuse Attack")
	v.AddStep("----------------------")
	v.AddStep("When the same nonce is used with the same key:")
	v.AddStep("1. The keystream is identical for both messages")
	v.AddStep("2. XORing the ciphertexts reveals the XOR of the plaintexts")
	v.AddStep("3. This can lead to partial or complete plaintext recovery")
	v.AddArrow()

	// XOR the ciphertexts (excluding the authentication tag)
	tagSize := 16
	ct1 := ciphertext1[:len(ciphertext1)-tagSize]
	ct2 := ciphertext2[:len(ciphertext2)-tagSize]
	xored := make([]byte, max(len(ct1), len(ct2)))
	for i := range xored {
		var b1, b2 byte
		if i < len(ct1) {
			b1 = ct1[i]
		}
		if i < len(ct2) {
			b2 = ct2[i]
		}
		xored[i] = b1 ^ b2
	}

	v.AddStep("XOR of Ciphertexts (excluding tags):")
	v.AddHexStep("Ciphertext XOR Result", xored)
	v.AddStep("Note: The XOR of ciphertexts matches the XOR of plaintexts!")
	v.AddStep("This is because: C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2")
	v.AddArrow()

	// Add technical explanation
	v.AddStep("🧠 Why This Works:")
	v.AddStep("================")
	v.AddStep("AEAD = Stream cipher + MAC")
	v.AddStep("If nonce is reused:")
	v.AddStep("• Same key + nonce → same keystream (KS)")
	v.AddStep("• C1 = M1 ⊕ KS")
	v.AddStep("• C2 = M2 ⊕ KS")
	v.AddStep("→ XOR(C1, C2) = M1 ⊕ M2")
	v.AddStep("")
	v.AddStep("The keystream cancels out in the XOR operation,")
	v.AddStep("leaving only the XOR of the original messages.")
	v.AddStep("This is why nonce reuse is catastrophic - it reveals")
	v.AddStep("the relationship between encrypted messages.")
	v.AddSeparator()

	// Add security notes
	v.AddStep("🔒 Security Implications")
	v.AddStep("======================")
	v.AddStep("1. Nonce reuse in AEAD ciphers is catastrophic")
	v.AddStep("2. The same nonce with the same key produces identical keystream")
	v.AddStep("3. This allows attackers to:")
	v.AddStep("   • Recover plaintext through XOR operations")
	v.AddStep("   • Forge valid ciphertexts")
	v.AddStep("   • Break confidentiality completely")
	v.AddStep("4. Authentication tags become meaningless")
	v.AddStep("5. The entire security model collapses")

	v.AddStep("✅ Best Practices")
	v.AddStep("===============")
	v.AddStep("1. Never reuse nonces with the same key")
	v.AddStep("2. Use a cryptographically secure random number generator")
	v.AddStep("3. Consider using a counter-based nonce generation")
	v.AddStep("4. Implement proper nonce management in your application")
	v.AddStep("5. Use unique nonces for each encryption operation")

	// Return the base64 encoded result of both ciphertexts
	result := fmt.Sprintf("Ciphertext 1: %s\nCiphertext 2: %s",
		base64.StdEncoding.EncodeToString(ciphertext1),
		base64.StdEncoding.EncodeToString(ciphertext2))

	return result, v.GetSteps(), nil
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
