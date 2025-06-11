package attacks

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/utils"
	"golang.org/x/crypto/chacha20poly1305"
)

// NonceReuseProcessor implements the nonce reuse attack simulation
type NonceReuseProcessor struct {
	*BaseProcessor
	config *AttackConfig
}

// NewNonceReuseProcessor creates a new nonce reuse attack processor
func NewNonceReuseProcessor() *NonceReuseProcessor {
	return &NonceReuseProcessor{
		BaseProcessor: NewBaseProcessor(),
		config:        NewAttackConfig(),
	}
}

// Configure configures the nonce reuse processor
func (p *NonceReuseProcessor) Configure(config map[string]interface{}) error {
	if keySize, ok := config["keySize"].(int); ok {
		if keySize != 256 {
			return fmt.Errorf("invalid key size: %d (must be 256 bits for ChaCha20-Poly1305)", keySize)
		}
		p.config.KeySize = keySize
	}

	// Generate a random key
	p.config.Key = make([]byte, p.config.KeySize/8)
	if _, err := rand.Read(p.config.Key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	return nil
}

// Process demonstrates the nonce reuse vulnerability in AEAD ciphers
func (p *NonceReuseProcessor) Process(text string, operation string) (string, []string, error) {
	p.addIntroduction()

	// Get second message
	secondMessage := p.getSecondMessage()

	// Show input information
	p.addInputInfo(text, secondMessage)

	// Create cipher and nonce
	aead, nonce, err := p.initializeCipher()
	if err != nil {
		return "", nil, err
	}

	// Encrypt messages
	ciphertext1, ciphertext2 := p.encryptMessages(aead, nonce, text, secondMessage)

	// Demonstrate the attack
	p.demonstrateAttack(text, secondMessage, ciphertext1, ciphertext2)

	// Add security notes
	p.addSecurityImplications()

	// Return the base64 encoded result of both ciphertexts
	result := fmt.Sprintf("Ciphertext 1: %s\nCiphertext 2: %s",
		base64.StdEncoding.EncodeToString(ciphertext1),
		base64.StdEncoding.EncodeToString(ciphertext2))

	return result, p.GetSteps(), nil
}

func (p *NonceReuseProcessor) addIntroduction() {
	p.AddStep("🔒 Nonce Reuse in AEAD Ciphers")
	p.AddStep("============================")
	p.AddNote("AEAD (Authenticated Encryption with Associated Data) ciphers")
	p.AddNote("require unique nonces for each encryption operation")
	p.AddNote("Reusing a nonce with the same key completely breaks security")
	p.AddSeparator()
}

func (p *NonceReuseProcessor) getSecondMessage() string {
	p.AddStep("Step 1: Message Collection")
	p.AddStep("----------------------")
	fmt.Printf("\n%s", utils.DefaultTheme.Format("Enter a second message to encrypt with the same nonce: ", "brightGreen"))
	var secondMessage string
	if _, err := fmt.Scanln(&secondMessage); err != nil {
		secondMessage = "This is a different message encrypted with the same nonce!"
	}
	if secondMessage == "" {
		secondMessage = "This is a different message encrypted with the same nonce!"
	}
	return secondMessage
}

func (p *NonceReuseProcessor) addInputInfo(text, secondMessage string) {
	p.AddTextStep("First Message", text)
	p.AddHexStep("Plaintext 1 (hex)", []byte(text))
	p.AddArrow()
	p.AddTextStep("Second Message", secondMessage)
	p.AddHexStep("Plaintext 2 (hex)", []byte(secondMessage))
	p.AddArrow()

	// Show XOR of plaintexts
	p.AddStep("XOR of Plaintexts (P1 ⊕ P2):")
	ptXored := p.xorBytes([]byte(text), []byte(secondMessage))
	p.AddHexStep("Plaintext XOR Result", ptXored)
	p.AddStep("Note: Non-zero bytes show where the messages differ!")
	p.AddArrow()
}

func (p *NonceReuseProcessor) initializeCipher() (cipher.AEAD, []byte, error) {
	p.AddStep("Step 2: Cipher Initialization")
	p.AddStep("---------------------------")
	aead, err := chacha20poly1305.New(p.config.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	p.AddStep("✅ Cipher initialized successfully")
	p.AddArrow()

	p.AddStep("Step 3: Nonce Generation")
	p.AddStep("---------------------")
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	p.AddStep("⚠️ WARNING: Using the same nonce for both messages")
	p.AddStep("This is a critical security vulnerability!")
	p.AddHexStep("Reused Nonce", nonce)
	p.AddArrow()

	return aead, nonce, nil
}

func (p *NonceReuseProcessor) encryptMessages(aead cipher.AEAD, nonce []byte, text, secondMessage string) ([]byte, []byte) {
	p.AddStep("Step 4: Encryption")
	p.AddStep("----------------")
	ciphertext1 := aead.Seal(nil, nonce, []byte(text), nil)
	ciphertext2 := aead.Seal(nil, nonce, []byte(secondMessage), nil)

	p.AddHexStep("First Ciphertext (with tag)", ciphertext1)
	p.AddArrow()
	p.AddHexStep("Second Ciphertext (with tag)", ciphertext2)
	p.AddArrow()

	return ciphertext1, ciphertext2
}

func (p *NonceReuseProcessor) demonstrateAttack(text, secondMessage string, ciphertext1, ciphertext2 []byte) {
	p.AddStep("Step 5: Nonce Reuse Attack")
	p.AddStep("----------------------")
	p.AddStep("When the same nonce is used with the same key:")
	p.AddStep("1. The keystream is identical for both messages")
	p.AddStep("2. XORing the ciphertexts reveals the XOR of the plaintexts")
	p.AddStep("3. This can lead to partial or complete plaintext recovery")
	p.AddArrow()

	// XOR the ciphertexts (excluding the authentication tag)
	tagSize := 16
	ct1 := ciphertext1[:len(ciphertext1)-tagSize]
	ct2 := ciphertext2[:len(ciphertext2)-tagSize]
	xored := p.xorBytes(ct1, ct2)

	p.AddStep("XOR of Ciphertexts (excluding tags):")
	p.AddHexStep("Ciphertext XOR Result", xored)
	p.AddStep("Note: The XOR of ciphertexts matches the XOR of plaintexts!")
	p.AddStep("This is because: C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2")
	p.AddArrow()

	p.addTechnicalExplanation()
}

func (p *NonceReuseProcessor) addTechnicalExplanation() {
	p.AddStep("🧠 Why This Works:")
	p.AddStep("================")
	p.AddStep("AEAD = Stream cipher + MAC")
	p.AddStep("If nonce is reused:")
	p.AddStep("• Same key + nonce → same keystream (KS)")
	p.AddStep("• C1 = M1 ⊕ KS")
	p.AddStep("• C2 = M2 ⊕ KS")
	p.AddStep("→ XOR(C1, C2) = M1 ⊕ M2")
	p.AddStep("")
	p.AddStep("The keystream cancels out in the XOR operation,")
	p.AddStep("leaving only the XOR of the original messages.")
	p.AddStep("This is why nonce reuse is catastrophic - it reveals")
	p.AddStep("the relationship between encrypted messages.")
	p.AddSeparator()
}

func (p *NonceReuseProcessor) addSecurityImplications() {
	p.AddStep("🔒 Security Implications")
	p.AddStep("======================")
	p.AddStep("1. Nonce reuse in AEAD ciphers is catastrophic")
	p.AddStep("2. The same nonce with the same key produces identical keystream")
	p.AddStep("3. This allows attackers to:")
	p.AddStep("   • Recover plaintext through XOR operations")
	p.AddStep("   • Forge valid ciphertexts")
	p.AddStep("   • Break confidentiality completely")
	p.AddStep("4. Authentication tags become meaningless")
	p.AddStep("5. The entire security model collapses")

	p.AddStep("✅ Best Practices")
	p.AddStep("===============")
	p.AddStep("1. Never reuse nonces with the same key")
	p.AddStep("2. Use a cryptographically secure random number generator")
	p.AddStep("3. Consider using a counter-based nonce generation")
	p.AddStep("4. Implement proper nonce management in your application")
	p.AddStep("5. Use unique nonces for each encryption operation")
}

// xorBytes performs XOR operation on two byte slices
func (p *NonceReuseProcessor) xorBytes(a, b []byte) []byte {
	result := make([]byte, max(len(a), len(b)))
	for i := range result {
		var b1, b2 byte
		if i < len(a) {
			b1 = a[i]
		}
		if i < len(b) {
			b2 = b[i]
		}
		result[i] = b1 ^ b2
	}
	return result
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
