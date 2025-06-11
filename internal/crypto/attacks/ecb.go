package attacks

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// ECBProcessor implements the ECB mode attack simulation
type ECBProcessor struct {
	keySize int
	key     []byte
}

// NewECBProcessor creates a new ECB attack processor
func NewECBProcessor() *ECBProcessor {
	return &ECBProcessor{
		keySize: 256, // Default to AES-256
	}
}

// Configure configures the ECB processor
func (p *ECBProcessor) Configure(config map[string]interface{}) error {
	if keySize, ok := config["keySize"].(int); ok {
		switch keySize {
		case 128, 192, 256:
			p.keySize = keySize
		default:
			return fmt.Errorf("invalid key size: %d (must be 128, 192, or 256)", keySize)
		}
	}

	// Generate a random key
	p.key = make([]byte, p.keySize/8)
	if _, err := rand.Read(p.key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	return nil
}

// Process demonstrates the ECB mode pattern leakage
func (p *ECBProcessor) Process(text string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep("🔒 ECB Mode Pattern Leakage Demonstration")
	v.AddStep("=====================================")
	v.AddNote("ECB (Electronic Codebook) mode encrypts each block independently")
	v.AddNote("This leads to pattern leakage when the same plaintext blocks are encrypted")
	v.AddSeparator()

	// Show input
	v.AddTextStep("Input Text", text)
	v.AddArrow()

	// Create cipher block
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Pad the input
	paddedText := p.pad([]byte(text))
	v.AddHexStep("Padded Input", paddedText)
	v.AddArrow()

	// Show block structure with ASCII representation
	v.AddStep("Block Structure:")
	v.AddStep("Each block is 16 bytes (128 bits)")

	// Create a map to track block patterns
	blockPatterns := make(map[string][]int)

	for i := 0; i < len(paddedText); i += aes.BlockSize {
		end := i + aes.BlockSize
		if end > len(paddedText) {
			end = len(paddedText)
		}
		blockHex := fmt.Sprintf("%x", paddedText[i:end])
		blockPatterns[blockHex] = append(blockPatterns[blockHex], i/aes.BlockSize)

		// Show ASCII representation
		ascii := make([]byte, end-i)
		for j := range ascii {
			if paddedText[i+j] >= 32 && paddedText[i+j] <= 126 {
				ascii[j] = paddedText[i+j]
			} else {
				ascii[j] = '.'
			}
		}
		v.AddStep(fmt.Sprintf("Block %d: %x (%s)", i/aes.BlockSize, paddedText[i:end], string(ascii)))
	}
	v.AddArrow()

	// Encrypt each block
	encrypted := make([]byte, len(paddedText))
	encryptedPatterns := make(map[string][]int)

	for i := 0; i < len(paddedText); i += aes.BlockSize {
		end := i + aes.BlockSize
		if end > len(paddedText) {
			end = len(paddedText)
		}
		block.Encrypt(encrypted[i:end], paddedText[i:end])

		// Track encrypted block patterns
		blockHex := fmt.Sprintf("%x", encrypted[i:end])
		encryptedPatterns[blockHex] = append(encryptedPatterns[blockHex], i/aes.BlockSize)
	}

	// Show encrypted blocks with pattern detection
	v.AddStep("Encrypted Blocks:")
	for i := 0; i < len(encrypted); i += aes.BlockSize {
		end := i + aes.BlockSize
		if end > len(encrypted) {
			end = len(encrypted)
		}
		blockHex := fmt.Sprintf("%x", encrypted[i:end])
		pattern := encryptedPatterns[blockHex]

		// Check if this block has duplicates
		isDuplicate := len(pattern) > 1 && pattern[0] != i/aes.BlockSize
		duplicateNote := ""
		if isDuplicate {
			duplicateNote = " ✅ Duplicate detected!"
		}

		v.AddStep(fmt.Sprintf("Block %d: %s%s", i/aes.BlockSize, blockHex, duplicateNote))
	}
	v.AddArrow()

	// Show pattern analysis
	v.AddStep("Pattern Analysis:")
	for _, positions := range blockPatterns {
		if len(positions) > 1 {
			v.AddStep(fmt.Sprintf("• Plaintext pattern found in blocks: %v", positions))
		}
	}
	for _, positions := range encryptedPatterns {
		if len(positions) > 1 {
			v.AddStep(fmt.Sprintf("• Ciphertext pattern found in blocks: %v", positions))
		}
	}
	v.AddArrow()

	// Base64 encode the result
	encoded := base64.StdEncoding.EncodeToString(encrypted)
	v.AddTextStep("Base64 Encoded Result", encoded)

	// Add security notes
	v.AddSeparator()
	v.AddStep("⚠️ Security Implications:")
	v.AddStep("1. Same plaintext blocks produce same ciphertext blocks")
	v.AddStep("2. Patterns in plaintext are preserved in ciphertext")
	v.AddStep("3. No semantic security - attacker can identify repeated blocks")
	v.AddStep("4. No authentication - blocks can be reordered or modified")

	v.AddStep("✅ Best Practices:")
	v.AddStep("1. Use authenticated encryption modes (GCM, CCM, OCB)")
	v.AddStep("2. Use CBC mode with random IVs if AEAD is not available")
	v.AddStep("3. Never use ECB mode for encrypting data")
	v.AddStep("4. Always use unique IVs/nonces for each encryption")

	return encoded, v.GetSteps(), nil
}

// pad adds PKCS7 padding to the input
func (p *ECBProcessor) pad(data []byte) []byte {
	padding := aes.BlockSize - (len(data) % aes.BlockSize)
	padtext := make([]byte, len(data)+padding)
	copy(padtext, data)
	for i := len(data); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}
	return padtext
}
