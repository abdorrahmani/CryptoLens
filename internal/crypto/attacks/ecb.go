package attacks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// ECBProcessor implements the ECB mode attack simulation
type ECBProcessor struct {
	*BaseProcessor
	config *AttackConfig
}

// NewECBProcessor creates a new ECB attack processor
func NewECBProcessor() *ECBProcessor {
	return &ECBProcessor{
		BaseProcessor: NewBaseProcessor(),
		config:        NewAttackConfig(),
	}
}

// Configure configures the ECB processor
func (p *ECBProcessor) Configure(config map[string]interface{}) error {
	if keySize, ok := config["keySize"].(int); ok {
		switch keySize {
		case 128, 192, 256:
			p.config.KeySize = keySize
		default:
			return fmt.Errorf("invalid key size: %d (must be 128, 192, or 256)", keySize)
		}
	}

	// Generate a random key
	p.config.Key = make([]byte, p.config.KeySize/8)
	if _, err := rand.Read(p.config.Key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	return nil
}

// Process demonstrates the ECB mode pattern leakage
func (p *ECBProcessor) Process(text string, operation string) (string, []string, error) {
	p.addIntroduction()

	// Create cipher block
	block, err := aes.NewCipher(p.config.Key)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Pad and encrypt
	paddedText := p.pad([]byte(text))
	p.addInputInfo(text, paddedText)

	// Encrypt blocks
	encrypted := p.encryptBlocks(block, paddedText)

	// Analyze patterns
	p.analyzePatterns(paddedText, encrypted)

	// Add security notes
	p.addSecurityImplications()

	return base64.StdEncoding.EncodeToString(encrypted), p.GetSteps(), nil
}

func (p *ECBProcessor) addIntroduction() {
	p.AddStep("🔒 ECB Mode Pattern Leakage Demonstration")
	p.AddStep("=====================================")
	p.AddNote("ECB (Electronic Codebook) mode encrypts each block independently")
	p.AddNote("This leads to pattern leakage when the same plaintext blocks are encrypted")
	p.AddSeparator()
}

func (p *ECBProcessor) addInputInfo(text string, paddedText []byte) {
	p.AddTextStep("Input Text", text)
	p.AddArrow()
	p.AddHexStep("Padded Input", paddedText)
	p.AddArrow()

	// Show block structure
	p.AddStep("Block Structure:")
	p.AddStep("Each block is 16 bytes (128 bits)")

	// Show ASCII representation of blocks
	for i := 0; i < len(paddedText); i += aes.BlockSize {
		end := i + aes.BlockSize
		if end > len(paddedText) {
			end = len(paddedText)
		}
		ascii := make([]byte, end-i)
		for j := range ascii {
			if paddedText[i+j] >= 32 && paddedText[i+j] <= 126 {
				ascii[j] = paddedText[i+j]
			} else {
				ascii[j] = '.'
			}
		}
		p.AddStep(fmt.Sprintf("Block %d: %x (%s)", i/aes.BlockSize, paddedText[i:end], string(ascii)))
	}
	p.AddArrow()
}

func (p *ECBProcessor) encryptBlocks(block cipher.Block, paddedText []byte) []byte {
	encrypted := make([]byte, len(paddedText))
	for i := 0; i < len(paddedText); i += aes.BlockSize {
		end := i + aes.BlockSize
		if end > len(paddedText) {
			end = len(paddedText)
		}
		block.Encrypt(encrypted[i:end], paddedText[i:end])
	}
	return encrypted
}

func (p *ECBProcessor) analyzePatterns(paddedText, encrypted []byte) {
	// Track block patterns
	blockPatterns := make(map[string][]int)
	encryptedPatterns := make(map[string][]int)

	// Analyze plaintext patterns
	for i := 0; i < len(paddedText); i += aes.BlockSize {
		end := i + aes.BlockSize
		if end > len(paddedText) {
			end = len(paddedText)
		}
		blockHex := fmt.Sprintf("%x", paddedText[i:end])
		blockPatterns[blockHex] = append(blockPatterns[blockHex], i/aes.BlockSize)
	}

	// Analyze encrypted patterns
	for i := 0; i < len(encrypted); i += aes.BlockSize {
		end := i + aes.BlockSize
		if end > len(encrypted) {
			end = len(encrypted)
		}
		blockHex := fmt.Sprintf("%x", encrypted[i:end])
		encryptedPatterns[blockHex] = append(encryptedPatterns[blockHex], i/aes.BlockSize)
	}

	// Show encrypted blocks with pattern detection
	p.AddStep("Encrypted Blocks:")
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

		p.AddStep(fmt.Sprintf("Block %d: %s%s", i/aes.BlockSize, blockHex, duplicateNote))
	}
	p.AddArrow()

	// Show pattern analysis
	p.AddStep("Pattern Analysis:")
	for _, positions := range blockPatterns {
		if len(positions) > 1 {
			p.AddStep(fmt.Sprintf("• Plaintext pattern found in blocks: %v", positions))
		}
	}
	for _, positions := range encryptedPatterns {
		if len(positions) > 1 {
			p.AddStep(fmt.Sprintf("• Ciphertext pattern found in blocks: %v", positions))
		}
	}
	p.AddArrow()
}

func (p *ECBProcessor) addSecurityImplications() {
	p.AddSeparator()
	p.AddStep("⚠️ Security Implications:")
	p.AddStep("1. Same plaintext blocks produce same ciphertext blocks")
	p.AddStep("2. Patterns in plaintext are preserved in ciphertext")
	p.AddStep("3. No semantic security - attacker can identify repeated blocks")
	p.AddStep("4. No authentication - blocks can be reordered or modified")

	p.AddStep("✅ Best Practices:")
	p.AddStep("1. Use authenticated encryption modes (GCM, CCM, OCB)")
	p.AddStep("2. Use CBC mode with random IVs if AEAD is not available")
	p.AddStep("3. Never use ECB mode for encrypting data")
	p.AddStep("4. Always use unique IVs/nonces for each encryption")
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
