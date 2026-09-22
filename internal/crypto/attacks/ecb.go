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
	p.AddNote("ECB (Electronic Codebook) is the naive way to use a block cipher: chop the")
	p.AddNote("message into 16-byte blocks and encrypt each one independently.")
	p.AddSeparator()

	p.AddStep("📈 Why ECB leaks")
	p.AddStep("With no IV and no chaining, ECB is DETERMINISTIC: the same plaintext block always")
	p.AddStep("produces the same ciphertext block, under the same key. So structure in the input")
	p.AddStep("survives into the output — an attacker sees which blocks repeat and where.")
	p.AddNote("The famous 'ECB penguin': encrypting a bitmap with ECB still shows the penguin,")
	p.AddNote("because identical pixel blocks map to identical ciphertext blocks.")
	p.AddSeparator()
	p.AddNote("Tip: enter a message with a repeated 16-byte block (e.g. \"YELLOW SUBMARINEYELLOW SUBMARINE\") to see identical ciphertext blocks below.")
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
	p.AddStep("1. Same plaintext blocks produce same ciphertext blocks (no semantic security).")
	p.AddStep("2. An attacker learns equality/structure without decrypting anything.")
	p.AddStep("3. Blocks can be cut, pasted, or reordered undetected (no authentication).")
	p.AddStep("4. Known-plaintext lets an attacker build a codebook of block→ciphertext.")

	p.AddSeparator()
	p.AddStep("✅ Prevention & Solutions")
	p.AddStep("The root cause is determinism with no per-message randomness and no integrity.")
	p.AddStep("1. Prefer an AEAD mode: AES-GCM or ChaCha20-Poly1305 (menu 11) — encrypts AND")
	p.AddStep("   authenticates, with a unique nonce per message so identical data differs.")
	p.AddStep("2. If you must use CBC (menu 3), use a fresh random IV per message and add a")
	p.AddStep("   separate MAC (encrypt-then-MAC) for integrity.")
	p.AddStep("3. Never use ECB for anything but a single block of already-random data.")
	p.AddStep("4. Always make encryption non-deterministic via an IV/nonce.")
	p.AddNote("Compare with the AES walkthrough (menu 3): CBC chaining is exactly what stops the")
	p.AddNote("pattern leakage you see above.")
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
