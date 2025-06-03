package crypto

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

type SHA256Processor struct {
	BaseConfigurableProcessor
}

func NewSHA256Processor() *SHA256Processor {
	return &SHA256Processor{}
}

// Configure implements the ConfigurableProcessor interface
func (p *SHA256Processor) Configure(config map[string]interface{}) error {
	return p.BaseConfigurableProcessor.Configure(config)
}

func (p *SHA256Processor) Process(text string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep("SHA-256 Hash Process")
	v.AddStep("=============================")
	v.AddNote("SHA-256 is a cryptographic hash function")
	v.AddNote("It produces a 256-bit (32-byte) hash value")
	v.AddSeparator()

	// Show input
	v.AddTextStep("Input Text", text)
	v.AddArrow()

	// Show binary representation
	v.AddBinaryStep("Text as Binary", []byte(text))
	v.AddArrow()

	// Calculate hash
	hash := sha256.Sum256([]byte(text))

	// Show hash in different formats
	v.AddHexStep("SHA-256 Hash (Hex)", hash[:])
	v.AddBinaryStep("SHA-256 Hash (Binary)", hash[:])
	v.AddArrow()

	// Base64 encode the result
	encoded := base64.StdEncoding.EncodeToString(hash[:])
	v.AddTextStep("Base64 Encoded Hash", encoded)

	// Add how it works
	v.AddSeparator()
	v.AddStep("How SHA-256 Works:")
	v.AddStep("1. Message Padding:")
	v.AddStep("   - Add a single '1' bit")
	v.AddStep("   - Add '0' bits until message length is 448 bits (mod 512)")
	v.AddStep("   - Add 64-bit message length")
	v.AddStep("2. Message Schedule:")
	v.AddStep("   - Break padded message into 512-bit blocks")
	v.AddStep("   - Create 64 32-bit words from each block")
	v.AddStep("3. Compression Function:")
	v.AddStep("   - Initialize 8 32-bit working variables")
	v.AddStep("   - Process each block through 64 rounds")
	v.AddStep("   - Each round uses different constants and operations")
	v.AddStep("4. Final Hash:")
	v.AddStep("   - Combine working variables into 256-bit hash")
	v.AddStep("   - Result is 32 bytes (64 hexadecimal characters)")

	// Add security notes
	v.AddSeparator()
	v.AddNote("Security Considerations:")
	v.AddNote("1. SHA-256 is a one-way function - cannot be reversed")
	v.AddNote("2. Any change in input produces a completely different hash")
	v.AddNote("3. Same input always produces the same hash")
	v.AddNote("4. Collision resistance: hard to find two inputs with same hash")
	v.AddNote("5. Pre-image resistance: hard to find input for a given hash")

	// Add technical details
	v.AddSeparator()
	v.AddStep("Technical Details:")
	v.AddStep("• Block Size: 512 bits")
	v.AddStep("• Word Size: 32 bits")
	v.AddStep("• Message Digest Size: 256 bits")
	v.AddStep("• Number of Rounds: 64")
	v.AddStep("• Operations: AND, OR, NOT, XOR, ADD, ROTATE")
	v.AddStep("• Constants: 64 different 32-bit values")

	return encoded, v.GetSteps(), nil
}
