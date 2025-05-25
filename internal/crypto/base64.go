package crypto

import (
	"encoding/base64"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

type Base64Processor struct{}

func NewBase64Processor() *Base64Processor {
	return &Base64Processor{}
}

func (p *Base64Processor) Process(text string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep("Base64 Encoding Process")
	v.AddStep("=====================")
	v.AddNote("Base64 is a binary-to-text encoding scheme that represents binary data in ASCII string format")
	v.AddSeparator()

	// Show original text
	v.AddTextStep("Original Text", text)
	v.AddArrow()

	// Show ASCII values
	ascii := make([]byte, len(text))
	for i, c := range text {
		ascii[i] = byte(c)
	}
	v.AddHexStep("ASCII Values", ascii)
	v.AddArrow()

	// Show binary representation
	v.AddBinaryStep("Binary Representation", ascii)
	v.AddArrow()

	// Encode to Base64
	encoded := base64.StdEncoding.EncodeToString([]byte(text))
	v.AddTextStep("Base64 Encoded", encoded)

	// Show how it works
	v.AddSeparator()
	v.AddStep("How Base64 Works:")
	v.AddStep("1. Take 3 bytes (24 bits) of input")
	v.AddStep("2. Split into 4 groups of 6 bits")
	v.AddStep("3. Convert each 6-bit group to a character using the Base64 alphabet")
	v.AddStep("4. Add padding (=) if needed to make the output length a multiple of 4")

	// Show the Base64 alphabet
	v.AddSeparator()
	v.AddStep("Base64 Alphabet:")
	v.AddStep("A-Z (0-25), a-z (26-51), 0-9 (52-61), + (62), / (63)")
	v.AddStep("Padding character: =")

	// Add final note
	v.AddSeparator()
	v.AddNote("Base64 is not encryption - it's just an encoding scheme that can be easily reversed")

	return encoded, v.GetSteps(), nil
}
