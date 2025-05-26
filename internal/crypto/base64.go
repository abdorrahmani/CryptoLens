package crypto

import (
	"encoding/base64"
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

type Base64Processor struct {
	BaseConfigurableProcessor
	paddingChar string
}

func NewBase64Processor() *Base64Processor {
	return &Base64Processor{
		paddingChar: "=", // Default padding character
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *Base64Processor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}

	// Configure padding character if provided
	if paddingChar, ok := config["paddingChar"].(string); ok {
		if len(paddingChar) != 1 {
			return fmt.Errorf("padding character must be a single character")
		}
		p.paddingChar = paddingChar
	}

	return nil
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
	v.AddStep(fmt.Sprintf("4. Add padding (%s) if needed to make the output length a multiple of 4", p.paddingChar))

	// Show the Base64 alphabet
	v.AddSeparator()
	v.AddStep("Base64 Alphabet:")
	v.AddStep("A-Z (0-25), a-z (26-51), 0-9 (52-61), + (62), / (63)")
	v.AddStep(fmt.Sprintf("Padding character: %s", p.paddingChar))

	// Add final note
	v.AddSeparator()
	v.AddNote("Base64 is not encryption - it's just an encoding scheme that can be easily reversed")

	return encoded, v.GetSteps(), nil
}
