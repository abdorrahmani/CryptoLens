package crypto

import (
	"encoding/base64"
	"fmt"
	"strings"

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

func (p *Base64Processor) Process(text string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep(fmt.Sprintf("Base64 %s Process", strings.Title(operation)))
	v.AddStep("=====================")
	v.AddNote("Base64 is a binary-to-text encoding scheme that represents binary data in ASCII string format")
	v.AddSeparator()

	if operation == OperationEncrypt {
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

		return encoded, v.GetSteps(), nil
	} else {
		// Show encoded text
		v.AddTextStep("Base64 Encoded Text", text)
		v.AddArrow()

		// Decode from Base64
		decoded, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return "", nil, fmt.Errorf("invalid base64 string: %w", err)
		}

		// Show ASCII values
		v.AddHexStep("ASCII Values", decoded)
		v.AddArrow()

		// Show binary representation
		v.AddBinaryStep("Binary Representation", decoded)
		v.AddArrow()

		// Show decoded text
		v.AddTextStep("Decoded Text", string(decoded))

		// Show how it works
		v.AddSeparator()
		v.AddStep("How Base64 Decoding Works:")
		v.AddStep("1. Take 4 characters from the input")
		v.AddStep("2. Convert each character back to its 6-bit value")
		v.AddStep("3. Combine the 6-bit values into 3 bytes")
		v.AddStep("4. Remove padding if present")

		return string(decoded), v.GetSteps(), nil
	}
}
