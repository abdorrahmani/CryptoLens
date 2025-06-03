package crypto

import (
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

type CaesarProcessor struct {
	BaseConfigurableProcessor
	shift int
}

func NewCaesarProcessor() *CaesarProcessor {
	return &CaesarProcessor{
		shift: 3, // Default shift
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *CaesarProcessor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}

	// Configure shift if provided
	if shift, ok := config["shift"].(int); ok {
		p.shift = shift
	}

	return nil
}

func (p *CaesarProcessor) Process(text string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Validate operation type
	if operation != OperationEncrypt && operation != OperationDecrypt {
		return "", nil, fmt.Errorf("invalid operation: %s", operation)
	}

	// Add introduction
	v.AddStep("Caesar Cipher Process")
	v.AddStep("=============================")
	v.AddNote("Caesar cipher is a substitution cipher")
	v.AddNote(fmt.Sprintf("Using shift value of %d", p.shift))
	v.AddSeparator()

	// Show alphabet
	v.AddStep("Alphabet:")
	v.AddStep("A B C D E F G H I J K L M N O P Q R S T U V W X Y Z")
	v.AddStep("0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25")
	v.AddSeparator()

	// Process each character
	result := make([]rune, len(text))
	for i, char := range text {
		if (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') {
			var base rune
			if char >= 'a' && char <= 'z' {
				base = 'a'
			} else {
				base = 'A'
			}
			pos := int(char - base)
			if operation == OperationDecrypt {
				pos = (pos - p.shift + 26) % 26
			} else {
				pos = (pos + p.shift) % 26
			}
			result[i] = rune(int(base) + pos)

			// Show character transformation
			v.AddStep(fmt.Sprintf("Character '%c':", char))
			v.AddStep(fmt.Sprintf("  Position: %d", int(char-base)))
			if operation == OperationDecrypt {
				v.AddStep(fmt.Sprintf("  Shift: -%d", p.shift))
				v.AddStep(fmt.Sprintf("  New Position: (%d - %d + 26) %% 26 = %d", int(char-base), p.shift, pos))
			} else {
				v.AddStep(fmt.Sprintf("  Shift: +%d", p.shift))
				v.AddStep(fmt.Sprintf("  New Position: (%d + %d) %% 26 = %d", int(char-base), p.shift, pos))
			}
			v.AddStep(fmt.Sprintf("  Result: '%c'", result[i]))
			v.AddArrow()
		} else {
			result[i] = char
			v.AddStep(fmt.Sprintf("Non-alphabetic character '%c' - unchanged", char))
			v.AddArrow()
		}
	}

	// Show the result
	if operation == OperationDecrypt {
		v.AddTextStep("Decrypted Text", string(result))
	} else {
		v.AddTextStep("Encrypted Text", string(result))
	}

	// Add how it works
	v.AddSeparator()
	v.AddStep("How Caesar Cipher Works:")
	v.AddStep("1. Each letter is shifted by a fixed number of positions")
	v.AddStep("2. The shift wraps around the alphabet (Z → A)")
	v.AddStep("3. Non-alphabetic characters remain unchanged")
	v.AddStep("4. The same shift value is used for all letters")
	v.AddNote("Caesar cipher is a simple substitution cipher - it's not secure for real-world use")

	// Add security notes
	v.AddSeparator()
	v.AddNote("Security Considerations:")
	v.AddNote("1. Only 25 possible keys (shifts)")
	v.AddNote("2. Vulnerable to frequency analysis")
	v.AddNote("3. No key management - same shift for all messages")
	v.AddNote("4. Can be broken by brute force (trying all 25 shifts)")

	return string(result), v.GetSteps(), nil
}
