package crypto

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/abdorrahmani/cryptolens/internal/utils"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type CaesarCipherProcessor struct {
	BaseConfigurableProcessor
	shift int
}

func NewCaesarCipherProcessor() *CaesarCipherProcessor {
	return &CaesarCipherProcessor{
		shift: 3, // Classic Caesar shift of 3
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *CaesarCipherProcessor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}

	// Configure shift value if provided
	if shift, ok := config["shift"].(int); ok {
		if shift < 0 || shift > 25 {
			return fmt.Errorf("shift value must be between 0 and 25")
		}
		p.shift = shift
	}

	return nil
}

func (p *CaesarCipherProcessor) Process(text string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep(fmt.Sprintf("Caesar Cipher %s Process", cases.Title(language.English).String(operation)))
	v.AddStep("=============================")
	v.AddNote("Caesar Cipher is one of the oldest known encryption methods")
	v.AddNote(fmt.Sprintf("Using shift value: %d", p.shift))
	v.AddSeparator()

	// Show original text
	v.AddTextStep("Original Text", text)
	v.AddArrow()

	// Process each character
	var result strings.Builder
	shift := p.shift
	if operation == OperationDecrypt {
		shift = 26 - p.shift // Reverse the shift for decryption
	}

	for i, char := range text {
		if unicode.IsLetter(char) {
			base := 'a'
			if unicode.IsUpper(char) {
				base = 'A'
			}
			shifted := (int(char)-int(base)+shift)%26 + int(base)
			result.WriteRune(rune(shifted))

			// Show the transformation
			v.AddStep(fmt.Sprintf("Character %d: '%c'", i+1, char))
			v.AddStep(fmt.Sprintf("  ASCII value: %d", char))
			v.AddStep(fmt.Sprintf("  Shifted by: %d", shift))
			v.AddStep(fmt.Sprintf("  New value: %d", shifted))
			v.AddStep(fmt.Sprintf("  Result: '%c'", rune(shifted)))
			v.AddArrow()
		} else {
			result.WriteRune(char)
			v.AddStep(fmt.Sprintf("Character %d: '%c' (not a letter - kept unchanged)", i+1, char))
			v.AddArrow()
		}
	}

	// Show final result
	v.AddTextStep(fmt.Sprintf("%sed Text", cases.Title(language.English).String(operation)), result.String())

	// Show the alphabet and shift
	v.AddSeparator()
	v.AddStep("Alphabet Shift:")
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	shifted := alphabet[shift:] + alphabet[:shift]
	v.AddStep(fmt.Sprintf("Original: %s", alphabet))
	v.AddStep(fmt.Sprintf("Shifted:  %s", shifted))

	// Add security notes
	v.AddSeparator()
	v.AddNote("Security Considerations:")
	v.AddNote("1. Caesar Cipher is a simple substitution cipher")
	v.AddNote("2. Only 25 possible keys (shifts)")
	v.AddNote("3. Vulnerable to frequency analysis")
	v.AddNote("4. Not suitable for modern security needs")

	return result.String(), v.GetSteps(), nil
}
