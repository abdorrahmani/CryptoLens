package crypto

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

type CaesarCipherProcessor struct {
	shift int
}

func NewCaesarCipherProcessor() *CaesarCipherProcessor {
	return &CaesarCipherProcessor{shift: 3} // Classic Caesar shift of 3
}

func (p *CaesarCipherProcessor) Process(text string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep("Caesar Cipher Encryption Process")
	v.AddStep("=============================")
	v.AddNote("Caesar Cipher is one of the oldest known encryption methods")
	v.AddNote(fmt.Sprintf("Using shift value: %d", p.shift))
	v.AddSeparator()

	// Show original text
	v.AddTextStep("Original Text", text)
	v.AddArrow()

	// Process each character
	var result strings.Builder
	for i, char := range text {
		if unicode.IsLetter(char) {
			base := 'a'
			if unicode.IsUpper(char) {
				base = 'A'
			}
			shifted := (int(char)-int(base)+p.shift)%26 + int(base)
			result.WriteRune(rune(shifted))

			// Show the transformation
			v.AddStep(fmt.Sprintf("Character %d: '%c'", i+1, char))
			v.AddStep(fmt.Sprintf("  ASCII value: %d", char))
			v.AddStep(fmt.Sprintf("  Shifted by: %d", p.shift))
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
	v.AddTextStep("Encrypted Text", result.String())

	// Show the alphabet and shift
	v.AddSeparator()
	v.AddStep("Alphabet Shift:")
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	shifted := alphabet[p.shift:] + alphabet[:p.shift]
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
