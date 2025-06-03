package crypto

import (
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/utils"
	"golang.org/x/text/unicode/norm"
)

type VigenereProcessor struct {
	BaseConfigurableProcessor
	key string
}

func NewVigenereProcessor() *VigenereProcessor {
	return &VigenereProcessor{
		key: "KEY",
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *VigenereProcessor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}
	if key, ok := config["key"].(string); ok {
		if key == "" {
			return fmt.Errorf("key cannot be empty")
		}
		// Normalize the key
		key = norm.NFC.String(key)
		for _, c := range key {
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
				return fmt.Errorf("key must be alphabetic only")
			}
		}
		p.key = key
	}
	return nil
}

// Process handles encryption/decryption
func (p *VigenereProcessor) Process(text string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

	v.AddStep("Vigenère Cipher Process")
	v.AddStep("=============================")
	v.AddNote("Vigenère cipher is a polyalphabetic substitution cipher")
	v.AddNote(fmt.Sprintf("Using key: %s", p.key))
	v.AddSeparator()

	if p.key == "" {
		return "", nil, fmt.Errorf("key is not set")
	}

	// Normalize the input text
	text = norm.NFC.String(text)

	key := p.key
	keyLen := len(key)
	if keyLen == 0 {
		return "", nil, fmt.Errorf("key is empty")
	}

	result := make([]rune, len(text))
	keyIndex := 0
	for i, char := range text {
		if (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') {
			keyChar := rune(key[keyIndex%keyLen])
			var k int
			if keyChar >= 'a' && keyChar <= 'z' {
				k = int(keyChar - 'a')
			} else {
				k = int(keyChar - 'A')
			}
			var base rune
			if char >= 'a' && char <= 'z' {
				base = 'a'
			} else {
				base = 'A'
			}
			if operation == OperationDecrypt {
				shifted := (int(char-base)-k+26)%26 + int(base)
				result[i] = rune(shifted)
				v.AddStep(fmt.Sprintf("Decrypt '%c' with key '%c' (shift %d): '%c'", char, keyChar, k, result[i]))
			} else if operation == OperationEncrypt {
				shifted := (int(char-base)+k)%26 + int(base)
				result[i] = rune(shifted)
				v.AddStep(fmt.Sprintf("Encrypt '%c' with key '%c' (shift %d): '%c'", char, keyChar, k, result[i]))
			} else {
				return "", nil, fmt.Errorf("invalid operation: %s", operation)
			}
			keyIndex++
			v.AddArrow()
		} else {
			result[i] = char
			v.AddStep(fmt.Sprintf("Non-alphabetic character '%c' - unchanged", char))
			v.AddArrow()
		}
	}

	// Normalize the result
	resultStr := norm.NFC.String(string(result))

	if operation == OperationDecrypt {
		v.AddTextStep("Decrypted Text", resultStr)
	} else if operation == OperationEncrypt {
		v.AddTextStep("Encrypted Text", resultStr)
	}

	v.AddSeparator()
	v.AddStep("How Vigenère Cipher Works:")
	v.AddStep("1. Each letter is shifted by the corresponding key letter's position (A=0, B=1, ...)")
	v.AddStep("2. The key repeats as needed to match the text length")
	v.AddStep("3. Non-alphabetic characters remain unchanged")
	v.AddStep("4. Encryption and decryption use modular arithmetic on the alphabet")
	v.AddNote("Vigenère cipher is stronger than Caesar but still vulnerable to frequency analysis for short keys")

	v.AddSeparator()
	v.AddNote("Security Considerations:")
	v.AddNote("1. Key should be as long and random as possible")
	v.AddNote("2. Repeated keys make the cipher vulnerable to Kasiski examination and frequency analysis")
	v.AddNote("3. Not secure for modern use; use strong symmetric ciphers for real security")

	return resultStr, v.GetSteps(), nil
}
