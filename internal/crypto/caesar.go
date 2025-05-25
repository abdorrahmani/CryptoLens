package crypto

import (
	"fmt"
	"strings"
	"unicode"
)

type CaesarCipherProcessor struct {
	shift int
}

func NewCaesarCipherProcessor() *CaesarCipherProcessor {
	return &CaesarCipherProcessor{shift: 3} // Classic Caesar shift of 3
}

func (p *CaesarCipherProcessor) Process(text string) (string, []string, error) {
	steps := []string{
		"Caesar Cipher is one of the oldest known encryption methods.",
		"It works by shifting each letter in the alphabet by a fixed number of positions.",
		"In this implementation, we're using the classic shift of 3 positions.",
		"Only letters are shifted; numbers and special characters remain unchanged.",
	}

	var result strings.Builder
	for _, char := range text {
		if unicode.IsLetter(char) {
			base := 'a'
			if unicode.IsUpper(char) {
				base = 'A'
			}
			shifted := (int(char)-int(base)+p.shift)%26 + int(base)
			result.WriteRune(rune(shifted))
			steps = append(steps, fmt.Sprintf("Shifted '%c' to '%c'", char, rune(shifted)))
		} else {
			result.WriteRune(char)
			steps = append(steps, fmt.Sprintf("Kept '%c' unchanged (not a letter)", char))
		}
	}

	steps = append(steps, "Note: Caesar Cipher is a simple substitution cipher and is not secure for modern use.")
	steps = append(steps, "It can be easily broken by frequency analysis or brute force.")

	return result.String(), steps, nil
}
