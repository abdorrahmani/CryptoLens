package crypto

import (
	"fmt"
	"strings"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// plainAlphabet is the reference A–Z used for the substitution table.
const plainAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// maxDetailedChars caps how many per-character transformations are spelled out
// so long inputs don't flood the view; the rest are summarized.
const maxDetailedChars = 12

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

	// Normalize the shift into [0,25]. The requested shift may be negative or
	// larger than the alphabet; only its value modulo 26 changes the output.
	encShift := ((p.shift % 26) + 26) % 26

	// The shift actually applied for THIS operation: encrypting shifts forward,
	// decrypting shifts back (which is a forward shift of 26-encShift).
	opShift := encShift
	if operation == OperationDecrypt {
		opShift = (26 - encShift) % 26
	}

	addCaesarIntro(v, operation, p.shift, encShift)
	addSubstitutionTable(v, operation, opShift)

	result := applyCaesar(text, opShift)
	addCharacterWalkthrough(v, text, operation, opShift)

	v.AddArrow()
	if operation == OperationDecrypt {
		v.AddTextStep("Decrypted Text", result)
	} else {
		v.AddTextStep("Encrypted Text", result)
	}

	// Cryptanalysis: demonstrate why the cipher is trivially breakable by
	// listing every possible shift of the ciphertext involved.
	cipherText := result
	if operation == OperationDecrypt {
		cipherText = text
	}
	addBruteForceSection(v, cipherText, encShift)

	addCaesarKeyFacts(v)
	return result, v.GetSteps(), nil
}

// --- explanatory sections --------------------------------------------------

func addCaesarIntro(v *utils.Visualizer, operation string, requested, encShift int) {
	v.AddStep("📌 What is the Caesar cipher?")
	v.AddStep("One of the oldest known ciphers, named after Julius Caesar, who used it to")
	v.AddStep("protect military messages. It is a MONOALPHABETIC SUBSTITUTION cipher: every")
	v.AddStep("letter is replaced by the letter a fixed number of positions further along")
	v.AddStep("the alphabet, wrapping around from Z back to A.")
	v.AddSeparator()

	v.AddStep("🔢 The key: a single shift value")
	v.AddStep(fmt.Sprintf("Requested shift: %d", requested))
	if requested != encShift {
		v.AddStep(fmt.Sprintf("Only the shift modulo 26 matters, so this is equivalent to a shift of %d.", encShift))
	}
	if encShift == 13 {
		v.AddNote("A shift of 13 is the special case ROT13: applying it twice returns the")
		v.AddNote("original text, so the same operation both encodes and decodes.")
	}
	if encShift == 0 {
		v.AddNote("A shift of 0 leaves the text unchanged — no encryption happens.")
	}
	v.AddSeparator()

	v.AddStep("📈 The formula")
	v.AddStep("Number each letter A=0, B=1, … Z=25. Then:")
	v.AddStep("  Encrypt:  C = (P + shift) mod 26")
	v.AddStep("  Decrypt:  P = (C − shift + 26) mod 26")
	v.AddStep("The '+26' and 'mod 26' keep the result inside 0–25 (the alphabet wrap-around).")
	if operation == OperationDecrypt {
		v.AddNote("Decrypting with shift k is the same as encrypting with shift (26 − k).")
	}
	v.AddSeparator()
}

// addSubstitutionTable shows the full plaintext→ciphertext letter mapping — the
// substitution table that defines the cipher for this shift.
func addSubstitutionTable(v *utils.Visualizer, operation string, opShift int) {
	shifted := shiftAlphabet(opShift)

	v.AddStep("🔢 Substitution table for this shift")
	if operation == OperationDecrypt {
		v.AddStep("Cipher letter → plaintext letter:")
		v.AddStep("  Cipher: " + spaced(plainAlphabet))
		v.AddStep("  Plain:  " + spaced(shifted))
	} else {
		v.AddStep("Plaintext letter → cipher letter:")
		v.AddStep("  Plain:  " + spaced(plainAlphabet))
		v.AddStep("  Cipher: " + spaced(shifted))
	}
	v.AddNote("Every occurrence of a letter maps to the same replacement — that fixed")
	v.AddNote("mapping is exactly what frequency analysis exploits to break the cipher.")
	v.AddSeparator()
}

// addCharacterWalkthrough spells out the transformation for each letter, capped
// so long inputs stay readable.
func addCharacterWalkthrough(v *utils.Visualizer, text, operation string, opShift int) {
	v.AddStep("📈 Character-by-character transformation")

	detailed := 0
	skipped := 0
	for _, char := range text {
		base, ok := letterBase(char)
		if !ok {
			if detailed < maxDetailedChars {
				v.AddStep(fmt.Sprintf("'%c' → '%c'  (non-letter, unchanged)", char, char))
			}
			continue
		}

		pos := int(char - base)
		newPos := (pos + opShift) % 26
		out := rune(int(base) + newPos)

		if detailed >= maxDetailedChars {
			skipped++
			continue
		}
		detailed++

		sign := "+"
		disp := opShift
		if operation == OperationDecrypt {
			// Present decryption as subtraction of the user's key for clarity.
			sign = "−"
			disp = 26 - opShift
			if disp == 26 {
				disp = 0
			}
			v.AddStep(fmt.Sprintf("'%c' (pos %2d) → (%d %s %d + 26) mod 26 = %2d → '%c'",
				char, pos, pos, sign, disp, newPos, out))
		} else {
			v.AddStep(fmt.Sprintf("'%c' (pos %2d) → (%d %s %d) mod 26 = %2d → '%c'",
				char, pos, pos, sign, disp, newPos, out))
		}
	}
	if skipped > 0 {
		v.AddNote(fmt.Sprintf("… and %d more letter(s) transformed the same way (hidden for brevity).", skipped))
	}
	v.AddSeparator()
}

// addBruteForceSection lists every shift of the ciphertext, driving home that a
// 25-key space is broken by simply trying them all.
func addBruteForceSection(v *utils.Visualizer, cipherText string, encShift int) {
	v.AddSeparator()
	v.AddStep("🔒 Cryptanalysis: brute-forcing all 25 shifts")
	v.AddStep("Because there are only 25 usable keys, an attacker can just try them all")
	v.AddStep("and read whichever result makes sense. Here is that attack on the ciphertext:")

	preview := cipherText
	const maxPreview = 40
	truncated := false
	if len(preview) > maxPreview {
		preview = preview[:maxPreview]
		truncated = true
	}

	for s := 1; s < 26; s++ {
		// Decrypt attempt = shift the ciphertext back by s (forward by 26-s).
		guess := applyCaesar(preview, (26-s)%26)
		marker := ""
		if s == encShift {
			marker = "  ← the real key"
		}
		line := fmt.Sprintf("  shift %2d: %s", s, guess)
		if truncated {
			line += "…"
		}
		v.AddStep(line + marker)
	}
	v.AddNote("A computer scans all 25 in microseconds; even by hand it takes seconds.")
	v.AddSeparator()
}

func addCaesarKeyFacts(v *utils.Visualizer) {
	v.AddStep("📚 Key facts & security")
	v.AddStep("• Key space is tiny: only 25 non-trivial shifts, so brute force is instant.")
	v.AddStep("• Letter frequencies survive the substitution, so frequency analysis reveals")
	v.AddStep("  the shift without even brute-forcing (E is the most common English letter).")
	v.AddStep("• The same letter always maps to the same output — no diffusion, no key schedule.")
	v.AddStep("• Historical/educational only. The Vigenère cipher (a shifting Caesar) was the")
	v.AddStep("  next step; modern security uses AES or ChaCha20 (see menu options 3 and 11).")
	v.AddNote("Never use the Caesar cipher to protect real data — treat it purely as a learning tool.")
}

// --- core transform & helpers ----------------------------------------------

// applyCaesar shifts every letter of text forward by opShift (0–25), preserving
// case and leaving non-letters untouched.
func applyCaesar(text string, opShift int) string {
	out := make([]rune, 0, len(text))
	for _, char := range text {
		if base, ok := letterBase(char); ok {
			pos := (int(char-base) + opShift) % 26
			out = append(out, rune(int(base)+pos))
		} else {
			out = append(out, char)
		}
	}
	return string(out)
}

// letterBase returns the case base ('A' or 'a') for an ASCII letter and whether
// the rune is such a letter.
func letterBase(char rune) (rune, bool) {
	switch {
	case char >= 'A' && char <= 'Z':
		return 'A', true
	case char >= 'a' && char <= 'z':
		return 'a', true
	default:
		return 0, false
	}
}

// shiftAlphabet returns A–Z rotated left by opShift (the cipher alphabet).
func shiftAlphabet(opShift int) string {
	var b strings.Builder
	for i := 0; i < 26; i++ {
		b.WriteByte(plainAlphabet[(i+opShift)%26])
	}
	return b.String()
}

// spaced inserts a space between characters for a readable alphabet row.
func spaced(s string) string {
	return strings.Join(strings.Split(s, ""), " ")
}
