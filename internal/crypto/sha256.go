package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type SHA256Processor struct{}

func NewSHA256Processor() *SHA256Processor {
	return &SHA256Processor{}
}

func (p *SHA256Processor) Process(text string) (string, []string, error) {
	steps := []string{
		"SHA-256 is a cryptographic hash function that produces a 256-bit (32-byte) hash value.",
		"It is a one-way function, meaning it cannot be reversed to recover the original input.",
		"The process involves:",
		"1. Converting the input text to bytes",
		"2. Processing the bytes through the SHA-256 algorithm",
		"3. Converting the resulting hash to a hexadecimal string",
	}

	// Create a new SHA-256 hash
	hash := sha256.New()

	// Write the input text to the hash
	hash.Write([]byte(text))
	steps = append(steps, fmt.Sprintf("Processed %d bytes of input", len(text)))

	// Get the final hash
	hashBytes := hash.Sum(nil)
	steps = append(steps, fmt.Sprintf("Generated 32-byte (256-bit) hash"))

	// Convert to hexadecimal
	hashString := hex.EncodeToString(hashBytes)
	steps = append(steps, "Converted hash to hexadecimal string")
	steps = append(steps, "Note: SHA-256 is a one-way hash function - the original text cannot be recovered from the hash")

	return hashString, steps, nil
}
