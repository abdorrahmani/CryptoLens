package crypto

import (
	"encoding/base64"
)

type Base64Processor struct{}

func NewBase64Processor() *Base64Processor {
	return &Base64Processor{}
}

func (p *Base64Processor) Process(text string) (string, []string, error) {
	steps := []string{
		"Base64 encoding is a way to represent binary data using only printable ASCII characters.",
		"It works by taking 3 bytes of input and converting them into 4 bytes of output.",
		"Each output byte represents 6 bits of the input data.",
		"The encoding uses A-Z, a-z, 0-9, +, and / characters, with = for padding.",
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(text))
	steps = append(steps, "Input text converted to bytes and encoded using Base64 algorithm.")
	steps = append(steps, "Note: Base64 is not encryption - it's just an encoding scheme that can be easily reversed.")

	return encoded, steps, nil
}
