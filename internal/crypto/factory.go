package crypto

import (
	"fmt"
)

// ProcessorFactory creates crypto processors
type ProcessorFactory struct{}

// NewProcessorFactory creates a new processor factory
func NewProcessorFactory() *ProcessorFactory {
	return &ProcessorFactory{}
}

// CreateProcessor creates a new processor based on the algorithm name
func (f *ProcessorFactory) CreateProcessor(algorithm string) (Processor, error) {
	switch algorithm {
	case "aes":
		return NewAESProcessor(), nil
	case "base64":
		return NewBase64Processor(), nil
	case "caesar":
		return NewCaesarProcessor(), nil
	case "hmac":
		return NewHMACProcessor(), nil
	case "pbkdf":
		return NewPBKDFProcessor(), nil
	case "rsa":
		return NewRSAProcessor(), nil
	case "sha256":
		return NewSHA256Processor(), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}
