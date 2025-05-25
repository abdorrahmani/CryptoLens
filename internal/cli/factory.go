package cli

import (
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/crypto"
)

// CryptoProcessorFactory implements ProcessorFactory for creating encryption processors
type CryptoProcessorFactory struct{}

// NewCryptoProcessorFactory creates a new processor factory
func NewCryptoProcessorFactory() *CryptoProcessorFactory {
	return &CryptoProcessorFactory{}
}

func (f *CryptoProcessorFactory) CreateProcessor(choice int) (crypto.Processor, error) {
	switch choice {
	case 1:
		return crypto.NewBase64Processor(), nil
	case 2:
		return crypto.NewCaesarCipherProcessor(), nil
	case 3:
		return crypto.NewAESProcessor(), nil
	case 4:
		return crypto.NewSHA256Processor(), nil
	default:
		return nil, fmt.Errorf("invalid processor choice: %d", choice)
	}
}
