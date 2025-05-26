package cli

import (
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/config"
	"github.com/abdorrahmani/cryptolens/internal/crypto"
)

// CryptoProcessorFactory implements ProcessorFactory for creating encryption processors
type CryptoProcessorFactory struct {
	config *config.Config
}

// NewCryptoProcessorFactory creates a new processor factory
func NewCryptoProcessorFactory() *CryptoProcessorFactory {
	return &CryptoProcessorFactory{}
}

// SetConfig sets the configuration for the factory
func (f *CryptoProcessorFactory) SetConfig(cfg *config.Config) {
	f.config = cfg
}

func (f *CryptoProcessorFactory) CreateProcessor(choice int) (crypto.Processor, error) {
	var processor crypto.ConfigurableProcessor

	switch choice {
	case 1:
		processor = crypto.NewBase64Processor()
		if f.config != nil {
			config := map[string]interface{}{
				"paddingChar": f.config.Base64.PaddingChar,
			}
			if err := processor.Configure(config); err != nil {
				return nil, fmt.Errorf("failed to configure Base64 processor: %w", err)
			}
		}
	case 2:
		processor = crypto.NewCaesarCipherProcessor()
		if f.config != nil {
			config := map[string]interface{}{
				"shift": f.config.Caesar.DefaultShift,
			}
			if err := processor.Configure(config); err != nil {
				return nil, fmt.Errorf("failed to configure Caesar cipher processor: %w", err)
			}
		}
	case 3:
		processor = crypto.NewAESProcessor()
		if f.config != nil {
			config := map[string]interface{}{
				"keySize": f.config.AES.DefaultKeySize,
				"keyFile": f.config.AES.KeyFile,
			}
			if err := processor.Configure(config); err != nil {
				return nil, fmt.Errorf("failed to configure AES processor: %w", err)
			}
		}
	case 4:
		return crypto.NewSHA256Processor(), nil
	default:
		return nil, fmt.Errorf("invalid processor choice: %d", choice)
	}

	return processor, nil
}
