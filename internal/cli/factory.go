package cli

import (
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/config"
	"github.com/abdorrahmani/cryptolens/internal/crypto"
)

// ProcessorRegistry maps processor IDs to their creation functions
type ProcessorRegistry map[int]ProcessorCreator

// ProcessorCreator is a function type that creates a new processor
type ProcessorCreator func(cfg *config.Config) (crypto.Processor, error)

// CryptoProcessorFactory implements ProcessorFactory for creating encryption processors
type CryptoProcessorFactory struct {
	config   *config.Config
	registry ProcessorRegistry
}

// NewCryptoProcessorFactory creates a new processor factory
func NewCryptoProcessorFactory() *CryptoProcessorFactory {
	factory := &CryptoProcessorFactory{
		registry: make(ProcessorRegistry),
	}

	// Register default processors
	factory.RegisterProcessor(1, createBase64Processor)
	factory.RegisterProcessor(2, createCaesarProcessor)
	factory.RegisterProcessor(3, createAESProcessor)
	factory.RegisterProcessor(4, createSHA256Processor)
	factory.RegisterProcessor(5, createRSAProcessor)

	return factory
}

// RegisterProcessor registers a new processor creator function
func (f *CryptoProcessorFactory) RegisterProcessor(id int, creator ProcessorCreator) {
	f.registry[id] = creator
}

// SetConfig sets the configuration for the factory
func (f *CryptoProcessorFactory) SetConfig(cfg *config.Config) {
	f.config = cfg
}

// CreateProcessor creates a processor based on the given choice
func (f *CryptoProcessorFactory) CreateProcessor(choice int) (crypto.Processor, error) {
	creator, exists := f.registry[choice]
	if !exists {
		return nil, fmt.Errorf("invalid processor choice: %d", choice)
	}

	return creator(f.config)
}

// Processor creation functions
func createBase64Processor(cfg *config.Config) (crypto.Processor, error) {
	processor := crypto.NewBase64Processor()
	if cfg != nil {
		config := map[string]interface{}{
			"paddingChar": cfg.GetBase64Config().PaddingChar,
		}
		if err := processor.Configure(config); err != nil {
			return nil, fmt.Errorf("failed to configure Base64 processor: %w", err)
		}
	}
	return processor, nil
}

func createCaesarProcessor(cfg *config.Config) (crypto.Processor, error) {
	processor := crypto.NewCaesarCipherProcessor()
	if cfg != nil {
		config := map[string]interface{}{
			"shift": cfg.GetCaesarConfig().DefaultShift,
		}
		if err := processor.Configure(config); err != nil {
			return nil, fmt.Errorf("failed to configure Caesar cipher processor: %w", err)
		}
	}
	return processor, nil
}

func createAESProcessor(cfg *config.Config) (crypto.Processor, error) {
	processor := crypto.NewAESProcessor()
	if cfg != nil {
		config := map[string]interface{}{
			"keySize": cfg.GetAESConfig().DefaultKeySize,
			"keyFile": cfg.GetAESConfig().KeyFile,
		}
		if err := processor.Configure(config); err != nil {
			return nil, fmt.Errorf("failed to configure AES processor: %w", err)
		}
	}
	return processor, nil
}

func createSHA256Processor(cfg *config.Config) (crypto.Processor, error) {
	return crypto.NewSHA256Processor(), nil
}

func createRSAProcessor(cfg *config.Config) (crypto.Processor, error) {
	processor := crypto.NewRSAProcessor()
	if cfg != nil {
		// Ensure key size is at least 2048 bits for security
		keySize := cfg.GetRSAConfig().KeySize
		if keySize < 2048 {
			keySize = 2048
		}
		config := map[string]interface{}{
			"keySize":        keySize,
			"publicKeyFile":  cfg.GetRSAConfig().PublicKeyFile,
			"privateKeyFile": cfg.GetRSAConfig().PrivateKeyFile,
		}
		if err := processor.Configure(config); err != nil {
			return nil, fmt.Errorf("failed to configure RSA processor: %w", err)
		}
	}
	return processor, nil
}
