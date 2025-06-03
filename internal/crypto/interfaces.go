package crypto

// Processor defines the interface for crypto processors
type Processor interface {
	// Process handles encryption/decryption/hashing
	Process(text string, operation string) (string, []string, error)
}

// ConfigurableProcessor defines the interface for configurable processors
type ConfigurableProcessor interface {
	Processor
	// Configure sets up the processor with the given configuration
	Configure(config map[string]interface{}) error
}

// KeyManager defines the interface for key management
type KeyManager interface {
	// LoadOrGenerateKey loads an existing key or generates a new one
	LoadOrGenerateKey() error
	// GetKey returns the current key
	GetKey() []byte
	// SetKey sets a new key
	SetKey(key []byte) error
}

// BaseConfigurableProcessor provides a base implementation of ConfigurableProcessor
type BaseConfigurableProcessor struct {
	config map[string]interface{}
}

// Configure implements the ConfigurableProcessor interface
func (p *BaseConfigurableProcessor) Configure(config map[string]interface{}) error {
	p.config = config
	return nil
}

// GetConfig returns the current configuration
func (p *BaseConfigurableProcessor) GetConfig() map[string]interface{} {
	return p.config
}

// Operation types
const (
	OperationEncrypt = "encrypt"
	OperationDecrypt = "decrypt"
)
