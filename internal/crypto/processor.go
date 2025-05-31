package crypto

// Processor defines the base interface for all encryption/encoding methods
type Processor interface {
	// Process takes input text and returns the processed result and step-by-step explanation
	Process(text string, operation string) (string, []string, error)
}

// ConfigurableProcessor extends the Processor interface with configuration capabilities
type ConfigurableProcessor interface {
	Processor
	// Configure applies configuration settings to the processor
	Configure(config map[string]interface{}) error
}

// KeyManager defines the interface for key management operations
type KeyManager interface {
	// LoadKey loads an existing key
	LoadKey() error
	// GenerateKey generates a new key
	GenerateKey() error
	// SaveKey saves the current key
	SaveKey() error
}

// BaseConfigurableProcessor provides a base implementation for configurable processors
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
