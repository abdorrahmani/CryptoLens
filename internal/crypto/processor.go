package crypto

// Processor defines the interface for all encryption/encoding methods
type Processor interface {
	// Process takes input text and returns the processed result and step-by-step explanation
	Process(text string) (string, []string, error)
}
