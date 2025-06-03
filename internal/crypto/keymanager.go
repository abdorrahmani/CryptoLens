package crypto

import (
	"crypto/rand"
	"fmt"
	"os"
)

// FileKeyManager implements key management using files
type FileKeyManager struct {
	keySize int
	keyFile string
	key     []byte
}

// NewFileKeyManager creates a new file-based key manager
func NewFileKeyManager(keySize int, keyFile string) *FileKeyManager {
	return &FileKeyManager{
		keySize: keySize,
		keyFile: keyFile,
	}
}

// LoadOrGenerateKey loads an existing key or generates a new one
func (m *FileKeyManager) LoadOrGenerateKey() error {
	// Try to load existing key
	if key, err := os.ReadFile(m.keyFile); err == nil {
		if len(key) == m.keySize/8 {
			m.key = key
			return nil
		}
	}

	// Generate new key
	key := make([]byte, m.keySize/8)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Save key to file
	if err := os.WriteFile(m.keyFile, key, 0600); err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}

	m.key = key
	return nil
}

// GetKey returns the current key
func (m *FileKeyManager) GetKey() []byte {
	return m.key
}

// SetKey sets a new key
func (m *FileKeyManager) SetKey(key []byte) error {
	if len(key) != m.keySize/8 {
		return fmt.Errorf("invalid key size: got %d bytes, want %d bytes", len(key), m.keySize/8)
	}

	if err := os.WriteFile(m.keyFile, key, 0600); err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}

	m.key = key
	return nil
}
