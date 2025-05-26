package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

type AESProcessor struct {
	BaseConfigurableProcessor
	key     []byte
	keySize int
	keyFile string
}

func NewAESProcessor() *AESProcessor {
	return &AESProcessor{
		keySize: 256, // Default to AES-256
		keyFile: "aes_key.bin",
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *AESProcessor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}

	// Configure key size if provided
	if keySize, ok := config["keySize"].(int); ok {
		switch keySize {
		case 128, 192, 256:
			p.keySize = keySize
		default:
			return fmt.Errorf("invalid key size: %d (must be 128, 192, or 256)", keySize)
		}
	}

	// Configure key file if provided
	if keyFile, ok := config["keyFile"].(string); ok {
		p.keyFile = keyFile
	}

	// Load or generate key
	if err := p.loadOrGenerateKey(); err != nil {
		return fmt.Errorf("failed to load/generate key: %w", err)
	}

	return nil
}

func (p *AESProcessor) loadOrGenerateKey() error {
	// Try to load existing key
	if key, err := os.ReadFile(p.keyFile); err == nil {
		if len(key) == p.keySize/8 {
			p.key = key
			return nil
		}
	}

	// Generate new key
	key := make([]byte, p.keySize/8)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Save key to file
	if err := os.WriteFile(p.keyFile, key, 0600); err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}

	p.key = key
	return nil
}

func (p *AESProcessor) Process(text string) (string, []string, error) {
	steps := []string{
		"AES (Advanced Encryption Standard) is a symmetric encryption algorithm.",
		"It uses the same key for both encryption and decryption.",
		fmt.Sprintf("This implementation uses AES-%d in CBC mode with PKCS7 padding.", p.keySize),
		"The process involves:",
		"1. Generating a random initialization vector (IV)",
		"2. Padding the data to match the block size",
		"3. Encrypting the data using the key and IV",
		"4. Combining the IV and encrypted data",
	}

	// Create cipher block
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	// Create initialization vector
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", nil, fmt.Errorf("failed to generate IV: %v", err)
	}

	// Pad the input
	paddedText := p.pad([]byte(text))
	steps = append(steps, fmt.Sprintf("Padded input to %d bytes", len(paddedText)))

	// Encrypt
	ciphertext := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedText)

	// Combine IV and ciphertext
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result, iv)
	copy(result[len(iv):], ciphertext)

	// Base64 encode the result
	encoded := base64.StdEncoding.EncodeToString(result)
	steps = append(steps, "Combined IV and encrypted data")
	steps = append(steps, "Base64 encoded the result for safe transmission")
	steps = append(steps, "Note: AES is a secure encryption algorithm when used properly with a strong key")

	return encoded, steps, nil
}

func (p *AESProcessor) pad(data []byte) []byte {
	padding := aes.BlockSize - (len(data) % aes.BlockSize)
	padtext := make([]byte, len(data)+padding)
	copy(padtext, data)
	for i := len(data); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}
	return padtext
}
