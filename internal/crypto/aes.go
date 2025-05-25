package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

type AESProcessor struct {
	key []byte
}

func NewAESProcessor() *AESProcessor {
	// In a real application, you would want to use a proper key derivation function
	// and store the key securely. This is just for demonstration.
	key := []byte("1234567890123456") // 16 bytes for AES-128
	return &AESProcessor{key: key}
}

func (p *AESProcessor) Process(text string) (string, []string, error) {
	steps := []string{
		"AES (Advanced Encryption Standard) is a symmetric encryption algorithm.",
		"It uses the same key for both encryption and decryption.",
		"This implementation uses AES-128 in CBC mode with PKCS7 padding.",
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
