package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

type AESProcessor struct {
	BaseConfigurableProcessor
	keyManager KeyManager
	keySize    int
}

func NewAESProcessor() *AESProcessor {
	return &AESProcessor{
		keySize: 256, // Default to AES-256
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
	keyFile := "aes_key.bin"
	if kf, ok := config["keyFile"].(string); ok {
		keyFile = kf
	}

	// Initialize key manager
	p.keyManager = NewFileKeyManager(p.keySize, keyFile)
	if err := p.keyManager.LoadOrGenerateKey(); err != nil {
		return fmt.Errorf("failed to load/generate key: %w", err)
	}

	return nil
}

func (p *AESProcessor) Process(text string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Check for empty input
	if text == "" {
		return "", nil, fmt.Errorf("empty input")
	}

	// Validate operation type
	if operation != OperationEncrypt && operation != OperationDecrypt {
		return "", nil, fmt.Errorf("invalid operation: %s", operation)
	}

	// Add introduction
	v.AddStep("AES Encryption Process")
	v.AddStep("=============================")
	v.AddNote("AES (Advanced Encryption Standard) is a symmetric encryption algorithm")
	v.AddNote(fmt.Sprintf("Using AES-%d in CBC mode with PKCS7 padding", p.keySize))
	v.AddSeparator()

	// Show key information
	v.AddStep("Key Information:")
	v.AddStep(fmt.Sprintf("Key Size: %d bits", p.keySize))
	v.AddStep(fmt.Sprintf("Block Size: %d bits", aes.BlockSize*8))
	v.AddStep("Mode: CBC (Cipher Block Chaining)")
	v.AddStep("Padding: PKCS7")
	v.AddSeparator()

	if operation == OperationDecrypt {
		// Add decryption steps
		v.AddStep("Decryption Process:")
		v.AddStep("1. Base64 decode the input")
		v.AddStep("2. Extract IV from the beginning")
		v.AddStep("3. Use AES-CBC to decrypt")
		v.AddStep("4. Remove PKCS7 padding")
		v.AddStep("5. Convert result to text")
		v.AddSeparator()

		// Show input
		v.AddTextStep("Encrypted Input (Base64)", text)
		v.AddArrow()

		// Decode from base64
		data, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return "", nil, fmt.Errorf("invalid base64 string: %w", err)
		}
		v.AddHexStep("Decoded Data", data)
		v.AddArrow()

		// Extract IV and ciphertext
		if len(data) < aes.BlockSize {
			return "", nil, fmt.Errorf("ciphertext too short")
		}
		iv := data[:aes.BlockSize]
		ciphertext := data[aes.BlockSize:]
		v.AddHexStep("Initialization Vector (IV)", iv)
		v.AddHexStep("Ciphertext", ciphertext)
		v.AddArrow()

		// Create cipher block
		block, err := aes.NewCipher(p.keyManager.GetKey())
		if err != nil {
			return "", nil, fmt.Errorf("failed to create cipher: %v", err)
		}
		v.AddStep("Created AES cipher block")
		v.AddArrow()

		// Decrypt
		mode := cipher.NewCBCDecrypter(block, iv)
		plaintext := make([]byte, len(ciphertext))
		mode.CryptBlocks(plaintext, ciphertext)
		v.AddHexStep("Decrypted Data (with padding)", plaintext)
		v.AddArrow()

		// Unpad
		unpadded, err := p.unpad(plaintext)
		if err != nil {
			return "", nil, fmt.Errorf("failed to unpad: %w", err)
		}
		v.AddTextStep("Decrypted Text", string(unpadded))

		// Add security notes
		v.AddSeparator()
		v.AddNote("Security Considerations:")
		v.AddNote("1. AES is a secure symmetric encryption algorithm")
		v.AddNote("2. The key must be kept secret")
		v.AddNote("3. Each encryption should use a unique IV")
		v.AddNote("4. CBC mode provides better security than ECB")

		return string(unpadded), v.GetSteps(), nil
	}

	// Add encryption steps
	v.AddStep("Encryption Process:")
	v.AddStep("1. Convert text to bytes")
	v.AddStep("2. Generate random IV")
	v.AddStep("3. Add PKCS7 padding")
	v.AddStep("4. Use AES-CBC to encrypt")
	v.AddStep("5. Combine IV and ciphertext")
	v.AddStep("6. Base64 encode the result")
	v.AddSeparator()

	// Show input
	v.AddTextStep("Input Text", text)
	v.AddArrow()

	// Create initialization vector
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", nil, fmt.Errorf("failed to generate IV: %v", err)
	}
	v.AddHexStep("Generated IV", iv)
	v.AddArrow()

	// Create cipher block
	block, err := aes.NewCipher(p.keyManager.GetKey())
	if err != nil {
		return "", nil, fmt.Errorf("failed to create cipher: %v", err)
	}
	v.AddStep("Created AES cipher block")
	v.AddArrow()

	// Pad the input
	paddedText := p.pad([]byte(text))
	v.AddHexStep("Padded Input", paddedText)
	v.AddArrow()

	// Encrypt
	ciphertext := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedText)
	v.AddHexStep("Encrypted Data", ciphertext)
	v.AddArrow()

	// Combine IV and ciphertext
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result, iv)
	copy(result[len(iv):], ciphertext)
	v.AddHexStep("Combined IV and Ciphertext", result)
	v.AddArrow()

	// Base64 encode the result
	encoded := base64.StdEncoding.EncodeToString(result)
	v.AddTextStep("Base64 Encoded Result", encoded)

	// Add security notes
	v.AddSeparator()
	v.AddNote("Security Considerations:")
	v.AddNote("1. AES is a secure symmetric encryption algorithm")
	v.AddNote("2. The key must be kept secret")
	v.AddNote("3. Each encryption uses a unique random IV")
	v.AddNote("4. CBC mode provides better security than ECB")

	// Add how it works
	v.AddSeparator()
	v.AddStep("How AES Works:")
	v.AddStep("1. Key Expansion: Generate round keys from the main key")
	v.AddStep("2. Initial Round: Add round key to the state")
	v.AddStep("3. Main Rounds (9/11/13 for 128/192/256-bit keys):")
	v.AddStep("   a. SubBytes: Replace each byte using S-box")
	v.AddStep("   b. ShiftRows: Shift rows of the state")
	v.AddStep("   c. MixColumns: Mix columns of the state")
	v.AddStep("   d. AddRoundKey: Add round key to the state")
	v.AddStep("4. Final Round (without MixColumns)")
	v.AddStep("5. CBC Mode: Each block is XORed with the previous ciphertext")

	return encoded, v.GetSteps(), nil
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

func (p *AESProcessor) unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padding := int(data[len(data)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:len(data)-padding], nil
}
