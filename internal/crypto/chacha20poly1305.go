package crypto

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/abdorrahmani/cryptolens/internal/utils"
	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20Poly1305Processor implements the Processor interface for ChaCha20-Poly1305 operations
type ChaCha20Poly1305Processor struct {
	BaseConfigurableProcessor
	keyManager KeyManager
	keySize    int
	nonceSize  int
	tagSize    int
}

// NewChaCha20Poly1305Processor creates a new ChaCha20-Poly1305 processor
func NewChaCha20Poly1305Processor() *ChaCha20Poly1305Processor {
	return &ChaCha20Poly1305Processor{
		keySize:   256,
		nonceSize: 12,
		tagSize:   16,
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *ChaCha20Poly1305Processor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}

	// Configure key file if provided
	keyFile := "keys/chacha20poly1305_key.bin"
	if kf, ok := config["keyFile"].(string); ok {
		keyFile = kf
	}

	// Initialize key manager
	p.keyManager = NewFileKeyManager(256, keyFile) // ChaCha20-Poly1305 uses 256-bit keys
	if err := p.keyManager.LoadOrGenerateKey(); err != nil {
		return fmt.Errorf("failed to load/generate key: %w", err)
	}

	// Configure key size if provided
	if keySize, ok := config["keySize"].(int); ok {
		if keySize != 256 {
			return fmt.Errorf("invalid key size: %d (must be 256 bits)", keySize)
		}
		p.keySize = keySize
	}

	// Configure nonce size if provided
	if nonceSize, ok := config["nonceSize"].(int); ok {
		if nonceSize != 12 {
			return fmt.Errorf("invalid nonce size: %d (must be 12 bytes)", nonceSize)
		}
		p.nonceSize = nonceSize
	}

	// Configure tag size if provided
	if tagSize, ok := config["tagSize"].(int); ok {
		if tagSize != 16 {
			return fmt.Errorf("invalid tag size: %d (must be 16 bytes)", tagSize)
		}
		p.tagSize = tagSize
	}

	return nil
}

// Process implements the Processor interface
func (p *ChaCha20Poly1305Processor) Process(text string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep("ChaCha20-Poly1305 Process")
	v.AddStep("=============================")
	v.AddNote("ChaCha20-Poly1305 is an authenticated encryption algorithm")
	v.AddNote("It combines the ChaCha20 stream cipher with the Poly1305 MAC")
	v.AddNote("Provides both confidentiality and authenticity")
	v.AddSeparator()

	if operation == OperationEncrypt {
		return p.encrypt(text, v)
	}
	return p.decrypt(text, v)
}

func (p *ChaCha20Poly1305Processor) encrypt(text string, v *utils.Visualizer) (string, []string, error) {
	// Show original text
	v.AddTextStep("Original Text", text)
	v.AddArrow()

	// Ask for key input preference
	fmt.Printf("\n%s", utils.DefaultTheme.Format("Key Management:", "brightCyan"))
	fmt.Printf("\n%s", utils.DefaultTheme.Format("1. Use existing key", "yellow"))
	fmt.Printf("\n%s", utils.DefaultTheme.Format("2. Enter custom key (32 bytes in hex)", "yellow"))
	fmt.Printf("\n%s", utils.DefaultTheme.Format("Enter your choice (1-2): ", "brightGreen"))

	var key []byte
	var err error
	choice := ""
	if input, err := bufio.NewReader(os.Stdin).ReadString('\n'); err == nil {
		choice = strings.TrimSpace(input)
	}

	if choice == "2" {
		fmt.Printf("%s", utils.DefaultTheme.Format("Enter 32-byte key in hex format: ", "brightGreen"))
		keyHex := ""
		if input, err := bufio.NewReader(os.Stdin).ReadString('\n'); err == nil {
			keyHex = strings.TrimSpace(input)
		}
		key, err = hex.DecodeString(keyHex)
		if err != nil || len(key) != 32 {
			return "", nil, fmt.Errorf("invalid key: must be 32 bytes in hex format")
		}
		v.AddNote("Using custom key")
		v.AddNote("Warning: Ensure the key is kept secure and not reused")
	} else {
		key = p.keyManager.GetKey()
		v.AddNote("Using existing key from key manager")
	}

	v.AddHexStep("Encryption Key", key)
	v.AddArrow()

	// Create ChaCha20-Poly1305 cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Ask for nonce input preference
	fmt.Printf("\n%s", utils.DefaultTheme.Format("Nonce Management:", "brightCyan"))
	fmt.Printf("\n%s", utils.DefaultTheme.Format("1. Generate random nonce", "yellow"))
	fmt.Printf("\n%s", utils.DefaultTheme.Format("2. Enter custom nonce (12 bytes in hex)", "yellow"))
	fmt.Printf("\n%s", utils.DefaultTheme.Format("Enter your choice (1-2): ", "brightGreen"))

	var nonce []byte
	choice = ""
	if input, err := bufio.NewReader(os.Stdin).ReadString('\n'); err == nil {
		choice = strings.TrimSpace(input)
	}

	if choice == "2" {
		fmt.Printf("%s", utils.DefaultTheme.Format("Enter 12-byte nonce in hex format: ", "brightGreen"))
		nonceHex := ""
		if input, err := bufio.NewReader(os.Stdin).ReadString('\n'); err == nil {
			nonceHex = strings.TrimSpace(input)
		}
		nonce, err = hex.DecodeString(nonceHex)
		if err != nil || len(nonce) != 12 {
			return "", nil, fmt.Errorf("invalid nonce: must be 12 bytes in hex format")
		}
		v.AddNote("Using custom nonce")
		v.AddNote("⚠️ WARNING: Never reuse a nonce with the same key")
		v.AddNote("⚠️ WARNING: Nonce reuse can lead to complete security failure")
		v.AddNote("⚠️ WARNING: Each encryption should use a unique nonce")
	} else {
		nonce = make([]byte, p.nonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return "", nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
		v.AddNote("Using randomly generated nonce")
		v.AddNote("The nonce is cryptographically secure and unique")
	}

	v.AddHexStep("Nonce", nonce)
	v.AddArrow()

	// Get AAD from user
	fmt.Printf("\n%s", utils.DefaultTheme.Format("Enter Additional Authenticated Data (AAD) or press Enter to skip: ", "brightGreen bold"))
	aad := ""
	if input, err := bufio.NewReader(os.Stdin).ReadString('\n'); err == nil {
		aad = strings.TrimSpace(input)
	}

	if aad != "" {
		v.AddTextStep("Additional Authenticated Data (AAD)", aad)
		v.AddNote("AAD is authenticated but not encrypted")
		v.AddNote("If AAD changes during decryption, the operation will fail")
		v.AddNote("Useful for protecting associated metadata")
		v.AddArrow()
	}

	// Measure execution time
	startTime := time.Now()
	ciphertext := aead.Seal(nil, nonce, []byte(text), []byte(aad))
	executionTime := time.Since(startTime)

	// Format execution time
	var timeStr string
	if executionTime < time.Millisecond {
		timeStr = fmt.Sprintf("%.3fµs", float64(executionTime.Nanoseconds())/1000.0)
	} else {
		timeStr = fmt.Sprintf("%.3fms", float64(executionTime.Milliseconds()))
	}
	v.AddNote(fmt.Sprintf("Encryption time: %s", timeStr))

	// Extract ciphertext and tag
	actualCiphertext := ciphertext[:len(ciphertext)-p.tagSize]
	tag := ciphertext[len(ciphertext)-p.tagSize:]

	// Show ciphertext and tag separately
	v.AddHexStep("Ciphertext (without tag)", actualCiphertext)
	v.AddArrow()
	v.AddHexStep("Authentication Tag", tag)
	v.AddArrow()

	// Combine nonce, ciphertext, and tag
	result := append(nonce, ciphertext...)

	// Show final result in different formats
	v.AddTextStep("Final Result (Hex)", hex.EncodeToString(result))
	v.AddTextStep("Final Result (Base64)", base64.StdEncoding.EncodeToString(result))

	// Add security notes
	v.AddSeparator()
	v.AddNote("Security Considerations:")
	v.AddNote("1. ChaCha20-Poly1305 provides both confidentiality and authenticity")
	v.AddNote("2. The key must be kept secret and secure")
	v.AddNote("3. The nonce must be unique for each encryption")
	v.AddNote("4. The authentication tag ensures message integrity")
	v.AddNote("5. ChaCha20-Poly1305 is resistant to timing attacks")
	if aad != "" {
		v.AddNote("6. AAD provides additional authentication for associated metadata")
		v.AddNote("7. Any change to AAD will cause decryption to fail")
	}
	if choice == "2" {
		v.AddNote("8. Using custom key - ensure it's kept secure")
		v.AddNote("9. Using custom nonce - ensure it's never reused")
	}

	return base64.StdEncoding.EncodeToString(result), v.GetSteps(), nil
}

func (p *ChaCha20Poly1305Processor) decrypt(text string, v *utils.Visualizer) (string, []string, error) {
	// Decode input
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode input: %w", err)
	}

	// Show input
	v.AddTextStep("Input (Base64)", text)
	v.AddArrow()

	// Extract nonce and ciphertext
	if len(decoded) < p.nonceSize {
		return "", nil, fmt.Errorf("input too short")
	}
	nonce := decoded[:p.nonceSize]
	ciphertext := decoded[p.nonceSize:]

	v.AddHexStep("Extracted Nonce", nonce)
	v.AddArrow()

	// Extract actual ciphertext and tag
	actualCiphertext := ciphertext[:len(ciphertext)-p.tagSize]
	tag := ciphertext[len(ciphertext)-p.tagSize:]

	v.AddHexStep("Extracted Ciphertext (without tag)", actualCiphertext)
	v.AddArrow()
	v.AddHexStep("Extracted Authentication Tag", tag)
	v.AddArrow()

	// Ask for key input preference
	fmt.Printf("\n%s", utils.DefaultTheme.Format("Key Management:", "brightCyan"))
	fmt.Printf("\n%s", utils.DefaultTheme.Format("1. Use existing key", "yellow"))
	fmt.Printf("\n%s", utils.DefaultTheme.Format("2. Enter custom key (32 bytes in hex)", "yellow"))
	fmt.Printf("\n%s", utils.DefaultTheme.Format("Enter your choice (1-2): ", "brightGreen"))

	var key []byte
	choice := ""
	if input, err := bufio.NewReader(os.Stdin).ReadString('\n'); err == nil {
		choice = strings.TrimSpace(input)
	}

	if choice == "2" {
		fmt.Printf("%s", utils.DefaultTheme.Format("Enter 32-byte key in hex format: ", "brightGreen"))
		keyHex := ""
		if input, err := bufio.NewReader(os.Stdin).ReadString('\n'); err == nil {
			keyHex = strings.TrimSpace(input)
		}
		key, err = hex.DecodeString(keyHex)
		if err != nil || len(key) != 32 {
			return "", nil, fmt.Errorf("invalid key: must be 32 bytes in hex format")
		}
		v.AddNote("Using custom key")
		v.AddNote("Warning: Ensure the key is kept secure and not reused")
	} else {
		key = p.keyManager.GetKey()
		v.AddNote("Using existing key from key manager")
	}

	v.AddHexStep("Decryption Key", key)
	v.AddArrow()

	// Get AAD from user
	fmt.Printf("\n%s", utils.DefaultTheme.Format("Enter Additional Authenticated Data (AAD) or press Enter to skip: ", "brightGreen"))
	aad := ""
	if input, err := bufio.NewReader(os.Stdin).ReadString('\n'); err == nil {
		aad = strings.TrimSpace(input)
	}

	if aad != "" {
		v.AddTextStep("Additional Authenticated Data (AAD)", aad)
		v.AddNote("AAD must match the one used during encryption")
		v.AddNote("Any change to AAD will cause decryption to fail")
		v.AddNote("This ensures the associated metadata hasn't been tampered with")
		v.AddArrow()
	}

	// Create ChaCha20-Poly1305 cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Measure execution time
	startTime := time.Now()
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(aad))
	executionTime := time.Since(startTime)

	if err != nil {
		v.AddStep("❌ Decryption Failed:")
		v.AddStep(fmt.Sprintf("Error: %v", err))
		if aad != "" {
			v.AddNote("The error might be due to:")
			v.AddNote("1. Incorrect AAD")
			v.AddNote("2. Tampered ciphertext")
			v.AddNote("3. Invalid authentication tag")
		}
		if choice == "2" {
			v.AddNote("4. Incorrect custom key")
		}
		return "", v.GetSteps(), fmt.Errorf("decryption failed: %w", err)
	}

	// Format execution time
	var timeStr string
	if executionTime < time.Millisecond {
		timeStr = fmt.Sprintf("%.3fµs", float64(executionTime.Nanoseconds())/1000.0)
	} else {
		timeStr = fmt.Sprintf("%.3fms", float64(executionTime.Milliseconds()))
	}
	v.AddNote(fmt.Sprintf("Decryption time: %s", timeStr))

	// Show decrypted text
	v.AddTextStep("Decrypted Text", string(plaintext))

	// Add security notes
	v.AddSeparator()
	v.AddNote("Security Considerations:")
	v.AddNote("1. The authentication tag is verified during decryption")
	v.AddNote("2. If the tag is invalid, decryption fails")
	v.AddNote("3. This ensures both confidentiality and authenticity")
	v.AddNote("4. The key must be kept secret and secure")
	v.AddNote("5. The nonce must match the one used during encryption")
	if aad != "" {
		v.AddNote("6. AAD provides additional authentication for associated metadata")
		v.AddNote("7. Any change to AAD will cause decryption to fail")
	}
	if choice == "2" {
		v.AddNote("8. Using custom key - ensure it's kept secure")
		v.AddNote("9. Using custom nonce - ensure it's never reused")
	}

	return string(plaintext), v.GetSteps(), nil
}
