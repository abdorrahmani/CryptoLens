package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"os"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

type HMACProcessor struct {
	BaseConfigurableProcessor
	key           []byte
	keySize       int
	keyFile       string
	hashAlgorithm string
}

func NewHMACProcessor() *HMACProcessor {
	return &HMACProcessor{
		keySize:       256,
		keyFile:       "hmac_key.bin",
		hashAlgorithm: "sha256",
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *HMACProcessor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}

	// Configure key size if provided
	if keySize, ok := config["keySize"].(int); ok {
		p.keySize = keySize
	}

	// Configure key file if provided
	if keyFile, ok := config["keyFile"].(string); ok {
		p.keyFile = keyFile
	}

	// Configure hash algorithm if provided
	if hashAlgo, ok := config["hashAlgorithm"].(string); ok {
		if hashAlgo != "" {
			if hashAlgo != "sha256" && hashAlgo != "sha512" {
				return fmt.Errorf("unsupported hash algorithm: %s (must be sha256 or sha512)", hashAlgo)
			}
			p.hashAlgorithm = hashAlgo
		}
	}

	// Load or generate key
	if err := p.loadOrGenerateKey(); err != nil {
		return fmt.Errorf("failed to load/generate key: %w", err)
	}

	return nil
}

func (p *HMACProcessor) loadOrGenerateKey() error {
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

func (p *HMACProcessor) Process(text string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep(fmt.Sprintf("HMAC-%s Process", p.hashAlgorithm))
	v.AddStep("=============================")
	v.AddNote("HMAC (Hash-based Message Authentication Code) is a specific type of message authentication code")
	v.AddNote("It involves a cryptographic hash function and a secret cryptographic key")
	v.AddNote(fmt.Sprintf("Using %s as the underlying hash function", p.hashAlgorithm))
	v.AddNote("Note: HMAC is a one-way function - the original message cannot be recovered from the HMAC value")
	v.AddSeparator()

	// Show original text
	v.AddTextStep("Original Text", text)
	v.AddArrow()

	// Show key information
	v.AddHexStep("HMAC Key", p.key)
	v.AddArrow()

	// Demonstrate key preparation
	blockSize := getBlockSize(p.hashAlgorithm)
	v.AddStep("Key Preparation:")
	v.AddStep("1. If key length > block size, hash it")
	v.AddStep("2. If key length < block size, pad with zeros")
	v.AddStep(fmt.Sprintf("Block size for %s: %d bytes", p.hashAlgorithm, blockSize))

	// Pad key to block size if needed
	paddedKey := make([]byte, blockSize)
	copy(paddedKey, p.key)
	v.AddHexStep("Padded Key", paddedKey)
	v.AddArrow()

	// Demonstrate inner padding
	v.AddStep("Inner Padding Creation:")
	v.AddStep("1. Create a block-sized buffer filled with 0x36")
	innerPad := createPadding(0x36, blockSize)
	v.AddHexStep("Inner Padding Buffer", innerPad)
	v.AddStep("2. XOR the padded key with the inner padding")
	innerKey := xorBytes(paddedKey, innerPad)
	v.AddHexStep("Inner Key (Key XOR 0x36)", innerKey)
	v.AddArrow()

	// Demonstrate outer padding
	v.AddStep("Outer Padding Creation:")
	v.AddStep("1. Create a block-sized buffer filled with 0x5c")
	outerPad := createPadding(0x5c, blockSize)
	v.AddHexStep("Outer Padding Buffer", outerPad)
	v.AddStep("2. XOR the padded key with the outer padding")
	outerKey := xorBytes(paddedKey, outerPad)
	v.AddHexStep("Outer Key (Key XOR 0x5c)", outerKey)
	v.AddArrow()

	// Create HMAC
	var h hash.Hash
	if p.hashAlgorithm == "sha256" {
		h = hmac.New(sha256.New, p.key)
	} else {
		h = hmac.New(sha512.New, p.key)
	}

	// Write the message to the HMAC
	h.Write([]byte(text))
	v.AddStep("HMAC Calculation:")
	v.AddStep("1. Hash(innerKey || message)")
	v.AddStep("2. Hash(outerKey || result)")
	v.AddArrow()

	// Get the HMAC
	hmacResult := h.Sum(nil)
	v.AddHexStep("HMAC Result", hmacResult)
	v.AddArrow()

	// Convert to hexadecimal
	hmacString := hex.EncodeToString(hmacResult)
	v.AddTextStep("Hexadecimal HMAC", hmacString)

	// Show how it works
	v.AddSeparator()
	v.AddStep("How HMAC Works:")
	v.AddStep("1. Prepare the key (if needed, pad or hash it)")
	v.AddStep("2. Create an inner padding by XORing the key with 0x36")
	v.AddStep("3. Create an outer padding by XORing the key with 0x5c")
	v.AddStep("4. Hash the inner padding concatenated with the message")
	v.AddStep("5. Hash the outer padding concatenated with the result from step 4")
	v.AddStep("6. The final hash is the HMAC value")

	// Add security notes
	v.AddSeparator()
	v.AddNote("Security Considerations:")
	v.AddNote("1. HMAC provides both data integrity and authentication")
	v.AddNote("2. The key must be kept secret and secure")
	v.AddNote("3. HMAC is resistant to length extension attacks")
	v.AddNote("4. The security depends on the underlying hash function")
	v.AddNote("5. HMAC is a one-way function - the original message cannot be recovered")

	return hmacString, v.GetSteps(), nil
}

// Helper function to get block size for hash algorithm
func getBlockSize(algorithm string) int {
	if algorithm == "sha256" {
		return 64 // SHA-256 block size
	}
	return 128 // SHA-512 block size
}

// Helper function to create padding buffer
func createPadding(value byte, size int) []byte {
	padding := make([]byte, size)
	for i := range padding {
		padding[i] = value
	}
	return padding
}

// Helper function to XOR two byte slices
func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		return nil
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}
