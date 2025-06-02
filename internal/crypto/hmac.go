package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"os"

	"github.com/abdorrahmani/cryptolens/internal/utils"
	"golang.org/x/crypto/blake2b"
)

// Available hash algorithms
const (
	HashSHA1       = "sha1"
	HashSHA256     = "sha256"
	HashSHA512     = "sha512"
	HashBLAKE2b256 = "blake2b-256"
	HashBLAKE2b512 = "blake2b-512"
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
		hashAlgorithm: HashSHA256,
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
			switch hashAlgo {
			case HashSHA1, HashSHA256, HashSHA512, HashBLAKE2b256, HashBLAKE2b512:
				p.hashAlgorithm = hashAlgo
			default:
				return fmt.Errorf("unsupported hash algorithm: %s (must be one of: sha1, sha256, sha512, blake2b-256, blake2b-512)", hashAlgo)
			}
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

// getHashFunction returns the appropriate hash function for the selected algorithm
func (p *HMACProcessor) getHashFunction() (func() hash.Hash, error) {
	switch p.hashAlgorithm {
	case HashSHA1:
		return sha1.New, nil
	case HashSHA256:
		return sha256.New, nil
	case HashSHA512:
		return sha512.New, nil
	case HashBLAKE2b256:
		return func() hash.Hash {
			h, _ := blake2b.New256(nil)
			return h
		}, nil
	case HashBLAKE2b512:
		return func() hash.Hash {
			h, _ := blake2b.New512(nil)
			return h
		}, nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", p.hashAlgorithm)
	}
}

// getBlockSize returns the block size for the selected hash algorithm
func (p *HMACProcessor) getBlockSize() int {
	switch p.hashAlgorithm {
	case HashSHA1:
		return 64
	case HashSHA256:
		return 64
	case HashSHA512:
		return 128
	case HashBLAKE2b256:
		return 64
	case HashBLAKE2b512:
		return 128
	default:
		return 64 // Default to SHA-256 block size
	}
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
	blockSize := p.getBlockSize()
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
	hashFunc, err := p.getHashFunction()
	if err != nil {
		return "", nil, err
	}
	h := hmac.New(hashFunc, p.key)

	// Write the message to the HMAC
	h.Write([]byte(text))
	v.AddStep("HMAC Calculation:")
	v.AddStep("1. Hash(innerKey || message)")
	v.AddStep("2. Hash(outerKey || result)")
	v.AddArrow()

	// Get the HMAC
	hmacResult := h.Sum(nil)
	v.AddHexStep("HMAC Result (Raw Bytes)", hmacResult)
	v.AddArrow()

	// Convert to hexadecimal
	hmacHex := hex.EncodeToString(hmacResult)
	v.AddTextStep("HMAC Result (Hex)", hmacHex)

	// Convert to Base64
	hmacBase64 := base64.StdEncoding.EncodeToString(hmacResult)
	v.AddTextStep("HMAC Result (Base64)", hmacBase64)

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
	v.AddNote(fmt.Sprintf("6. Using %s as the underlying hash function", p.hashAlgorithm))

	// Return both formats in the result
	result := fmt.Sprintf("Hex: %s\nBase64: %s", hmacHex, hmacBase64)
	return result, v.GetSteps(), nil
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
