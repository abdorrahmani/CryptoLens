package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"time"

	"github.com/abdorrahmani/cryptolens/internal/utils"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
)

// Available hash algorithms
const (
	HashSHA1       = "sha1"
	HashSHA256     = "sha256"
	HashSHA512     = "sha512"
	HashBLAKE2b256 = "blake2b-256"
	HashBLAKE2b512 = "blake2b-512"
	HashBLAKE3     = "blake3"
)

type HMACProcessor struct {
	BaseConfigurableProcessor
	keyManager    KeyManager
	hashAlgorithm string
}

func NewHMACProcessor() *HMACProcessor {
	return &HMACProcessor{
		hashAlgorithm: HashSHA256,
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *HMACProcessor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}

	// Configure key file if provided
	keyFile := "hmac_key.bin"
	if kf, ok := config["keyFile"].(string); ok {
		keyFile = kf
	}

	// Initialize key manager
	p.keyManager = NewFileKeyManager(256, keyFile) // HMAC-SHA256 uses 256-bit keys
	if err := p.keyManager.LoadOrGenerateKey(); err != nil {
		return fmt.Errorf("failed to load/generate key: %w", err)
	}

	// Configure hash algorithm if provided
	if hashAlgo, ok := config["hashAlgorithm"].(string); ok {
		if hashAlgo != "" {
			switch hashAlgo {
			case HashSHA1, HashSHA256, HashSHA512, HashBLAKE2b256, HashBLAKE2b512, HashBLAKE3:
				p.hashAlgorithm = hashAlgo
			default:
				return fmt.Errorf("unsupported hash algorithm: %s (must be one of: sha1, sha256, sha512, blake2b-256, blake2b-512, blake3)", hashAlgo)
			}
		}
	}

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
	case HashBLAKE3:
		return func() hash.Hash {
			return blake3.New()
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
	case HashBLAKE3:
		return 64
	default:
		return 64 // Default to SHA-256 block size
	}
}

// getOutputSize returns the output size in bytes for the selected hash algorithm
func (p *HMACProcessor) getOutputSize() int {
	switch p.hashAlgorithm {
	case HashSHA1:
		return 20 // 160 bits
	case HashSHA256:
		return 32 // 256 bits
	case HashSHA512:
		return 64 // 512 bits
	case HashBLAKE2b256:
		return 32 // 256 bits
	case HashBLAKE2b512:
		return 64 // 512 bits
	case HashBLAKE3:
		return 32 // 256 bits by default
	default:
		return 32 // Default to SHA-256 size
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
	v.AddHexStep("HMAC Key", p.keyManager.GetKey())
	v.AddArrow()

	// Demonstrate key preparation
	blockSize := p.getBlockSize()
	v.AddStep("Key Preparation:")
	v.AddStep("1. If key length > block size, hash it")
	v.AddStep("2. If key length < block size, pad with zeros")
	v.AddStep(fmt.Sprintf("Block size for %s: %d bytes", p.hashAlgorithm, blockSize))

	// Pad key to block size if needed
	paddedKey := make([]byte, blockSize)
	copy(paddedKey, p.keyManager.GetKey())
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
	h := hmac.New(hashFunc, p.keyManager.GetKey())

	// Measure execution time with multiple iterations for precision
	const iterations = 1000
	var totalTime time.Duration

	// Warm-up iteration
	h.Write([]byte(text))
	h.Sum(nil)

	// Measure multiple iterations
	for i := 0; i < iterations; i++ {
		h.Reset()
		startTime := time.Now()
		h.Write([]byte(text))
		h.Sum(nil)
		totalTime += time.Since(startTime)
	}

	// Calculate average time
	avgTime := totalTime / iterations

	// Format execution time with higher precision
	var timeStr string
	if avgTime < time.Millisecond {
		timeStr = fmt.Sprintf("%.3fµs", float64(avgTime.Nanoseconds())/1000.0)
	} else {
		timeStr = fmt.Sprintf("%.3fms", float64(avgTime.Milliseconds()))
	}
	v.AddNote(fmt.Sprintf("Current algorithm (%s) execution time: %s (avg of %d iterations)", p.hashAlgorithm, timeStr, iterations))

	// Calculate final HMAC for actual use
	h.Reset()
	h.Write([]byte(text))
	hmacResult := h.Sum(nil)

	v.AddStep("HMAC Calculation:")
	v.AddStep("1. Hash(innerKey || message)")
	v.AddStep("2. Hash(outerKey || result)")
	v.AddArrow()

	// Show the HMAC result
	v.AddHexStep("HMAC Result (Raw Bytes)", hmacResult)
	v.AddArrow()

	// Convert to hexadecimal
	hmacHex := hex.EncodeToString(hmacResult)
	v.AddTextStep(fmt.Sprintf("HMAC Result (Hex) - %d bytes", len(hmacResult)), hmacHex)

	// Convert to Base64
	hmacBase64 := base64.StdEncoding.EncodeToString(hmacResult)
	v.AddTextStep(fmt.Sprintf("HMAC Result (Base64) - %d bytes", len(hmacResult)), hmacBase64)

	// Add hash algorithm information
	v.AddStep("Hash Algorithm Information:")
	v.AddStep(fmt.Sprintf("Selected Algorithm: %s", p.hashAlgorithm))
	v.AddStep(fmt.Sprintf("Block Size: %d bytes", p.getBlockSize()))
	v.AddStep(fmt.Sprintf("Output Size: %d bytes", p.getOutputSize()))
	v.AddStep("")
	v.AddStep("Available Algorithms:")

	// Show all algorithms with the selected one highlighted
	algorithms := []struct {
		name    string
		details []string
	}{
		{
			name: HashSHA1,
			details: []string{
				"- SHA-1: 160-bit (20 bytes) output",
				"- Note: SHA-1 is considered cryptographically broken and should not be used for security-critical applications",
			},
		},
		{
			name: HashSHA256,
			details: []string{
				"- SHA-256: 256-bit (32 bytes) output",
				"- Part of the SHA-2 family",
				"- Widely used in security applications and protocols",
			},
		},
		{
			name: HashSHA512,
			details: []string{
				"- SHA-512: 512-bit (64 bytes) output",
				"- Part of the SHA-2 family",
				"- Provides higher security margin than SHA-256",
			},
		},
		{
			name: HashBLAKE2b256,
			details: []string{
				"- BLAKE2b-256: 256-bit (32 bytes) output",
				"- Faster than SHA-256 on 64-bit platforms",
				"- Used in many cryptocurrencies and security applications",
			},
		},
		{
			name: HashBLAKE2b512,
			details: []string{
				"- BLAKE2b-512: 512-bit (64 bytes) output",
				"- Faster than SHA-512 on 64-bit platforms",
				"- Used in many cryptocurrencies and security applications",
			},
		},
		{
			name: HashBLAKE3,
			details: []string{
				"- BLAKE3: 256-bit (32 bytes) output by default",
				"- Successor to BLAKE2, offering even better performance",
				"- Features parallel processing and tree hashing",
				"- Used in modern security applications and protocols",
			},
		},
	}

	for _, algo := range algorithms {
		if algo.name == p.hashAlgorithm {
			v.AddStep(fmt.Sprintf("→ %s (Currently Selected)", algo.name))
		} else {
			v.AddStep(fmt.Sprintf("  %s", algo.name))
		}
		for _, detail := range algo.details {
			v.AddStep(detail)
		}
		v.AddStep("")
	}

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
