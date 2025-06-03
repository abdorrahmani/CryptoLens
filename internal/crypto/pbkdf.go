package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// PBKDFProcessor implements password-based key derivation
type PBKDFProcessor struct {
	BaseConfigurableProcessor
	keyManager KeyManager
	iterations int
	saltSize   int
}

// NewPBKDFProcessor creates a new PBKDF processor
func NewPBKDFProcessor() *PBKDFProcessor {
	return &PBKDFProcessor{
		iterations: 100000, // Default iterations
		saltSize:   16,     // Default salt size
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *PBKDFProcessor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}

	// Configure iterations if provided
	if iter, ok := config["iterations"].(int); ok {
		p.iterations = iter
	}

	// Configure salt size if provided
	if size, ok := config["saltSize"].(int); ok {
		p.saltSize = size
	}

	// Configure key file if provided
	keyFile := "pbkdf_key.bin"
	if kf, ok := config["keyFile"].(string); ok {
		keyFile = kf
	}

	// Initialize key manager
	p.keyManager = NewFileKeyManager(256, keyFile) // PBKDF2-SHA256 uses 256-bit keys
	if err := p.keyManager.LoadOrGenerateKey(); err != nil {
		return fmt.Errorf("failed to load/generate key: %w", err)
	}

	return nil
}

// Process handles password-based key derivation
func (p *PBKDFProcessor) Process(text string, _ string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep("PBKDF2-SHA256 Process")
	v.AddStep("=============================")
	v.AddNote("PBKDF2 (Password-Based Key Derivation Function 2) is used for key stretching")
	v.AddNote("Using SHA-256 as the underlying hash function")
	v.AddSeparator()

	// Add password strength warnings
	v.AddStep("Using PBKDF2-SHA256 for key derivation")

	// Password strength analysis
	if len(text) < 8 {
		v.AddStep("⚠️  Warning: Password is too short (less than 8 characters)")
		v.AddStep("    This makes it more vulnerable to brute-force attacks")
		v.AddStep("    Recommendation: Use at least 12 characters")
	} else if len(text) < 12 {
		v.AddStep("⚠️  Warning: Password could be stronger")
		v.AddStep("    Recommendation: Use at least 12 characters")
	}

	// Check for common patterns
	if isCommonPassword(text) {
		v.AddStep("⚠️  Warning: This appears to be a common password pattern")
		v.AddStep("    Recommendation: Use a more unique password")
	}

	// Generate salt
	salt := make([]byte, p.saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Measure execution time
	start := time.Now()
	derivedKey := pbkdf2.Key([]byte(text), salt, p.iterations, 32, sha256.New)
	duration := time.Since(start)

	// Show process details
	v.AddStep(fmt.Sprintf("Generated salt (%d bytes)", p.saltSize))
	v.AddStep(fmt.Sprintf("Performed %d iterations", p.iterations))
	v.AddStep(fmt.Sprintf("Derived key in %v", duration))
	v.AddStep("Base64 encoded the result for safe transmission")
	v.AddNote("PBKDF2 is designed to be computationally intensive to prevent brute-force attacks")

	// Add how it works
	v.AddSeparator()
	v.AddStep("How PBKDF2 Works:")
	v.AddStep("1. Password and Salt:")
	v.AddStep("   - Password is the input text")
	v.AddStep("   - Salt is a random value to prevent rainbow table attacks")
	v.AddStep("2. Iterations:")
	v.AddStep(fmt.Sprintf("   - Performs %d iterations of SHA-256", p.iterations))
	v.AddStep("   - Each iteration makes brute-force attacks more expensive")
	v.AddStep("3. Key Derivation:")
	v.AddStep("   - Combines password, salt, and iteration count")
	v.AddStep("   - Produces a 256-bit (32-byte) key")
	v.AddStep("4. Output:")
	v.AddStep("   - The derived key is base64 encoded for safe transmission")

	// Add security notes
	v.AddSeparator()
	v.AddNote("Security Considerations:")
	v.AddNote("1. The salt must be unique for each password")
	v.AddNote("2. More iterations make the process slower but more secure")
	v.AddNote("3. The derived key should be used as input to other cryptographic operations")
	v.AddNote("4. Never store the original password, only the derived key and salt")
	v.AddNote("5. The salt can be stored alongside the derived key")

	// Base64 encode the result
	encoded := base64.StdEncoding.EncodeToString(derivedKey)
	return encoded, v.GetSteps(), nil
}

// isCommonPassword checks if the password matches common patterns
func isCommonPassword(password string) bool {
	// Convert to lowercase for case-insensitive comparison
	lowerPass := strings.ToLower(password)

	// List of common passwords and patterns
	commonPasswords := []string{
		"password", "123456", "qwerty", "admin", "welcome",
		"letmein", "monkey", "dragon", "baseball", "football",
		"abc123", "111111", "123123", "12345678", "123456789",
		"1234567890", "qwerty123", "password123", "admin123",
	}

	// Check against common passwords
	for _, common := range commonPasswords {
		if lowerPass == common {
			return true
		}
	}

	// Check for sequential numbers
	if matched, _ := regexp.MatchString(`^[0-9]+$`, password); matched {
		return true
	}

	// Check for repeated characters
	for i := 0; i < len(password)-2; i++ {
		if password[i] == password[i+1] && password[i] == password[i+2] {
			return true
		}
	}

	return false
}
