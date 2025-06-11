package attacks

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// BruteForceProcessor implements the brute force attack simulation
type BruteForceProcessor struct {
	*BaseProcessor
	config *AttackConfig
}

// NewBruteForceProcessor creates a new brute force attack processor
func NewBruteForceProcessor() *BruteForceProcessor {
	return &BruteForceProcessor{
		BaseProcessor: NewBaseProcessor(),
		config:        NewAttackConfig(),
	}
}

// Configure configures the brute force processor
func (p *BruteForceProcessor) Configure(config map[string]interface{}) error {
	if iterations, ok := config["iterations"].(int); ok {
		p.config.Iterations = iterations
	}

	// Generate a random salt
	p.config.Salt = make([]byte, 16)
	if _, err := rand.Read(p.config.Salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	return nil
}

// Process demonstrates the brute force attack on a weak PBKDF key
func (p *BruteForceProcessor) Process(text string, operation string) (string, []string, error) {
	p.addIntroduction()

	// Generate target key
	targetKey := p.generateTargetKey(text)
	p.addTargetKeyInfo(text, targetKey)

	// Start attack
	startTime := time.Now()
	attempts, found, foundPassword, foundKey := p.performAttack(targetKey)
	duration := time.Since(startTime)

	// Show results
	p.addResults(attempts, duration, found, foundPassword, foundKey)
	p.addSecurityImplications()
	p.addComparisonWithSecureParams(duration)

	return fmt.Sprintf("Attack completed in %.2f seconds", duration.Seconds()), p.GetSteps(), nil
}

func (p *BruteForceProcessor) addIntroduction() {
	p.AddStep("🔒 Brute Force Attack on Weak PBKDF")
	p.AddStep("================================")
	p.AddNote("This simulation demonstrates how weak key derivation parameters")
	p.AddNote("can make passwords vulnerable to brute force attacks")
	p.AddNote("")
	p.AddNote("⚠️ Important Note: This attack is NOT directly breaking the cipher")
	p.AddNote("Instead, it's comparing derived keys from PBKDF2 with weak parameters")
	p.AddNote("The attacker is trying to find a password that generates the same derived key")
	p.AddNote("This is why strong key derivation parameters are crucial for security")
	p.AddSeparator()
}

func (p *BruteForceProcessor) generateTargetKey(text string) string {
	targetKey := pbkdf2.Key([]byte(text), p.config.Salt, p.config.Iterations, 32, sha256.New)
	return base64.StdEncoding.EncodeToString(targetKey)
}

func (p *BruteForceProcessor) addTargetKeyInfo(text, targetKey string) {
	p.AddTextStep("Target Password", text)
	p.AddStep(fmt.Sprintf("Using PBKDF2 with only %d iterations", p.config.Iterations))
	p.AddHexStep("Salt", p.config.Salt)
	p.AddTextStep("Target Key (Base64)", targetKey)
	p.AddArrow()
}

func (p *BruteForceProcessor) performAttack(targetKey string) (int, bool, string, string) {
	commonPasswords := CommonPasswords()
	p.addAttackDetails()

	var attempts int
	var found bool
	var foundPassword string
	var foundKey string

	for _, password := range commonPasswords {
		attempts++
		derivedKey := pbkdf2.Key([]byte(password), p.config.Salt, p.config.Iterations, 32, sha256.New)
		derivedKeyBase64 := base64.StdEncoding.EncodeToString(derivedKey)

		if attempts%5 == 0 {
			p.AddStep(fmt.Sprintf("Trying password %d/%d: %s", attempts, len(commonPasswords), password))
		}

		if derivedKeyBase64 == targetKey {
			found = true
			foundPassword = password
			foundKey = derivedKeyBase64
			break
		}
	}

	return attempts, found, foundPassword, foundKey
}

func (p *BruteForceProcessor) addAttackDetails() {
	p.AddStep("Attack Details:")
	p.AddStep("1. Using a dictionary of common passwords")
	p.AddStep("2. Testing each password with the same salt")
	p.AddStep("3. Comparing derived keys")
	p.AddStep(fmt.Sprintf("4. Only %d iterations makes this very fast", p.config.Iterations))
	p.AddArrow()
}

func (p *BruteForceProcessor) addResults(attempts int, duration time.Duration, found bool, foundPassword, foundKey string) {
	p.AddSeparator()
	p.AddStep("Attack Results:")
	p.AddStep(fmt.Sprintf("Total attempts: %d", attempts))
	p.AddStep(fmt.Sprintf("Attack duration: %.2f seconds", duration.Seconds()))
	p.AddStep(fmt.Sprintf("Attempts per second: %.0f", float64(attempts)/duration.Seconds()))

	if found {
		p.AddStep("✅ Password found!")
		p.AddTextStep("Found Password", foundPassword)
		p.AddTextStep("Derived Key", foundKey)
	} else {
		p.AddStep("❌ Password not found in dictionary")
	}
}

func (p *BruteForceProcessor) addSecurityImplications() {
	p.AddSeparator()
	p.AddStep("🔒 Security Implications:")
	p.AddStep("1. Weak key derivation parameters make brute force attacks feasible")
	p.AddStep("2. Common passwords are easily cracked")
	p.AddStep("3. Low iteration counts allow for rapid password testing")
	p.AddStep("4. Dictionary attacks can be very effective")

	p.AddStep("✅ Best Practices:")
	p.AddStep("1. Use strong key derivation functions (Argon2, scrypt, bcrypt)")
	p.AddStep("2. Use high iteration counts (100,000+ for PBKDF2)")
	p.AddStep("3. Use unique salts for each password")
	p.AddStep("4. Enforce strong password policies")
	p.AddStep("5. Consider using memory-hard functions")
}

func (p *BruteForceProcessor) addComparisonWithSecureParams(duration time.Duration) {
	p.AddSeparator()
	p.AddStep("Comparison with Secure Parameters:")
	p.AddStep("Current (Weak):")
	p.AddStep(fmt.Sprintf("• PBKDF2 with %d iterations", p.config.Iterations))
	p.AddStep(fmt.Sprintf("• Attack time: %.2f seconds", duration.Seconds()))
	p.AddStep("Secure Configuration:")
	p.AddStep("• PBKDF2 with 310,000 iterations")
	p.AddStep("• Estimated attack time: ~5.2 hours")
	p.AddStep("• Argon2id with 1GB memory cost")
	p.AddStep("• Estimated attack time: ~2.3 days")
}
