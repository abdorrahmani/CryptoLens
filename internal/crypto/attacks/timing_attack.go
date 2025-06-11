package attacks

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// TimingAttackProcessor implements the timing attack simulation
type TimingAttackProcessor struct {
	*BaseProcessor
	config *AttackConfig
}

// NewTimingAttackProcessor creates a new timing attack processor
func NewTimingAttackProcessor() *TimingAttackProcessor {
	return &TimingAttackProcessor{
		BaseProcessor: NewBaseProcessor(),
		config:        NewAttackConfig(),
	}
}

// Configure configures the timing attack processor
func (p *TimingAttackProcessor) Configure(config map[string]interface{}) error {
	if keySize, ok := config["keySize"].(int); ok {
		if keySize != 256 {
			return fmt.Errorf("invalid key size: %d (must be 256 bits for HMAC-SHA256)", keySize)
		}
		p.config.KeySize = keySize
	}

	// Generate a random key
	p.config.Key = make([]byte, p.config.KeySize/8)
	if _, err := rand.Read(p.config.Key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Set test mode if specified
	if testMode, ok := config["testMode"].(bool); ok && testMode {
		p.config.Iterations = 1 // Reduce iterations in test mode
	}

	return nil
}

// Process demonstrates the timing attack on HMAC comparison
func (p *TimingAttackProcessor) Process(text string, operation string) (string, []string, error) {
	p.addIntroduction()

	// Generate HMAC for the input text
	correctHMAC := p.generateHMAC(text)
	p.addInputInfo(text, correctHMAC)

	// Demonstrate vulnerable comparison
	p.addVulnerableComparison()

	// Perform the attack
	guessedHMAC, byteTimings := p.performAttack(correctHMAC)

	// Show results
	p.addResults(guessedHMAC, correctHMAC, byteTimings)

	// Add security notes
	p.addSecurityImplications()

	return fmt.Sprintf("Attack completed in %.2fs", float64(time.Since(time.Now()).Seconds())), p.GetSteps(), nil
}

func (p *TimingAttackProcessor) addIntroduction() {
	p.AddStep("🔒 Timing Attack on HMAC Comparison")
	p.AddStep("================================")
	p.AddNote("Timing attacks exploit variations in execution time")
	p.AddNote("In HMAC verification, byte-by-byte comparison can leak information")
	p.AddNote("This simulation demonstrates why constant-time comparison is crucial")
	p.AddSeparator()
}

func (p *TimingAttackProcessor) generateHMAC(text string) []byte {
	h := hmac.New(sha256.New, p.config.Key)
	h.Write([]byte(text))
	return h.Sum(nil)
}

func (p *TimingAttackProcessor) addInputInfo(text string, correctHMAC []byte) {
	p.AddTextStep("Input Text", text)
	p.AddArrow()
	p.AddTextStep("Correct HMAC (Hex)", hex.EncodeToString(correctHMAC))
	p.AddArrow()
}

func (p *TimingAttackProcessor) addVulnerableComparison() {
	p.AddStep("Vulnerable Comparison Implementation:")
	p.AddStep("func compare(a, b []byte) bool {")
	p.AddStep("    if len(a) != len(b) { return false }")
	p.AddStep("    for i := 0; i < len(a); i++ {")
	p.AddStep("        if a[i] != b[i] { return false }")
	p.AddStep("        time.Sleep(1 * time.Millisecond) // Simulated delay")
	p.AddStep("    }")
	p.AddStep("    return true")
	p.AddStep("}")
	p.AddArrow()

	p.AddStep("Timing Attack Demonstration:")
	p.AddStep("1. We'll try to guess the HMAC byte by byte")
	p.AddStep("2. Each guess will be timed")
	p.AddStep("3. Longer times indicate more correct bytes")
	p.AddArrow()
}

type byteTiming struct {
	byteNum int
	time    time.Duration
}

func (p *TimingAttackProcessor) performAttack(correctHMAC []byte) ([]byte, []byteTiming) {
	guessedHMAC := make([]byte, len(correctHMAC))
	byteTimings := make([]byteTiming, len(correctHMAC))
	iterations := p.config.Iterations
	if iterations == 0 {
		iterations = 5 // Default iterations if not set
	}

	// Calculate total work to be done
	totalBytes := len(correctHMAC)
	totalGuesses := totalBytes * 256 // 256 possible values per byte
	fmt.Printf("\nTotal work: %d bytes × 256 guesses = %d comparisons\n", totalBytes, totalGuesses)
	fmt.Printf("Estimated time: %.1f seconds\n\n", float64(totalGuesses)*0.001*float64(iterations))

	// Start time for ETA calculation
	startTime := time.Now()

	// Print initial progress line
	fmt.Print("Progress: [", strings.Repeat("░", totalBytes), "] 0/", totalBytes, " bytes - ETA: calculating...")

	for i := 0; i < len(correctHMAC); i++ {
		// Calculate ETA
		elapsed := time.Since(startTime)
		progress := float64(i) / float64(totalBytes)
		var eta time.Duration
		if progress > 0 {
			eta = time.Duration(float64(elapsed) / progress * (1 - progress))
		}

		// Create a fixed-width progress bar
		progressBar := fmt.Sprintf("[%s%s]",
			strings.Repeat("█", i+1),
			strings.Repeat("░", totalBytes-i-1))

		// Format the ETA with fixed width
		etaStr := utils.FormatDuration(eta)
		if etaStr == "" {
			etaStr = "calculating..."
		}

		// Update progress in the same line with fixed-width fields
		fmt.Printf("\rProgress: %-40s %d/%d bytes - ETA: %-10s",
			progressBar,
			i+1, totalBytes,
			etaStr)

		p.AddStep(fmt.Sprintf("\nGuessing byte %d:", i+1))

		// Try each possible byte value
		var bestByte byte
		var bestTime time.Duration

		for b := 0; b < 256; b++ {
			guessedHMAC[i] = byte(b)

			// Measure multiple iterations for accuracy
			var byteTime time.Duration
			for j := 0; j < iterations; j++ {
				start := time.Now()
				compare(guessedHMAC, correctHMAC)
				byteTime += time.Since(start)
			}
			byteTime /= time.Duration(iterations)

			// Update best guess if this one took longer
			if byteTime > bestTime {
				bestTime = byteTime
				bestByte = byte(b)
			}
		}

		// Store timing for visualization
		byteTimings[i] = byteTiming{i + 1, bestTime}

		// Set the best guess
		guessedHMAC[i] = bestByte

		// Show progress
		currentHex := hex.EncodeToString(guessedHMAC[:i+1])
		correctHex := hex.EncodeToString(correctHMAC[:i+1])
		p.AddStep(fmt.Sprintf("Guessed: %s", currentHex))
		p.AddStep(fmt.Sprintf("Correct: %s", correctHex))
		p.AddStep(fmt.Sprintf("Time for this byte: %.2fms", float64(bestTime.Microseconds())/1000.0))

		if currentHex == correctHex {
			p.AddStep("✅ Byte guessed correctly!")
		} else {
			p.AddStep("❌ Byte guessed incorrectly")
		}
	}

	return guessedHMAC, byteTimings
}

func (p *TimingAttackProcessor) addResults(guessedHMAC, correctHMAC []byte, byteTimings []byteTiming) {
	// Show timing visualization
	p.AddSeparator()
	p.AddStep("Timing Visualization:")
	p.AddStep("===================")

	// Find max time for scaling
	var maxTime time.Duration
	for _, bt := range byteTimings {
		if bt.time > maxTime {
			maxTime = bt.time
		}
	}

	// Track statistics
	var correctGuesses, incorrectGuesses int
	var totalCorrectTime, totalIncorrectTime time.Duration
	var correctCount, incorrectCount int

	// Show timing graph
	for _, bt := range byteTimings {
		// Scale the bar length (max 50 characters)
		barLength := int(float64(bt.time) / float64(maxTime) * 50)
		bar := strings.Repeat("█", barLength)

		// Check if this byte was guessed correctly
		guessedByte := guessedHMAC[bt.byteNum-1]
		correctByte := correctHMAC[bt.byteNum-1]
		isCorrect := guessedByte == correctByte

		// Update statistics
		if isCorrect {
			correctGuesses++
			totalCorrectTime += bt.time
			correctCount++
		} else {
			incorrectGuesses++
			totalIncorrectTime += bt.time
			incorrectCount++
		}

		// Add status indicator
		status := "❌"
		if isCorrect {
			status = "✔️"
		}

		p.AddStep(fmt.Sprintf("Byte %2d: %6.2fms %s %s",
			bt.byteNum,
			float64(bt.time.Microseconds())/1000.0,
			bar,
			status))
	}

	// Calculate averages
	var avgCorrectTime, avgIncorrectTime time.Duration
	if correctCount > 0 {
		avgCorrectTime = totalCorrectTime / time.Duration(correctCount)
	}
	if incorrectCount > 0 {
		avgIncorrectTime = totalIncorrectTime / time.Duration(incorrectCount)
	}

	// Calculate accuracy
	accuracy := float64(correctGuesses) / float64(len(correctHMAC)) * 100

	// Show final results
	p.AddSeparator()
	p.AddStep("Attack Results:")
	p.AddStep(fmt.Sprintf("Guessed HMAC: %s", hex.EncodeToString(guessedHMAC)))
	p.AddStep(fmt.Sprintf("Correct HMAC: %s", hex.EncodeToString(correctHMAC)))

	// Add statistics
	p.AddSeparator()
	p.AddStep("Attack Statistics:")
	p.AddStep(fmt.Sprintf("✔️ Correct guesses: %d", correctGuesses))
	p.AddStep(fmt.Sprintf("❌ Incorrect guesses: %d", incorrectGuesses))
	p.AddStep(fmt.Sprintf("📊 Accuracy: %.1f%%", accuracy))
	p.AddStep(fmt.Sprintf("⏱️ Average time per byte (correct): %.1fms", float64(avgCorrectTime.Microseconds())/1000.0))
	p.AddStep(fmt.Sprintf("⏱️ Average time per byte (wrong): %.1fms", float64(avgIncorrectTime.Microseconds())/1000.0))

	if hex.EncodeToString(guessedHMAC) == hex.EncodeToString(correctHMAC) {
		p.AddStep("✅ Attack successful!")
	} else {
		p.AddStep("❌ Attack partially successful")
	}
}

func (p *TimingAttackProcessor) addSecurityImplications() {
	p.AddSeparator()
	p.AddStep("🔒 Security Implications:")
	p.AddStep("1. Timing attacks can reveal secret information")
	p.AddStep("2. Byte-by-byte comparison is vulnerable")
	p.AddStep("3. Execution time variations leak information")
	p.AddStep("4. Attackers can recover secrets byte by byte")

	p.AddStep("✅ Best Practices:")
	p.AddStep("1. Use constant-time comparison (crypto/subtle)")
	p.AddStep("2. Never use regular comparison for secrets")
	p.AddStep("3. Consider using HMAC verification libraries")
	p.AddStep("4. Be aware of timing side channels")
	p.AddStep("5. Test for timing vulnerabilities")

	// Show Go's solution
	p.AddSeparator()
	p.AddStep("Go's Solution:")
	p.AddStep("The crypto/subtle package provides ConstantTimeCompare:")
	p.AddStep("import \"crypto/subtle\"")
	p.AddStep("if subtle.ConstantTimeCompare(a, b) == 1 {")
	p.AddStep("    // HMACs match")
	p.AddStep("}")
}

var compareDelay = 1 * time.Millisecond // Default delay for comparison

// compare implements a vulnerable byte-by-byte comparison
func compare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
		time.Sleep(compareDelay) // Use configurable delay
	}
	return true
}
