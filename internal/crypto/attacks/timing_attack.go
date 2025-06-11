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
	keySize int
	key     []byte
}

// NewTimingAttackProcessor creates a new timing attack processor
func NewTimingAttackProcessor() *TimingAttackProcessor {
	return &TimingAttackProcessor{
		keySize: 256, // Default to 256-bit key
	}
}

// Configure configures the timing attack processor
func (p *TimingAttackProcessor) Configure(config map[string]interface{}) error {
	if keySize, ok := config["keySize"].(int); ok {
		if keySize != 256 {
			return fmt.Errorf("invalid key size: %d (must be 256 bits for HMAC-SHA256)", keySize)
		}
		p.keySize = keySize
	}

	// Generate a random key
	p.key = make([]byte, p.keySize/8)
	if _, err := rand.Read(p.key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	return nil
}

// Process demonstrates the timing attack on HMAC comparison
func (p *TimingAttackProcessor) Process(text string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep("🔒 Timing Attack on HMAC Comparison")
	v.AddStep("================================")
	v.AddNote("Timing attacks exploit variations in execution time")
	v.AddNote("In HMAC verification, byte-by-byte comparison can leak information")
	v.AddNote("This simulation demonstrates why constant-time comparison is crucial")
	v.AddSeparator()

	// Generate HMAC for the input text
	h := hmac.New(sha256.New, p.key)
	h.Write([]byte(text))
	correctHMAC := h.Sum(nil)
	correctHMACHex := hex.EncodeToString(correctHMAC)

	v.AddTextStep("Input Text", text)
	v.AddArrow()
	v.AddTextStep("Correct HMAC (Hex)", correctHMACHex)
	v.AddArrow()

	// Demonstrate vulnerable comparison
	v.AddStep("Vulnerable Comparison Implementation:")
	v.AddStep("func compare(a, b []byte) bool {")
	v.AddStep("    if len(a) != len(b) { return false }")
	v.AddStep("    for i := 0; i < len(a); i++ {")
	v.AddStep("        if a[i] != b[i] { return false }")
	v.AddStep("        time.Sleep(1 * time.Millisecond) // Simulated delay")
	v.AddStep("    }")
	v.AddStep("    return true")
	v.AddStep("}")
	v.AddArrow()

	// Demonstrate the attack
	v.AddStep("Timing Attack Demonstration:")
	v.AddStep("1. We'll try to guess the HMAC byte by byte")
	v.AddStep("2. Each guess will be timed")
	v.AddStep("3. Longer times indicate more correct bytes")
	v.AddArrow()

	// Simulate the attack
	guessedHMAC := make([]byte, len(correctHMAC))
	var totalTime time.Duration
	const iterations = 5 // Number of measurements per byte

	// Calculate total work to be done
	totalBytes := len(correctHMAC)
	totalGuesses := totalBytes * 256 // 256 possible values per byte
	fmt.Printf("\nTotal work: %d bytes × 256 guesses = %d comparisons\n", totalBytes, totalGuesses)
	fmt.Printf("Estimated time: %.1f seconds\n\n", float64(totalGuesses)*0.001*float64(iterations))

	// Track timing for visualization
	type byteTiming struct {
		byteNum int
		time    time.Duration
	}
	byteTimings := make([]byteTiming, totalBytes)

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

		v.AddStep(fmt.Sprintf("\nGuessing byte %d:", i+1))

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
			byteTime /= iterations

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
		totalTime += bestTime

		// Show progress
		currentHex := hex.EncodeToString(guessedHMAC[:i+1])
		correctHex := hex.EncodeToString(correctHMAC[:i+1])
		v.AddStep(fmt.Sprintf("Guessed: %s", currentHex))
		v.AddStep(fmt.Sprintf("Correct: %s", correctHex))
		v.AddStep(fmt.Sprintf("Time for this byte: %.2fms", float64(bestTime.Microseconds())/1000.0))

		if currentHex == correctHex {
			v.AddStep("✅ Byte guessed correctly!")
		} else {
			v.AddStep("❌ Byte guessed incorrectly")
		}
	}

	// Show timing visualization
	v.AddSeparator()
	v.AddStep("Timing Visualization:")
	v.AddStep("===================")

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

		v.AddStep(fmt.Sprintf("Byte %2d: %6.2fms %s %s",
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
	accuracy := float64(correctGuesses) / float64(totalBytes) * 100

	// Show final results
	v.AddSeparator()
	v.AddStep("Attack Results:")
	v.AddStep(fmt.Sprintf("Total attack time: %.2fs", float64(totalTime.Seconds())))
	v.AddStep(fmt.Sprintf("Guessed HMAC: %s", hex.EncodeToString(guessedHMAC)))
	v.AddStep(fmt.Sprintf("Correct HMAC: %s", correctHMACHex))

	// Add statistics
	v.AddSeparator()
	v.AddStep("Attack Statistics:")
	v.AddStep(fmt.Sprintf("✔️ Correct guesses: %d", correctGuesses))
	v.AddStep(fmt.Sprintf("❌ Incorrect guesses: %d", incorrectGuesses))
	v.AddStep(fmt.Sprintf("📊 Accuracy: %.1f%%", accuracy))
	v.AddStep(fmt.Sprintf("⏱️ Average time per byte (correct): %.1fms", float64(avgCorrectTime.Microseconds())/1000.0))
	v.AddStep(fmt.Sprintf("⏱️ Average time per byte (wrong): %.1fms", float64(avgIncorrectTime.Microseconds())/1000.0))

	if hex.EncodeToString(guessedHMAC) == correctHMACHex {
		v.AddStep("✅ Attack successful!")
	} else {
		v.AddStep("❌ Attack partially successful")
	}

	// Add security notes
	v.AddSeparator()
	v.AddStep("🔒 Security Implications:")
	v.AddStep("1. Timing attacks can reveal secret information")
	v.AddStep("2. Byte-by-byte comparison is vulnerable")
	v.AddStep("3. Execution time variations leak information")
	v.AddStep("4. Attackers can recover secrets byte by byte")

	v.AddStep("✅ Best Practices:")
	v.AddStep("1. Use constant-time comparison (crypto/subtle)")
	v.AddStep("2. Never use regular comparison for secrets")
	v.AddStep("3. Consider using HMAC verification libraries")
	v.AddStep("4. Be aware of timing side channels")
	v.AddStep("5. Test for timing vulnerabilities")

	// Show Go's solution
	v.AddSeparator()
	v.AddStep("Go's Solution:")
	v.AddStep("The crypto/subtle package provides ConstantTimeCompare:")
	v.AddStep("import \"crypto/subtle\"")
	v.AddStep("if subtle.ConstantTimeCompare(a, b) == 1 {")
	v.AddStep("    // HMACs match")
	v.AddStep("}")

	return fmt.Sprintf("Attack completed in %.2fs", float64(totalTime.Seconds())), v.GetSteps(), nil
}

// compare implements a vulnerable byte-by-byte comparison
func compare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
		time.Sleep(1 * time.Millisecond) // Simulated delay
	}
	return true
}