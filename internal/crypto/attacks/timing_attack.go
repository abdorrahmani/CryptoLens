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
	simulator       AttackSimulator
	visualizer      AttackVisualizer
	progressTracker ProgressTracker
	config          *TimingAttackConfig
}

// TimingAttackConfig holds configuration for timing attacks
type TimingAttackConfig struct {
	KeySize      int
	Iterations   int
	DelayPerByte time.Duration
}

// NewTimingAttackProcessor creates a new timing attack processor
func NewTimingAttackProcessor() *TimingAttackProcessor {
	return &TimingAttackProcessor{
		BaseProcessor: NewBaseProcessor(),
		config: &TimingAttackConfig{
			KeySize:      256,
			Iterations:   5,
			DelayPerByte: time.Millisecond,
		},
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

	if iterations, ok := config["iterations"].(int); ok {
		p.config.Iterations = iterations
	}

	// Initialize components
	p.simulator = NewTimingAttackSimulator(p.config)
	p.visualizer = NewTimingAttackVisualizer()
	p.progressTracker = NewConsoleProgressTracker()

	return nil
}

// Process demonstrates the timing attack on HMAC comparison
func (p *TimingAttackProcessor) Process(text string, operation string) (string, []string, error) {
	// Add introduction
	p.AddStep("🔒 Timing Attack on HMAC Comparison")
	p.AddStep("================================")
	p.AddNote("A timing attack is a SIDE-CHANNEL attack: it learns secrets not by breaking the")
	p.AddNote("math, but by measuring how long an operation takes.")
	p.AddSeparator()

	p.AddStep("📈 How it works here")
	p.AddStep("A naive tag check compares bytes left-to-right and RETURNS EARLY on the first")
	p.AddStep("mismatch. So a guess with a correct first byte takes slightly longer than one")
	p.AddStep("that is wrong immediately. By measuring which guess is slowest, an attacker")
	p.AddStep("learns one byte at a time — turning an impossible 2^256 search into 256×32 tries.")
	p.AddNote("This demo exaggerates the effect with a 1ms per-byte delay so the signal is")
	p.AddNote("visible instantly; real attacks average many timing samples to see microseconds.")
	p.AddSeparator()

	// Run the attack simulation
	result, err := p.simulator.Simulate(text)
	if err != nil {
		return "", nil, err
	}

	// Visualize results
	steps := p.visualizer.VisualizeAttack(result)
	p.AddSteps(steps)

	// Add security notes
	securityNotes := p.visualizer.VisualizeSecurityNotes()
	p.AddSteps(securityNotes)

	// Get all steps once
	allSteps := p.GetSteps()

	return fmt.Sprintf("Attack completed in %.2fs", result.Duration.Seconds()), allSteps, nil
}

// TimingAttackSimulator implements the timing attack simulation logic
type TimingAttackSimulator struct {
	config          *TimingAttackConfig
	key             []byte
	progressTracker ProgressTracker
}

// NewTimingAttackSimulator creates a new timing attack simulator
func NewTimingAttackSimulator(config *TimingAttackConfig) *TimingAttackSimulator {
	return &TimingAttackSimulator{
		config:          config,
		progressTracker: NewConsoleProgressTracker(),
	}
}

// Simulate runs the timing attack simulation
func (s *TimingAttackSimulator) Simulate(input string) (*AttackResult, error) {
	// Generate key if not exists
	if s.key == nil {
		s.key = make([]byte, s.config.KeySize/8)
		if _, err := rand.Read(s.key); err != nil {
			return nil, fmt.Errorf("failed to generate key: %w", err)
		}
	}

	// Generate correct HMAC
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(input))
	correctHMAC := h.Sum(nil)

	// Initialize result
	result := &AttackResult{
		CorrectValue: correctHMAC,
		Statistics:   &AttackStatistics{},
	}

	// Run the attack. (Progress is not streamed to stdout: this runs inside the
	// TUI, which owns the screen — any direct print would corrupt the display.)
	startTime := time.Now()
	guessedHMAC, stats := s.runAttack(correctHMAC)
	result.Duration = time.Since(startTime)
	result.GuessedValue = guessedHMAC
	result.Statistics = stats
	result.Success = hex.EncodeToString(guessedHMAC) == hex.EncodeToString(correctHMAC)

	// Complete progress tracking
	s.progressTracker.Complete()

	return result, nil
}

// runAttack performs the actual timing attack
func (s *TimingAttackSimulator) runAttack(correctHMAC []byte) ([]byte, *AttackStatistics) {
	guessedHMAC := make([]byte, len(correctHMAC))
	stats := &AttackStatistics{
		ByteTimings: make([]ByteTiming, len(correctHMAC)),
	}

	startTime := time.Now()
	totalBytes := len(correctHMAC)

	for i := 0; i < len(correctHMAC); i++ {
		// Calculate ETA
		elapsed := time.Since(startTime)
		progress := float64(i) / float64(totalBytes)
		var eta time.Duration
		if progress > 0 {
			eta = time.Duration(float64(elapsed) / progress * (1 - progress))
		}

		// Update progress
		s.progressTracker.UpdateProgress(i+1, totalBytes, eta)

		// Try each possible byte value
		var bestByte byte
		var bestTime time.Duration

		for b := 0; b < 256; b++ {
			guessedHMAC[i] = byte(b)
			byteTime := s.measureByteTime(guessedHMAC, correctHMAC)

			if byteTime > bestTime {
				bestTime = byteTime
				bestByte = byte(b)
			}
		}

		// Record timing and correctness
		isCorrect := bestByte == correctHMAC[i]
		stats.ByteTimings[i] = ByteTiming{
			ByteNumber: i + 1,
			Duration:   bestTime,
			IsCorrect:  isCorrect,
		}

		if isCorrect {
			stats.CorrectGuesses++
		} else {
			stats.IncorrectGuesses++
		}

		guessedHMAC[i] = bestByte
	}

	// Calculate statistics
	s.calculateStatistics(stats)
	return guessedHMAC, stats
}

// measureByteTime measures the time taken for a byte comparison
func (s *TimingAttackSimulator) measureByteTime(guessed, correct []byte) time.Duration {
	var totalTime time.Duration
	for i := 0; i < s.config.Iterations; i++ {
		start := time.Now()
		compare(guessed, correct)
		totalTime += time.Since(start)
	}
	return totalTime / time.Duration(s.config.Iterations)
}

// calculateStatistics computes attack statistics
func (s *TimingAttackSimulator) calculateStatistics(stats *AttackStatistics) {
	totalBytes := len(stats.ByteTimings)
	stats.Accuracy = float64(stats.CorrectGuesses) / float64(totalBytes) * 100

	var totalCorrectTime, totalIncorrectTime time.Duration
	for _, bt := range stats.ByteTimings {
		if bt.IsCorrect {
			totalCorrectTime += bt.Duration
		} else {
			totalIncorrectTime += bt.Duration
		}
	}

	if stats.CorrectGuesses > 0 {
		stats.AvgCorrectTime = totalCorrectTime / time.Duration(stats.CorrectGuesses)
	}
	if stats.IncorrectGuesses > 0 {
		stats.AvgIncorrectTime = totalIncorrectTime / time.Duration(stats.IncorrectGuesses)
	}
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
		time.Sleep(time.Millisecond) // Simulated delay
	}
	return true
}

// TimingAttackVisualizer implements visualization for timing attacks
type TimingAttackVisualizer struct {
	*BaseProcessor
}

// NewTimingAttackVisualizer creates a new timing attack visualizer
func NewTimingAttackVisualizer() *TimingAttackVisualizer {
	return &TimingAttackVisualizer{
		BaseProcessor: NewBaseProcessor(),
	}
}

// VisualizeAttack visualizes the attack results
func (v *TimingAttackVisualizer) VisualizeAttack(result *AttackResult) []string {
	// Clear any existing steps
	v.visualizer = utils.NewVisualizer()

	// Add attack results
	v.AddTextStep("Attack Results:", "")
	v.AddStep(fmt.Sprintf("Total attack time: %.2fs", result.Duration.Seconds()))
	v.AddStep(fmt.Sprintf("Guessed HMAC: %s", hex.EncodeToString(result.GuessedValue)))
	v.AddStep(fmt.Sprintf("Correct HMAC: %s", hex.EncodeToString(result.CorrectValue)))

	if result.Success {
		v.AddStep("✅ Attack successful!")
	} else {
		v.AddStep("❌ Attack partially successful")
	}

	// Add statistics
	v.AddSeparator()
	v.AddStep("Attack Statistics:")
	v.AddStep(fmt.Sprintf("✔️ Correct guesses: %d", result.Statistics.CorrectGuesses))
	v.AddStep(fmt.Sprintf("❌ Incorrect guesses: %d", result.Statistics.IncorrectGuesses))
	v.AddStep(fmt.Sprintf("📊 Accuracy: %.1f%%", result.Statistics.Accuracy))
	v.AddStep(fmt.Sprintf("⏱️ Average time per byte (correct): %.1fms", float64(result.Statistics.AvgCorrectTime.Microseconds())/1000.0))
	v.AddStep(fmt.Sprintf("⏱️ Average time per byte (wrong): %.1fms", float64(result.Statistics.AvgIncorrectTime.Microseconds())/1000.0))

	// Add timing visualization
	v.AddSeparator()
	v.AddStep("Timing Visualization:")
	v.AddStep("===================")

	// Find max time for scaling
	var maxTime time.Duration
	for _, bt := range result.Statistics.ByteTimings {
		if bt.Duration > maxTime {
			maxTime = bt.Duration
		}
	}

	// Show timing graph
	for _, bt := range result.Statistics.ByteTimings {
		barLength := int(float64(bt.Duration) / float64(maxTime) * 50)
		bar := strings.Repeat("█", barLength)
		status := "❌"
		if bt.IsCorrect {
			status = "✔️"
		}

		v.AddStep(fmt.Sprintf("Byte %2d: %6.2fms %s %s",
			bt.ByteNumber,
			float64(bt.Duration.Microseconds())/1000.0,
			bar,
			status))
	}

	return v.GetSteps()
}

// VisualizeSecurityNotes visualizes security-related notes
func (v *TimingAttackVisualizer) VisualizeSecurityNotes() []string {
	// Clear any existing steps
	v.visualizer = utils.NewVisualizer()

	v.AddSeparator()
	v.AddStep("🔒 Security Implications:")
	v.AddStep("1. A data-dependent early return leaks secret bytes through timing.")
	v.AddStep("2. Any '==', bytes.Equal, or memcmp on a secret is vulnerable.")
	v.AddStep("3. The leak is tiny per-comparison but averages out over many samples.")
	v.AddStep("4. Applies to MAC/tag checks, password hashes, and API-key comparisons alike.")

	v.AddSeparator()
	v.AddStep("✅ Prevention & Solutions")
	v.AddStep("The fix is CONSTANT-TIME comparison: always inspect every byte, regardless of")
	v.AddStep("where the first difference is, so the time reveals nothing.")
	v.AddStep("Go — compare raw tags in constant time:")
	v.AddStep("    import \"crypto/subtle\"")
	v.AddStep("    if subtle.ConstantTimeCompare(macA, macB) == 1 { /* match */ }")
	v.AddStep("Go — for HMAC specifically, hmac.Equal does this for you:")
	v.AddStep("    if hmac.Equal(expectedMAC, gotMAC) { /* match */ }")
	v.AddStep("Other tactics: compare HASHES of the two values (a mismatch position is then")
	v.AddStep("unpredictable), and never branch or log based on a partial secret match.")
	v.AddNote("The HMAC walkthrough (menu 6) already uses hmac.Equal — this is why.")

	return v.GetSteps()
}

// ConsoleProgressTracker implements progress tracking in the console
type ConsoleProgressTracker struct {
}

// NewConsoleProgressTracker creates a new console progress tracker
func NewConsoleProgressTracker() *ConsoleProgressTracker {
	return &ConsoleProgressTracker{}
}

// UpdateProgress is a no-op. Progress used to stream to stdout, but the attack
// runs inside the TUI which owns the screen; live output there corrupts the
// display, so progress is intentionally not printed.
func (t *ConsoleProgressTracker) UpdateProgress(current, total int, eta time.Duration) {}

// Complete is a no-op for the same reason as UpdateProgress.
func (t *ConsoleProgressTracker) Complete() {}
