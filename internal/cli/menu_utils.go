package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/abdorrahmani/cryptolens/internal/crypto"
)

// MenuUtils handles common menu operations and utilities
type MenuUtils struct {
	display DisplayHandler
	input   UserInputHandler
}

// NewMenuUtils creates a new menu utilities instance
func NewMenuUtils(display DisplayHandler, input UserInputHandler) *MenuUtils {
	return &MenuUtils{
		display: display,
		input:   input,
	}
}

// ProcessText handles text input and processing
func (u *MenuUtils) ProcessText(handler AlgorithmHandler, processor crypto.Processor, operation string) error {
	fmt.Printf("\n%s", u.display.(*ConsoleDisplay).theme.Format("Enter text to process: ", "brightGreen bold"))

	text, err := u.input.GetText()
	if err != nil {
		return err
	}

	u.display.ShowProcessingMessage(text)

	result, steps, err := handler.Handle(processor, text, operation)
	if err != nil {
		return err
	}

	u.display.ShowResult(result, steps)
	return nil
}

// ShowLoadingAnimation displays a loading animation
func (u *MenuUtils) ShowLoadingAnimation(done chan bool) {
	loadingChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	i := 0
	for {
		select {
		case <-done:
			fmt.Print("\r\033[K") // Clear the line
			return
		default:
			fmt.Printf("\r%s Running benchmark... %s", loadingChars[i], strings.Repeat(".", (i%5)+1))
			i = (i + 1) % len(loadingChars)
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// FormatBenchmarkResult formats a benchmark result
func (u *MenuUtils) FormatBenchmarkResult(result struct {
	name     string
	duration time.Duration
}, iterations int, fastestDuration time.Duration, index int) string {
	avgTime := float64(result.duration.Microseconds()) / float64(iterations)
	percentageDiff := float64(result.duration) / float64(fastestDuration) * 100

	var diffStr string
	if index == 0 {
		diffStr = " (baseline)"
	} else {
		diffStr = fmt.Sprintf(" (+%.1f%%)", percentageDiff-100)
	}

	return fmt.Sprintf("%d. %s: %d ops in %dms → avg: %.1fµs%s",
		index+1,
		strings.ToUpper(result.name),
		iterations,
		result.duration.Milliseconds(),
		avgTime,
		diffStr,
	)
}

// GetBenchmarkText gets text input for benchmarking
func (u *MenuUtils) GetBenchmarkText(defaultText string) string {
	fmt.Printf("\nEnter sample text for benchmarking (default: '%s'): ", defaultText)
	return GetTextInput(defaultText)
}

// GetBenchmarkIterations gets the number of iterations for benchmarking
func (u *MenuUtils) GetBenchmarkIterations(defaultIterations, min, max int) int {
	iterations := GetIntInput(fmt.Sprintf("\nEnter number of iterations (default: %d): ", defaultIterations), min, max)
	if iterations == 0 {
		return defaultIterations
	}
	return iterations
}

// ShowBenchmarkWarning shows a warning for PBKDF benchmarking
func (u *MenuUtils) ShowBenchmarkWarning() {
	fmt.Print("\n⚠️  Warning: Large numbers will take a long time to complete")
	fmt.Print("\n    Recommended: 10-100 iterations")
	fmt.Print("\n    PBKDF2: ~15ms per operation")
	fmt.Print("\n    Argon2id: ~36ms per operation")
	fmt.Print("\n    Scrypt: ~266ms per operation")
	fmt.Print("\n    (1000 iterations ≈ 4.5 minutes total)\n")
}

// CalculateEstimatedTime calculates the estimated time for PBKDF benchmarking
func (u *MenuUtils) CalculateEstimatedTime(iterations int) time.Duration {
	return time.Duration(iterations) * (15 + 36 + 266) * time.Millisecond
}
