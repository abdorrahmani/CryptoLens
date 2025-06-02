package cli

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/abdorrahmani/cryptolens/internal/crypto"
	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// Menu implements MenuInterface for handling the main application flow
type Menu struct {
	display DisplayHandler
	input   UserInputHandler
	factory ProcessorFactory
}

// NewMenu creates a new menu instance
func NewMenu(display DisplayHandler, input UserInputHandler, factory ProcessorFactory) *Menu {
	return &Menu{
		display: display,
		input:   input,
		factory: factory,
	}
}

// Run executes the main menu loop
func (m *Menu) Run() error {
	m.display.ShowWelcome()

	for {
		m.display.ShowMenu()

		choice, err := m.input.GetChoice()
		if err != nil {
			m.display.ShowError(err)
			continue
		}

		if choice == 7 {
			m.display.ShowGoodbye()
			return nil
		}

		if err := m.processChoice(choice); err != nil {
			m.display.ShowError(err)
		}
	}
}

// processChoice handles the user's menu choice
func (m *Menu) processChoice(choice int) error {
	processor, err := m.factory.CreateProcessor(choice)
	if err != nil {
		return err
	}

	// Get operation choice (skip for SHA-256 and HMAC)
	operation := crypto.OperationEncrypt
	if choice != 4 && choice != 6 { // Skip for SHA-256 (option 4) and HMAC (option 6)
		operation, err = m.input.GetOperation()
		if err != nil {
			return err
		}
	}

	// Configure HMAC processor if selected
	if choice == 6 { // HMAC option
		if configurable, ok := processor.(crypto.ConfigurableProcessor); ok {
			hashAlgo := GetHMACHashAlgorithm()
			if hashAlgo == "benchmark" {
				result, steps, err := RunHMACBenchmark()
				if err != nil {
					return err
				}
				m.display.ShowResult(result, steps)
				return nil
			}
			if err := configurable.Configure(map[string]interface{}{
				"hashAlgorithm": hashAlgo,
			}); err != nil {
				return fmt.Errorf("failed to configure HMAC processor: %w", err)
			}
		}
	}

	// Show prompt for user input
	message := ""
	if choice == 3 && operation == crypto.OperationDecrypt {
		message = "aes_decrypt"
	}
	m.display.ShowMessage(message)

	// Get text input from user
	text, err := m.input.GetText()
	if err != nil {
		return err
	}

	// Show the message being processed
	m.display.ShowProcessingMessage(text)

	result, steps, err := processor.Process(text, operation)
	if err != nil {
		return err
	}

	m.display.ShowResult(result, steps)
	return nil
}

// GetHMACHashAlgorithm prompts user to select a hash algorithm for HMAC
func GetHMACHashAlgorithm() string {
	fmt.Println("\nSelect Hash Algorithm:")
	fmt.Println("1. SHA-1")
	fmt.Println("2. SHA-256")
	fmt.Println("3. SHA-512")
	fmt.Println("4. BLAKE2b-256")
	fmt.Println("5. BLAKE2b-512")
	fmt.Println("6. BLAKE3")
	fmt.Println("7. Run Benchmark")

	choice := GetIntInput("Enter your choice (1-7): ", 1, 7)

	switch choice {
	case 1:
		return "sha1"
	case 2:
		return "sha256"
	case 3:
		return "sha512"
	case 4:
		return "blake2b-256"
	case 5:
		return "blake2b-512"
	case 6:
		return "blake3"
	case 7:
		return "benchmark"
	default:
		fmt.Println("Invalid choice. Defaulting to SHA-256")
		return "sha256"
	}
}

// RunHMACBenchmark runs a benchmark of all HMAC algorithms
func RunHMACBenchmark() (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep("HMAC Benchmark")
	v.AddStep("=============================")
	v.AddNote("This benchmark will test all available HMAC algorithms")
	v.AddNote("The test will use a sample text and run multiple iterations")
	v.AddSeparator()

	// Get sample text
	fmt.Print("\nEnter sample text for benchmarking (default: 'Hello, World!'): ")
	text := GetTextInput("Hello, World!")

	// Get number of iterations
	iterations := GetIntInput("\nEnter number of iterations (default: 10000): ", 1, 1000000)
	if iterations == 0 {
		iterations = 10000
	}

	v.AddStep(fmt.Sprintf("Running benchmark with %d iterations...", iterations))
	v.AddStep(fmt.Sprintf("Sample text: %s", text))
	v.AddSeparator()

	// Initialize processors for each algorithm
	algorithms := []string{
		"sha1",
		"sha256",
		"sha512",
		"blake2b-256",
		"blake2b-512",
		"blake3",
	}

	results := make([]struct {
		name     string
		duration time.Duration
	}, len(algorithms))

	// Create a channel for the loading animation
	done := make(chan bool)
	go func() {
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
	}()

	// Run benchmark for each algorithm
	for i, algo := range algorithms {
		processor := crypto.NewHMACProcessor()
		if err := processor.Configure(map[string]interface{}{
			"hashAlgorithm": algo,
		}); err != nil {
			done <- true // Stop the loading animation
			return "", nil, fmt.Errorf("failed to configure %s: %w", algo, err)
		}

		// Warm-up
		processor.Process(text, "encrypt")

		// Benchmark
		start := time.Now()
		for j := 0; j < iterations; j++ {
			processor.Process(text, "encrypt")
		}
		duration := time.Since(start)
		results[i] = struct {
			name     string
			duration time.Duration
		}{algo, duration}
	}

	// Stop the loading animation
	done <- true

	// Sort results by duration
	sort.Slice(results, func(i, j int) bool {
		return results[i].duration < results[j].duration
	})

	// Get fastest duration for percentage calculation
	fastestDuration := results[0].duration

	// Display results
	v.AddStep("Benchmark Results:")
	for i, result := range results {
		avgTime := float64(result.duration.Microseconds()) / float64(iterations)
		percentageDiff := float64(result.duration) / float64(fastestDuration) * 100

		// Format the percentage difference
		var diffStr string
		if i == 0 {
			diffStr = " (baseline)"
		} else {
			diffStr = fmt.Sprintf(" (+%.1f%%)", percentageDiff-100)
		}

		v.AddStep(fmt.Sprintf("%d. HMAC-%s: %d ops in %dms → avg: %.1fµs%s",
			i+1,
			strings.ToUpper(result.name),
			iterations,
			result.duration.Milliseconds(),
			avgTime,
			diffStr,
		))
	}

	// Add recommendations
	v.AddSeparator()
	v.AddStep("Recommendations:")
	v.AddStep("🚀 Fastest Algorithm: " + strings.ToUpper(results[0].name))
	v.AddStep("🛡️ Best Security (Balanced): BLAKE2b-512 or SHA-256")

	// Add performance comparison
	v.AddSeparator()
	v.AddStep("Performance Comparison:")
	v.AddStep(fmt.Sprintf("• %s is %.1f%% faster than SHA-256",
		strings.ToUpper(results[0].name),
		(float64(results[4].duration)/float64(results[0].duration)*100)-100))
	v.AddStep(fmt.Sprintf("• %s is %.1f%% faster than SHA-512",
		strings.ToUpper(results[0].name),
		(float64(results[5].duration)/float64(results[0].duration)*100)-100))

	return "", v.GetSteps(), nil
}

// GetTextInput gets text input with a default value
func GetTextInput(defaultValue string) string {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultValue
	}
	return input
}
