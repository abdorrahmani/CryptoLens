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
	display  DisplayHandler
	input    UserInputHandler
	factory  ProcessorFactory
	handlers map[int]AlgorithmHandler
	utils    *MenuUtils
}

// NewMenu creates a new menu instance
func NewMenu(display DisplayHandler, input UserInputHandler, factory ProcessorFactory) *Menu {
	menu := &Menu{
		display:  display,
		input:    input,
		factory:  factory,
		handlers: make(map[int]AlgorithmHandler),
		utils:    NewMenuUtils(display, input),
	}
	menu.registerHandlers()
	return menu
}

// registerHandlers registers all algorithm handlers
func (m *Menu) registerHandlers() {
	// Register special handlers
	m.handlers[OptionHMAC] = NewHMACHandler(m.display, m.input)
	m.handlers[OptionPBKDF] = NewPBKDFHandler(m.display, m.input)

	// Register default handler for other algorithms
	defaultHandler := NewDefaultHandler(m.display, m.input)
	for _, option := range GetMenuOptions() {
		if _, exists := m.handlers[option.ID]; !exists && option.ID != OptionExit {
			m.handlers[option.ID] = defaultHandler
		}
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

		if choice == OptionExit {
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
	handler, exists := m.handlers[choice]
	if !exists {
		return fmt.Errorf("invalid choice: %d", choice)
	}

	processor, err := m.factory.CreateProcessor(choice)
	if err != nil {
		return fmt.Errorf("failed to create processor: %w", err)
	}

	operation := m.getOperation(choice)
	return m.utils.ProcessText(handler, processor, operation)
}

// getOperation determines the operation based on the menu choice
func (m *Menu) getOperation(choice int) string {
	if GetSkipOperationOptions()[choice] {
		return GetDefaultOperation(choice)
	}

	operation, err := m.input.GetOperation()
	if err != nil {
		return GetDefaultOperation(choice)
	}
	return operation
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
		if _, _, err := processor.Process(text, "encrypt"); err != nil {
			done <- true // Stop the loading animation
			return "", nil, fmt.Errorf("failed to warm up %s: %w", algo, err)
		}

		// Benchmark
		start := time.Now()
		for j := 0; j < iterations; j++ {
			if _, _, err := processor.Process(text, "encrypt"); err != nil {
				done <- true // Stop the loading animation
				return "", nil, fmt.Errorf("failed to process iteration %d for %s: %w", j, algo, err)
			}
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

// GetPBKDFAlgorithm prompts user to select a PBKDF algorithm
func GetPBKDFAlgorithm() string {
	fmt.Println("\nSelect PBKDF Algorithm:")
	fmt.Println("1. PBKDF2 (Password-Based Key Derivation Function 2)")
	fmt.Println("2. Argon2id (Memory-Hard Function)")
	fmt.Println("3. Scrypt (Memory-Hard Function)")
	fmt.Println("4. Run Benchmark on All")

	choice := GetIntInput("Enter your choice (1-4): ", 1, 4)

	switch choice {
	case 1:
		return "pbkdf2"
	case 2:
		return "argon2id"
	case 3:
		return "scrypt"
	case 4:
		return "benchmark"
	default:
		fmt.Println("Invalid choice. Defaulting to Argon2id")
		return "argon2id"
	}
}

// RunPBKDFBenchmark runs a benchmark of all PBKDF algorithms
func RunPBKDFBenchmark() (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep("PBKDF Benchmark")
	v.AddStep("=============================")
	v.AddNote("This benchmark will test all available PBKDF algorithms")
	v.AddNote("The test will use a sample text and run multiple iterations")
	v.AddSeparator()

	// Get sample text
	fmt.Print("\nEnter sample text for benchmarking (default: 'Hello'): ")
	text := GetTextInput("Hello")

	// Get number of iterations with warning for large numbers
	fmt.Print("\nEnter number of iterations (default: 100): ")
	fmt.Print("\n⚠️  Warning: Large numbers will take a long time to complete")
	fmt.Print("\n    Recommended: 10-100 iterations")
	fmt.Print("\n    PBKDF2: ~15ms per operation")
	fmt.Print("\n    Argon2id: ~36ms per operation")
	fmt.Print("\n    Scrypt: ~266ms per operation")
	fmt.Print("\n    (1000 iterations ≈ 4.5 minutes total)\n")

	iterations := GetIntInput("\nEnter your choice: ", 1, 1000)
	if iterations == 0 {
		iterations = 100
	}

	// Show estimated time
	estimatedTime := time.Duration(iterations) * (15 + 36 + 266) * time.Millisecond
	v.AddStep(fmt.Sprintf("Running benchmark with %d iterations...", iterations))
	v.AddStep(fmt.Sprintf("Sample text: %s", text))
	v.AddStep(fmt.Sprintf("Estimated time: %v", estimatedTime.Round(time.Second)))
	v.AddSeparator()

	// Initialize processors for each algorithm
	algorithms := []string{
		"pbkdf2",
		"argon2id",
		"scrypt",
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
		processor := crypto.NewPBKDFProcessor()
		if err := processor.Configure(map[string]interface{}{
			"algorithm": algo,
		}); err != nil {
			done <- true // Stop the loading animation
			return "", nil, fmt.Errorf("failed to configure %s: %w", algo, err)
		}

		// Warm-up
		if _, _, err := processor.Process(text, "benchmark"); err != nil {
			done <- true // Stop the loading animation
			return "", nil, fmt.Errorf("failed to warm up %s: %w", algo, err)
		}

		// Benchmark
		start := time.Now()
		for j := 0; j < iterations; j++ {
			if _, _, err := processor.Process(text, "benchmark"); err != nil {
				done <- true // Stop the loading animation
				return "", nil, fmt.Errorf("failed to process iteration %d for %s: %w", j, algo, err)
			}
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

		v.AddStep(fmt.Sprintf("%d. %s: %d ops in %dms → avg: %.2fms%s",
			i+1,
			strings.ToUpper(result.name),
			iterations,
			result.duration.Milliseconds(),
			avgTime/1000, // Convert to milliseconds
			diffStr,
		))
	}

	// Add recommendations
	v.AddSeparator()
	v.AddStep("Recommendations:")
	v.AddStep("🚀 Fastest Algorithm: " + strings.ToUpper(results[0].name))
	v.AddStep("🛡️ Most Secure: Argon2id (Memory-hard function with better resistance to GPU attacks)")

	// Add performance comparison
	v.AddSeparator()
	v.AddStep("Performance Comparison:")
	v.AddStep(fmt.Sprintf("• %s is %.1f%% faster than Argon2id",
		strings.ToUpper(results[0].name),
		(float64(results[1].duration)/float64(results[0].duration)*100)-100))
	v.AddStep(fmt.Sprintf("• %s is %.1f%% faster than Scrypt",
		strings.ToUpper(results[0].name),
		(float64(results[2].duration)/float64(results[0].duration)*100)-100))

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
