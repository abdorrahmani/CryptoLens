package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/abdorrahmani/cryptolens/internal/crypto"
	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// BenchmarkRunner handles running benchmarks for different algorithms
type BenchmarkRunner struct {
	display DisplayHandler
	input   UserInputHandler
	utils   *MenuUtils
}

// NewBenchmarkRunner creates a new benchmark runner
func NewBenchmarkRunner(display DisplayHandler, input UserInputHandler) *BenchmarkRunner {
	return &BenchmarkRunner{
		display: display,
		input:   input,
		utils:   NewMenuUtils(display, input),
	}
}

// RunHMACBenchmark runs a benchmark of all HMAC algorithms
func (b *BenchmarkRunner) RunHMACBenchmark() (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep("HMAC Benchmark")
	v.AddStep("=============================")
	v.AddNote("This benchmark will test all available HMAC algorithms")
	v.AddNote("The test will use a sample text and run multiple iterations")
	v.AddSeparator()

	// Get sample text and iterations
	text := b.utils.GetBenchmarkText("Hello, World!")
	iterations := b.utils.GetBenchmarkIterations(10000, 1, 1000000)

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
	go b.utils.ShowLoadingAnimation(done)

	// Run benchmark for each algorithm
	for i, algo := range algorithms {
		processor := crypto.NewHMACProcessor()
		if err := processor.Configure(map[string]interface{}{
			"hashAlgorithm": algo,
		}); err != nil {
			done <- true
			return "", nil, fmt.Errorf("failed to configure %s: %w", algo, err)
		}

		// Warm-up
		if _, _, err := processor.Process(text, "encrypt"); err != nil {
			done <- true
			return "", nil, fmt.Errorf("failed to warm up %s: %w", algo, err)
		}

		// Benchmark
		start := time.Now()
		for j := 0; j < iterations; j++ {
			if _, _, err := processor.Process(text, "encrypt"); err != nil {
				done <- true
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
		v.AddStep(b.utils.FormatBenchmarkResult(result, iterations, fastestDuration, i))
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

// RunPBKDFBenchmark runs a benchmark of all PBKDF algorithms
func (b *BenchmarkRunner) RunPBKDFBenchmark() (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep("PBKDF Benchmark")
	v.AddStep("=============================")
	v.AddNote("This benchmark will test all available PBKDF algorithms")
	v.AddNote("The test will use a sample text and run multiple iterations")
	v.AddSeparator()

	// Get sample text
	text := b.utils.GetBenchmarkText("Hello")

	// Get number of iterations with warning
	b.utils.ShowBenchmarkWarning()
	iterations := b.utils.GetBenchmarkIterations(100, 1, 1000)

	// Show estimated time
	estimatedTime := b.utils.CalculateEstimatedTime(iterations)
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
	go b.utils.ShowLoadingAnimation(done)

	// Run benchmark for each algorithm
	for i, algo := range algorithms {
		processor := crypto.NewPBKDFProcessor()
		if err := processor.Configure(map[string]interface{}{
			"algorithm": algo,
		}); err != nil {
			done <- true
			return "", nil, fmt.Errorf("failed to configure %s: %w", algo, err)
		}

		// Warm-up
		if _, _, err := processor.Process(text, "benchmark"); err != nil {
			done <- true
			return "", nil, fmt.Errorf("failed to warm up %s: %w", algo, err)
		}

		// Benchmark
		start := time.Now()
		for j := 0; j < iterations; j++ {
			if _, _, err := processor.Process(text, "benchmark"); err != nil {
				done <- true
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
		v.AddStep(b.utils.FormatBenchmarkResult(result, iterations, fastestDuration, i))
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
