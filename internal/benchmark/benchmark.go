package benchmark

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/abdorrahmani/cryptolens/internal/crypto"
	"github.com/abdorrahmani/cryptolens/internal/input"
	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// BenchmarkResult represents the result of a benchmark run
type BenchmarkResult struct {
	name         string
	duration     time.Duration
	memoryUsage  uint64
	allocations  uint64
	platformInfo PlatformInfo
}

// PlatformInfo contains information about the system running the benchmark
type PlatformInfo struct {
	OS           string
	Architecture string
	CPUCount     int
	GoVersion    string
}

// getPlatformInfo returns information about the current platform
func getPlatformInfo() PlatformInfo {
	return PlatformInfo{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		CPUCount:     runtime.NumCPU(),
		GoVersion:    runtime.Version(),
	}
}

// RunHMACBenchmark runs a benchmark of all HMAC algorithms
func RunHMACBenchmark() (string, []string, error) {
	v := utils.NewVisualizer()
	setupBenchmark(v, "HMAC")

	text := getSampleText("Hello, World!")
	iterations := getIterations(10000, 1000000)

	v.AddStep(fmt.Sprintf("Running benchmark with %d iterations...", iterations))
	v.AddStep(fmt.Sprintf("Sample text: %s", text))
	v.AddSeparator()

	algorithms := []string{
		"sha1",
		"sha256",
		"sha512",
		"blake2b-256",
		"blake2b-512",
		"blake3",
	}

	results := runAlgorithmBenchmark(algorithms, text, iterations, func(algo string) (crypto.Processor, error) {
		processor := crypto.NewHMACProcessor()
		if err := processor.Configure(map[string]interface{}{
			"hashAlgorithm": algo,
		}); err != nil {
			return nil, fmt.Errorf("failed to configure %s: %w", algo, err)
		}
		return processor, nil
	})

	displayHMACResults(v, results, iterations)
	return "", v.GetSteps(), nil
}

// RunPBKDFBenchmark runs a benchmark of all PBKDF algorithms
func RunPBKDFBenchmark() (string, []string, error) {
	v := utils.NewVisualizer()
	setupBenchmark(v, "PBKDF")

	text := getSampleText("Hello")
	iterations := getPBKDFIterations()

	v.AddStep(fmt.Sprintf("Running benchmark with %d iterations...", iterations))
	v.AddStep(fmt.Sprintf("Sample text: %s", text))
	v.AddStep(fmt.Sprintf("Estimated time: %v", estimatePBKDFTime(iterations)))
	v.AddSeparator()

	algorithms := []string{
		"pbkdf2",
		"argon2id",
		"scrypt",
	}

	results := runAlgorithmBenchmark(algorithms, text, iterations, func(algo string) (crypto.Processor, error) {
		processor := crypto.NewPBKDFProcessor()
		if err := processor.Configure(map[string]interface{}{
			"algorithm": algo,
		}); err != nil {
			return nil, fmt.Errorf("failed to configure %s: %w", algo, err)
		}
		return processor, nil
	})

	displayPBKDFResults(v, results, iterations)
	return "", v.GetSteps(), nil
}

func setupBenchmark(v *utils.Visualizer, name string) {
	v.AddStep(fmt.Sprintf("%s Benchmark", name))
	v.AddStep("=============================")
	v.AddNote(fmt.Sprintf("This benchmark will test all available %s algorithms", name))
	v.AddNote("The test will use a sample text and run multiple iterations")
	v.AddSeparator()
}

func getSampleText(defaultValue string) string {
	fmt.Printf("\nEnter sample text for benchmarking (default: '%s'): ", defaultValue)
	return input.GetTextInput(defaultValue)
}

func getIterations(defaultValue, maxValue int) int {
	iterations := input.GetIntInput("\nEnter number of iterations (default: 10000): ", 1, maxValue)
	if iterations == 0 {
		iterations = defaultValue
	}
	return iterations
}

func getPBKDFIterations() int {
	fmt.Print("\nEnter number of iterations (default: 100): ")
	fmt.Print("\n⚠️  Warning: Large numbers will take a long time to complete")
	fmt.Print("\n    Recommended: 10-100 iterations")
	fmt.Print("\n    PBKDF2: ~15ms per operation")
	fmt.Print("\n    Argon2id: ~36ms per operation")
	fmt.Print("\n    Scrypt: ~266ms per operation")
	fmt.Print("\n    (1000 iterations ≈ 4.5 minutes total)\n")

	iterations := input.GetIntInput("\nEnter your choice: ", 1, 1000)
	if iterations == 0 {
		iterations = 100
	}
	return iterations
}

func estimatePBKDFTime(iterations int) time.Duration {
	return time.Duration(iterations) * (15 + 36 + 266) * time.Millisecond
}

func runAlgorithmBenchmark(
	algorithms []string,
	text string,
	iterations int,
	createProcessor func(string) (crypto.Processor, error),
) []BenchmarkResult {
	results := make([]BenchmarkResult, len(algorithms))
	platformInfo := getPlatformInfo()

	done := make(chan bool)
	go showLoadingAnimation(done)

	for i, algo := range algorithms {
		processor, err := createProcessor(algo)
		if err != nil {
			done <- true
			return nil
		}

		if _, _, err := processor.Process(text, "encrypt"); err != nil {
			done <- true
			return nil
		}

		// Reset memory stats
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		startAllocs := m.TotalAlloc
		startMemory := m.Alloc

		start := time.Now()
		for j := 0; j < iterations; j++ {
			if _, _, err := processor.Process(text, "encrypt"); err != nil {
				done <- true
				return nil
			}
		}
		duration := time.Since(start)

		// Get final memory stats
		runtime.ReadMemStats(&m)
		memoryUsage := m.Alloc - startMemory
		allocations := m.TotalAlloc - startAllocs

		results[i] = BenchmarkResult{
			name:         algo,
			duration:     duration,
			memoryUsage:  memoryUsage,
			allocations:  allocations,
			platformInfo: platformInfo,
		}
	}

	done <- true
	sort.Slice(results, func(i, j int) bool {
		return results[i].duration < results[j].duration
	})

	return results
}

func showLoadingAnimation(done chan bool) {
	loadingChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	i := 0
	for {
		select {
		case <-done:
			fmt.Print("\r\033[K")
			return
		default:
			fmt.Printf("\r%s Running benchmark... %s", loadingChars[i], strings.Repeat(".", (i%5)+1))
			i = (i + 1) % len(loadingChars)
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func displayHMACResults(v *utils.Visualizer, results []BenchmarkResult, iterations int) {
	fastestDuration := results[0].duration

	// Display platform information
	v.AddStep("Platform Information:")
	v.AddStep(fmt.Sprintf("OS: %s", results[0].platformInfo.OS))
	v.AddStep(fmt.Sprintf("Architecture: %s", results[0].platformInfo.Architecture))
	v.AddStep(fmt.Sprintf("CPU Cores: %d", results[0].platformInfo.CPUCount))
	v.AddStep(fmt.Sprintf("Go Version: %s", results[0].platformInfo.GoVersion))
	v.AddSeparator()

	v.AddStep("Benchmark Results:")
	for i, result := range results {
		avgTime := float64(result.duration.Microseconds()) / float64(iterations)
		percentageDiff := float64(result.duration) / float64(fastestDuration) * 100
		memoryPerOp := float64(result.memoryUsage) / float64(iterations)
		allocsPerOp := float64(result.allocations) / float64(iterations)

		var diffStr string
		if i == 0 {
			diffStr = " (baseline)"
		} else {
			diffStr = fmt.Sprintf(" (+%.1f%%)", percentageDiff-100)
		}

		v.AddStep(fmt.Sprintf("%d. HMAC-%s:", i+1, strings.ToUpper(result.name)))
		v.AddStep(fmt.Sprintf("   • Time: %d ops in %dms → avg: %.1fµs%s",
			iterations,
			result.duration.Milliseconds(),
			avgTime,
			diffStr))
		v.AddStep(fmt.Sprintf("   • Memory: %.2f KB per operation", memoryPerOp/1024))
		v.AddStep(fmt.Sprintf("   • Allocations: %.1f per operation", allocsPerOp))
	}

	// Add ASCII art visualization
	v.AddSeparator()
	v.AddStep("Benchmark Visual Comparison:")

	// Calculate the scale factor for visualization
	maxChars := 50
	scaleFactor := float64(maxChars) / float64(results[len(results)-1].duration.Milliseconds())

	for _, result := range results {
		avgTime := float64(result.duration.Microseconds()) / float64(iterations)
		barLength := int(float64(result.duration.Milliseconds()) * scaleFactor)
		bar := strings.Repeat("█", barLength)
		// Add background color and spacing
		v.AddStep(fmt.Sprintf("\033[32m%-15s \033[40m%s\033[0m\033[32m (%.1fµs)\033[0m",
			"HMAC-"+strings.ToUpper(result.name),
			bar,
			avgTime))
	}

	v.AddSeparator()
	v.AddStep("Recommendations:")
	v.AddStep("🚀 Fastest Algorithm: " + strings.ToUpper(results[0].name))
	v.AddStep("🛡️ Best Security (Balanced): BLAKE2b-512 or SHA-256")
	v.AddStep("💾 Most Memory Efficient: " + strings.ToUpper(results[0].name))

	v.AddSeparator()
	v.AddStep("Performance Comparison:")
	v.AddStep(fmt.Sprintf("• %s is %.1f%% faster than SHA-256",
		strings.ToUpper(results[0].name),
		(float64(results[4].duration)/float64(results[0].duration)*100)-100))
	v.AddStep(fmt.Sprintf("• %s is %.1f%% faster than SHA-512",
		strings.ToUpper(results[0].name),
		(float64(results[5].duration)/float64(results[0].duration)*100)-100))
}

func displayPBKDFResults(v *utils.Visualizer, results []BenchmarkResult, iterations int) {
	fastestDuration := results[0].duration

	// Display platform information
	v.AddStep("Platform Information:")
	v.AddStep(fmt.Sprintf("OS: %s", results[0].platformInfo.OS))
	v.AddStep(fmt.Sprintf("Architecture: %s", results[0].platformInfo.Architecture))
	v.AddStep(fmt.Sprintf("CPU Cores: %d", results[0].platformInfo.CPUCount))
	v.AddStep(fmt.Sprintf("Go Version: %s", results[0].platformInfo.GoVersion))
	v.AddSeparator()

	v.AddStep("Benchmark Results:")
	for i, result := range results {
		avgTime := float64(result.duration.Microseconds()) / float64(iterations)
		percentageDiff := float64(result.duration) / float64(fastestDuration) * 100
		memoryPerOp := float64(result.memoryUsage) / float64(iterations)
		allocsPerOp := float64(result.allocations) / float64(iterations)

		var diffStr string
		if i == 0 {
			diffStr = " (baseline)"
		} else {
			diffStr = fmt.Sprintf(" (+%.1f%%)", percentageDiff-100)
		}

		v.AddStep(fmt.Sprintf("%d. %s:", i+1, strings.ToUpper(result.name)))
		v.AddStep(fmt.Sprintf("   • Time: %d ops in %dms → avg: %.2fms%s",
			iterations,
			result.duration.Milliseconds(),
			avgTime/1000,
			diffStr))
		v.AddStep(fmt.Sprintf("   • Memory: %.2f MB per operation", memoryPerOp/1024/1024))
		v.AddStep(fmt.Sprintf("   • Allocations: %.1f per operation", allocsPerOp))
	}

	// Add ASCII art visualization
	v.AddSeparator()
	v.AddStep("Benchmark Visual Comparison:")

	// Calculate the scale factor for visualization
	maxChars := 50
	scaleFactor := float64(maxChars) / float64(results[len(results)-1].duration.Milliseconds())

	for _, result := range results {
		avgTime := float64(result.duration.Microseconds()) / float64(iterations) / 1000 // Convert to ms
		barLength := int(float64(result.duration.Milliseconds()) * scaleFactor)
		bar := strings.Repeat("█", barLength)
		// Add background color and spacing
		v.AddStep(fmt.Sprintf("\033[32m%-10s \033[40m%s\033[0m\033[32m (%.1fms)\033[0m",
			strings.ToUpper(result.name),
			bar,
			avgTime))
	}

	v.AddSeparator()
	v.AddStep("Recommendations:")
	v.AddStep("🚀 Fastest Algorithm: " + strings.ToUpper(results[0].name))
	v.AddStep("🛡️ Most Secure: Argon2id (Memory-hard function with better resistance to GPU attacks)")
	v.AddStep("💾 Most Memory Efficient: " + strings.ToUpper(results[0].name))

	v.AddSeparator()
	v.AddStep("Performance Comparison:")
	v.AddStep(fmt.Sprintf("• %s is %.1f%% faster than Argon2id",
		strings.ToUpper(results[0].name),
		(float64(results[1].duration)/float64(results[0].duration)*100)-100))
	v.AddStep(fmt.Sprintf("• %s is %.1f%% faster than Scrypt",
		strings.ToUpper(results[0].name),
		(float64(results[2].duration)/float64(results[0].duration)*100)-100))
}
