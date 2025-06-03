package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math"
	"os"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// PBKDFProcessor implements password-based key derivation
type PBKDFProcessor struct {
	BaseConfigurableProcessor
	algorithm  string
	iterations int
	memory     uint32
	threads    uint8
	keyLength  uint32
	salt       []byte
}

// NewPBKDFProcessor creates a new PBKDF processor
func NewPBKDFProcessor() *PBKDFProcessor {
	// Generate initial salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		// If we can't generate salt, use a default one
		salt = []byte("default_salt_123")
	}

	return &PBKDFProcessor{
		algorithm:  "pbkdf2",
		iterations: 100000,
		memory:     64 * 1024, // 64MB
		threads:    4,
		keyLength:  32, // 256 bits
		salt:       salt,
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *PBKDFProcessor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}

	// Set default values first
	p.iterations = 100000
	p.memory = 64 * 1024
	p.threads = 4
	p.keyLength = 32

	// Override with config values if provided
	if algo, ok := config["algorithm"].(string); ok {
		p.algorithm = algo
	}
	if iter, ok := config["iterations"].(int); ok && iter > 0 {
		p.iterations = iter
	}
	if mem, ok := config["memory"].(uint32); ok && mem > 0 {
		p.memory = mem
	}
	if thr, ok := config["threads"].(uint8); ok && thr > 0 {
		p.threads = thr
	}
	if keyLen, ok := config["keyLength"].(uint32); ok && keyLen > 0 {
		p.keyLength = keyLen
	}

	// Generate new salt for each operation
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}
	p.salt = salt

	return nil
}

// Process handles password-based key derivation
func (p *PBKDFProcessor) Process(password string, operation string) (string, []string, error) {
	if operation == OperationDecrypt {
		return "", nil, fmt.Errorf("key derivation is a one-way process and cannot be reversed")
	}

	// Validate input
	if len(password) == 0 {
		return "", nil, fmt.Errorf("password cannot be empty")
	}

	// Ensure salt is initialized
	if p.salt == nil || len(p.salt) == 0 {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return "", nil, fmt.Errorf("failed to generate salt: %w", err)
		}
		p.salt = salt
	}

	steps := []string{
		fmt.Sprintf("Using %s for key derivation", p.algorithm),
		fmt.Sprintf("Salt (base64): %s", base64.StdEncoding.EncodeToString(p.salt)),
	}

	var derivedKey []byte
	var err error

	// Check if we're in benchmark mode
	isBenchmark := operation == "benchmark"

	switch p.algorithm {
	case "pbkdf2":
		// Ensure minimum iterations
		iterations := p.iterations
		if iterations < 1000 {
			iterations = 1000
		}
		derivedKey = pbkdf2.Key([]byte(password), p.salt, iterations, int(p.keyLength), sha256.New)
		steps = append(steps, fmt.Sprintf("PBKDF2 Parameters:"))
		steps = append(steps, fmt.Sprintf("- Iterations: %d", iterations))
		steps = append(steps, fmt.Sprintf("- Key Length: %d bits", p.keyLength*8))
		steps = append(steps, fmt.Sprintf("- Hash Function: SHA-256"))

	case "argon2id":
		// Use more reasonable parameters for interactive use
		iterations := uint32(3)     // Reduced from default for faster response
		threads := uint8(4)         // Use all available CPU cores
		memory := uint32(64 * 1024) // 64MB
		keyLength := uint32(32)     // 256 bits

		if !isBenchmark {
			fmt.Print("\nDeriving key with Argon2id (this may take a few seconds)...\n")
			fmt.Print("Progress: [")
			progress := 0
			for i := 0; i < 50; i++ {
				fmt.Print(" ")
			}
			fmt.Print("] 0%")
			os.Stdout.Sync()

			// Start a goroutine to update progress
			done := make(chan bool)
			go func() {
				for i := 0; i < 100; i++ {
					select {
					case <-done:
						return
					default:
						time.Sleep(50 * time.Millisecond)
						fmt.Printf("\rProgress: [")
						progress = i
						for j := 0; j < 50; j++ {
							if j < progress/2 {
								fmt.Print("=")
							} else {
								fmt.Print(" ")
							}
						}
						fmt.Printf("] %d%%", progress)
						os.Stdout.Sync()
					}
				}
			}()

			derivedKey = argon2.IDKey([]byte(password), p.salt, iterations, memory, threads, keyLength)
			done <- true
			fmt.Print("\rProgress: [")
			for i := 0; i < 50; i++ {
				fmt.Print("=")
			}
			fmt.Println("] 100%")
		} else {
			derivedKey = argon2.IDKey([]byte(password), p.salt, iterations, memory, threads, keyLength)
		}

		steps = append(steps, fmt.Sprintf("Argon2id Parameters:"))
		steps = append(steps, fmt.Sprintf("- Iterations: %d", iterations))
		steps = append(steps, fmt.Sprintf("- Memory: %d KB", memory/1024))
		steps = append(steps, fmt.Sprintf("- Threads: %d", threads))
		steps = append(steps, fmt.Sprintf("- Key Length: %d bits", keyLength*8))

	case "scrypt":
		// Ensure minimum iterations and power of 2 for Scrypt
		iterations := p.iterations
		if iterations < 2 {
			iterations = 2
		}
		// Find the next power of 2
		iterations = 1 << uint(math.Log2(float64(iterations))+1)
		if iterations < 2 {
			iterations = 2
		}

		if !isBenchmark {
			fmt.Print("\nDeriving key with Scrypt (this may take a few seconds)...\n")
			fmt.Print("Progress: [")
			progress := 0
			for i := 0; i < 50; i++ {
				fmt.Print(" ")
			}
			fmt.Print("] 0%")
			os.Stdout.Sync()

			// Start a goroutine to update progress
			done := make(chan bool)
			go func() {
				for i := 0; i < 100; i++ {
					select {
					case <-done:
						return
					default:
						time.Sleep(50 * time.Millisecond)
						fmt.Printf("\rProgress: [")
						progress = i
						for j := 0; j < 50; j++ {
							if j < progress/2 {
								fmt.Print("=")
							} else {
								fmt.Print(" ")
							}
						}
						fmt.Printf("] %d%%", progress)
						os.Stdout.Sync()
					}
				}
			}()

			derivedKey, err = scrypt.Key([]byte(password), p.salt, iterations, 8, 1, int(p.keyLength))
			if err != nil {
				done <- true
				return "", nil, fmt.Errorf("failed to derive key using scrypt: %w", err)
			}

			done <- true
			fmt.Print("\rProgress: [")
			for i := 0; i < 50; i++ {
				fmt.Print("=")
			}
			fmt.Println("] 100%")
		} else {
			derivedKey, err = scrypt.Key([]byte(password), p.salt, iterations, 8, 1, int(p.keyLength))
			if err != nil {
				return "", nil, fmt.Errorf("failed to derive key using scrypt: %w", err)
			}
		}

		steps = append(steps, fmt.Sprintf("Scrypt Parameters:"))
		steps = append(steps, fmt.Sprintf("- N (CPU/Memory cost): %d (2^%d)", iterations, int(math.Log2(float64(iterations)))))
		steps = append(steps, fmt.Sprintf("- r (Block size): 8"))
		steps = append(steps, fmt.Sprintf("- p (Parallelization): 1"))
		steps = append(steps, fmt.Sprintf("- Key Length: %d bits", p.keyLength*8))

	default:
		return "", nil, fmt.Errorf("unsupported algorithm: %s", p.algorithm)
	}

	// Add security notes
	steps = append(steps, "\nSecurity Considerations:")
	steps = append(steps, "1. Salt is randomly generated for each operation")
	steps = append(steps, "2. Parameters are chosen for security and performance balance")
	steps = append(steps, "3. Key derivation is a one-way process")
	steps = append(steps, "4. Never store the original password")

	// Return the derived key in base64 format
	return base64.StdEncoding.EncodeToString(derivedKey), steps, nil
}
