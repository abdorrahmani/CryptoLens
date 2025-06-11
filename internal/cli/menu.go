package cli

import (
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/benchmark"
	"github.com/abdorrahmani/cryptolens/internal/crypto"
	"github.com/abdorrahmani/cryptolens/internal/input"
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

		if choice == 13 {
			m.display.ShowGoodbye()
			return nil
		}

		if choice == 12 {
			if err := m.handleAttackMenu(); err != nil {
				m.display.ShowError(err)
			}
			continue
		}

		if err := m.processChoice(choice); err != nil {
			m.display.ShowError(err)
		}
	}
}

// handleAttackMenu handles the attack simulation menu
func (m *Menu) handleAttackMenu() error {
	for {
		m.display.ShowAttackMenu()

		choice, err := m.input.GetAttackChoice()
		if err != nil {
			return err
		}

		if choice == 6 {
			return nil // Back to main menu
		}

		if err := m.processAttackChoice(choice); err != nil {
			return err
		}
	}
}

// processAttackChoice handles the user's attack menu choice
func (m *Menu) processAttackChoice(choice int) error {
	processor, err := m.factory.CreateAttackProcessor(choice)
	if err != nil {
		return fmt.Errorf("failed to create attack processor: %w", err)
	}

	fmt.Printf("\n%s", m.display.(*ConsoleDisplay).theme.Format("Enter text to demonstrate the attack: ", "brightGreen bold"))
	text, err := m.input.GetText()
	if err != nil {
		return err
	}

	m.display.ShowProcessingMessage(text)

	result, steps, err := processor.Process(text, crypto.OperationEncrypt)
	if err != nil {
		return fmt.Errorf("failed to process: %w", err)
	}

	m.display.ShowResult(result, steps)
	return nil
}

// processChoice handles the user's menu choice
func (m *Menu) processChoice(choice int) error {
	fmt.Printf("Creating processor for choice %d\n", choice)
	processor, err := m.factory.CreateProcessor(choice)
	if err != nil {
		return fmt.Errorf("failed to create processor: %w", err)
	}

	// Get operation choice (skip for SHA-256, HMAC, PBKDF, DH, and X25519)
	operation := crypto.OperationEncrypt
	if choice != 4 && choice != 6 && choice != 7 && choice != 8 && choice != 9 { // Skip for SHA-256 (4), HMAC (6), PBKDF (7), DH (8), and X25519 (9)
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
				result, steps, err := benchmark.RunHMACBenchmark()
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

	// Configure PBKDF processor if selected
	if choice == 7 { // PBKDF option
		if configurable, ok := processor.(crypto.ConfigurableProcessor); ok {
			algo := GetPBKDFAlgorithm()
			if algo == "benchmark" {
				result, steps, err := benchmark.RunPBKDFBenchmark()
				if err != nil {
					return err
				}
				m.display.ShowResult(result, steps)
				return nil
			}
			if err := configurable.Configure(map[string]interface{}{
				"algorithm": algo,
			}); err != nil {
				return fmt.Errorf("failed to configure PBKDF processor: %w", err)
			}
		}
	}

	// Configure JWT processor if selected
	if choice == 10 { // JWT option
		if configurable, ok := processor.(crypto.ConfigurableProcessor); ok {
			algorithm := GetJWTAlgorithm()
			if err := configurable.Configure(map[string]interface{}{
				"algorithm": algorithm,
			}); err != nil {
				return fmt.Errorf("failed to configure JWT processor: %w", err)
			}
			// Get secret key for HS256
			if algorithm == "HS256" {
				fmt.Print("Enter secret key (default = my-secret-key): ")
				secretKey := input.GetTextInput("my-secret-key")
				if secretKey != "" {
					if err := configurable.Configure(map[string]interface{}{
						"secretKey": secretKey,
					}); err != nil {
						return fmt.Errorf("failed to configure JWT secret key: %w", err)
					}
				}
			}
		}
	}

	// Special handling for DH and X25519 demonstration
	if choice == 8 || choice == 9 {
		fmt.Printf("\n%s", m.display.(*ConsoleDisplay).theme.Format("Press Enter to start key exchange demonstration...", "brightGreen bold"))
		// Set DH mode to allow empty input
		if input, ok := m.input.(*ConsoleInput); ok {
			input.SetDHMode(true)
		}
		// Wait for Enter key
		if _, err := m.input.GetText(); err != nil {
			return err
		}
		// Reset DH mode
		if input, ok := m.input.(*ConsoleInput); ok {
			input.SetDHMode(false)
		}
		// Process with empty string for demonstration
		result, steps, err := processor.Process("", operation)
		if err != nil {
			return fmt.Errorf("failed to process: %w", err)
		}
		m.display.ShowResult(result, steps)
		return nil
	}

	// Regular processing for other algorithms
	fmt.Printf("\n%s", m.display.(*ConsoleDisplay).theme.Format("Enter text to process: ", "brightGreen bold"))
	text, err := m.input.GetText()
	if err != nil {
		return err
	}

	m.display.ShowProcessingMessage(text)

	result, steps, err := processor.Process(text, operation)
	if err != nil {
		return fmt.Errorf("failed to process: %w", err)
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

	choice := input.GetIntInput("Enter your choice (1-7): ", 1, 7)

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

// GetPBKDFAlgorithm prompts user to select a PBKDF algorithm
func GetPBKDFAlgorithm() string {
	fmt.Println("\nSelect PBKDF Algorithm:")
	fmt.Println("1. PBKDF2 (Password-Based Key Derivation Function 2)")
	fmt.Println("2. Argon2id (Memory-Hard Function)")
	fmt.Println("3. Scrypt (Memory-Hard Function)")
	fmt.Println("4. Run Benchmark on All")

	choice := input.GetIntInput("Enter your choice (1-4): ", 1, 4)

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

// GetJWTAlgorithm prompts user to select a JWT algorithm
func GetJWTAlgorithm() string {
	fmt.Println("\nSelect JWT Algorithm:")
	fmt.Println("1. HS256 (HMAC with SHA-256)")
	fmt.Println("2. RS256 (RSA with SHA-256)")
	fmt.Println("3. EdDSA (Ed25519)")

	choice := input.GetIntInput("Enter your choice (1-3): ", 1, 3)

	switch choice {
	case 1:
		return "HS256"
	case 2:
		return "RS256"
	case 3:
		return "EdDSA"
	default:
		fmt.Println("Invalid choice. Defaulting to HS256")
		return "HS256"
	}
}
