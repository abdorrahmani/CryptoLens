package cli

import (
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/crypto"
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

	choice := GetIntInput("Enter your choice (1-5): ", 1, 5)

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
	default:
		fmt.Println("Invalid choice. Defaulting to SHA-256")
		return "sha256"
	}
}
