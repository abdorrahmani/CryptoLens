package cli

import "github.com/abdorrahmani/cryptolens/internal/crypto"

// MenuInterface defines the contract for menu operations
type MenuInterface interface {
	Run() error
}

// ProcessorFactory defines the contract for creating encryption processors
type ProcessorFactory interface {
	CreateProcessor(choice int) (crypto.Processor, error)
}

// UserInputHandler defines the contract for handling user input
type UserInputHandler interface {
	GetChoice() (int, error)
	GetText() (string, error)
	GetOperation() (string, error)
}

// DisplayHandler defines the contract for displaying output
type DisplayHandler interface {
	ShowMenu()
	ShowResult(result string, steps []string)
	ShowError(err error)
	ShowWelcome()
	ShowGoodbye()
	ShowMessage(message string)
	ShowProcessingMessage(message string)
	ShowOperationPrompt()
}
