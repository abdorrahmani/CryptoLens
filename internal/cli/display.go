package cli

import (
	"fmt"
)

// ConsoleDisplay implements DisplayHandler for console output
type ConsoleDisplay struct{}

// NewConsoleDisplay creates a new console display handler
func NewConsoleDisplay() *ConsoleDisplay {
	return &ConsoleDisplay{}
}

// ShowMenu displays the main menu
func (d *ConsoleDisplay) ShowMenu() {
	fmt.Println("\nCryptoLens - Choose an encryption method:")
	fmt.Println("1. Base64 Encoding")
	fmt.Println("2. Caesar Cipher")
	fmt.Println("3. AES Encryption")
	fmt.Println("4. SHA-256 Hashing")
	fmt.Println("5. Exit")
	fmt.Print("\nEnter your choice (1-5): ")
}

// ShowResult displays the processing result and steps
func (d *ConsoleDisplay) ShowResult(result string, steps []string) {
	fmt.Println("\nResult:", result)
	fmt.Println("\nProcessing Steps:")
	for i, step := range steps {
		fmt.Printf("%d. %s\n", i+1, step)
	}
	fmt.Println("----------------------------------------")
}

// ShowError displays an error message
func (d *ConsoleDisplay) ShowError(err error) {
	fmt.Printf("\nError: %v\n", err)
	fmt.Println("----------------------------------------")
}

// ShowWelcome displays the welcome message
func (d *ConsoleDisplay) ShowWelcome() {
	fmt.Println("Welcome to CryptoLens!")
	fmt.Println("This program demonstrates various encryption methods.")
	fmt.Println("----------------------------------------")
}

// ShowGoodbye displays the goodbye message
func (d *ConsoleDisplay) ShowGoodbye() {
	fmt.Println("\nThank you for using CryptoLens!")
	fmt.Println("Goodbye!")
}

// ShowMessage displays the prompt for user input
func (d *ConsoleDisplay) ShowMessage(message string) {
	fmt.Print("\nEnter text to process: ")
}

// ShowProcessingMessage displays the message being processed
func (d *ConsoleDisplay) ShowProcessingMessage(message string) {
	fmt.Printf("\nProcessing message: %s\n", message)
	fmt.Println("----------------------------------------")
}
