package cli

import (
	"fmt"
	"strings"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// ConsoleDisplay implements DisplayHandler for console output
type ConsoleDisplay struct {
	theme utils.Theme
}

// NewConsoleDisplay creates a new console display handler
func NewConsoleDisplay() *ConsoleDisplay {
	return &ConsoleDisplay{
		theme: utils.DefaultTheme,
	}
}

// ShowMenu displays the main menu
func (d *ConsoleDisplay) ShowMenu() {
	fmt.Printf("\n%s\n", d.theme.Format("CryptoLens - Choose an encryption method:", "bold cyan"))
	fmt.Printf("%s\n", d.theme.Format("1. Base64 Encoding", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("2. Caesar Cipher", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("3. AES Encryption", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("4. SHA-256 Hashing", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("5. RSA Encryption", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("6. HMAC Authentication", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("7. Exit", "yellow"))
	fmt.Printf("\n%s", d.theme.Format("Enter your choice (1-7): ", "green"))
}

// ShowResult displays the processing result and steps
func (d *ConsoleDisplay) ShowResult(result string, steps []string) {
	fmt.Printf("\n%s\n", d.theme.Format("Result:", "bold brightGreen"))
	fmt.Printf("%s\n", d.theme.Format(result, "brightGreen"))

	fmt.Printf("\n%s\n", d.theme.Format("Processing Steps:", "bold brightCyan"))
	for i, step := range steps {
		if strings.HasPrefix(step, "Note:") {
			fmt.Printf("%s\n", d.theme.Format(step, "dim"))
		} else if strings.HasPrefix(step, "How") || strings.HasPrefix(step, "Security") {
			fmt.Printf("\n%s\n", d.theme.Format(step, "bold"))
		} else if strings.Contains(step, "->") {
			fmt.Printf("%s\n", d.theme.Format(step, "brightYellow"))
		} else if strings.HasPrefix(step, "Character") {
			fmt.Printf("%s\n", d.theme.Format(step, "brightPurple"))
		} else if strings.HasPrefix(step, "ASCII") || strings.HasPrefix(step, "Binary") {
			fmt.Printf("%s\n", d.theme.Format(step, "brightBlue"))
		} else {
			fmt.Printf("%s\n", d.theme.Format(fmt.Sprintf("%d. %s", i+1, step), "yellow"))
		}
	}
	fmt.Printf("%s\n", d.theme.Format("----------------------------------------", "dim blue"))
}

// ShowError displays an error message
func (d *ConsoleDisplay) ShowError(err error) {
	fmt.Printf("\n%s %s\n", d.theme.Format("Error:", "bold brightRed"), d.theme.Format(err.Error(), "red"))
	if err.Error() == "invalid base64 string: illegal base64 data at input byte 0" {
		fmt.Printf("%s\n", d.theme.Format("Note: For AES decryption, please enter the previously encrypted text in base64 format", "dim yellow"))
	}
	fmt.Printf("%s\n", d.theme.Format("----------------------------------------", "dim blue"))
}

// ShowWelcome displays the welcome message
func (d *ConsoleDisplay) ShowWelcome() {
	fmt.Printf("%s\n", d.theme.Format("Welcome to CryptoLens!", "bold brightCyan"))
	fmt.Printf("%s\n", d.theme.Format("This program demonstrates various encryption methods.", "dim white"))
	fmt.Printf("%s\n", d.theme.Format("----------------------------------------", "dim blue"))
}

// ShowGoodbye displays the goodbye message
func (d *ConsoleDisplay) ShowGoodbye() {
	fmt.Printf("\n%s\n", d.theme.Format("Thank you for using CryptoLens!", "brightCyan bold"))
	fmt.Printf("%s\n", d.theme.Format("Goodbye!", "brightCyan bold"))
}

// ShowMessage displays the prompt for user input
func (d *ConsoleDisplay) ShowMessage(message string) {
	if message == "aes_decrypt" {
		fmt.Printf("\n%s", d.theme.Format("Enter the encrypted text (in base64 format): ", "brightGreen bold"))
	} else {
		fmt.Printf("\n%s", d.theme.Format("Enter text to process: ", "brightGreen bold"))
	}
}

// ShowProcessingMessage displays the message being processed
func (d *ConsoleDisplay) ShowProcessingMessage(message string) {
	fmt.Printf("\n%s %s\n", d.theme.Format("Processing message:", "bold brightPurple"), d.theme.Format(message, "purple"))
	fmt.Printf("%s\n", d.theme.Format("----------------------------------------", "dim blue"))
}

// ShowOperationPrompt displays the operation selection prompt
func (d *ConsoleDisplay) ShowOperationPrompt() {
	fmt.Printf("\n%s\n", d.theme.Format("Choose operation:", "bold brightCyan"))
	fmt.Printf("%s\n", d.theme.Format("1. Encrypt", "brightYellow bold"))
	fmt.Printf("%s\n", d.theme.Format("2. Decrypt", "brightYellow bold"))
	fmt.Printf("\n%s", d.theme.Format("Enter your choice (1-2): ", "brightGreen bold"))
}
