package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/abdorrahmani/cryptolens/internal/utils"
	"github.com/olekukonko/tablewriter"
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
	fmt.Printf("%s\n", d.theme.Format("7. Password-Based Key Derivation", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("8. Exit", "yellow"))
	fmt.Printf("\n%s", d.theme.Format("Enter your choice (1-8): ", "green"))
}

// ShowResult displays the processing result and steps
func (d *ConsoleDisplay) ShowResult(result string, steps []string) {
	fmt.Printf("\n%s\n", d.theme.Format("Result:", "bold brightGreen"))
	fmt.Printf("%s\n", d.theme.Format(result, "brightGreen"))

	fmt.Printf("\n%s\n", d.theme.Format("Processing Steps:", "bold brightCyan"))

	// Create sections
	sections := map[string][]string{
		"📌 Introduction":      make([]string, 0),
		"🔢 Implementation":    make([]string, 0),
		"🔍 Technical Details": make([]string, 0),
		"📈 Security":          make([]string, 0),
		"⚠️ Caveats":          make([]string, 0),
	}

	// Categorize steps into sections
	currentSection := "📌 Introduction"
	for _, step := range steps {
		// Introduction section
		if strings.HasPrefix(step, "Note:") && !strings.Contains(step, "Security") && !strings.Contains(step, "Warning") {
			currentSection = "📌 Introduction"
		}
		// Implementation section
		if strings.HasPrefix(step, "How") ||
			strings.HasPrefix(step, "1.") ||
			strings.HasPrefix(step, "2.") ||
			strings.HasPrefix(step, "3.") ||
			strings.HasPrefix(step, "4.") ||
			strings.HasPrefix(step, "5.") ||
			strings.HasPrefix(step, "6.") {
			currentSection = "🔢 Implementation"
		}
		// Technical Details section
		if strings.HasPrefix(step, "Technical") ||
			strings.HasPrefix(step, "ASCII") ||
			strings.HasPrefix(step, "Binary") ||
			strings.HasPrefix(step, "Character") ||
			strings.HasPrefix(step, "Block") ||
			strings.HasPrefix(step, "Key") ||
			strings.HasPrefix(step, "Padding") ||
			strings.HasPrefix(step, "Algorithm") {
			currentSection = "🔍 Technical Details"
		}
		// Security section
		if strings.HasPrefix(step, "Security") ||
			strings.Contains(step, "authentication") ||
			strings.Contains(step, "integrity") ||
			strings.Contains(step, "resistant") ||
			strings.Contains(step, "secure") {
			currentSection = "📈 Security"
		}
		// Caveats section
		if strings.Contains(step, "vulnerable") ||
			strings.Contains(step, "warning") ||
			strings.Contains(step, "not secure") ||
			strings.Contains(step, "broken") ||
			strings.Contains(step, "⚠️") {
			currentSection = "⚠️ Caveats"
		}
		// Keep current section for other steps
		sections[currentSection] = append(sections[currentSection], step)
	}

	// Display each section with a header and separator
	for section, sectionSteps := range sections {
		if len(sectionSteps) > 0 {
			fmt.Printf("\n%s\n", d.theme.Format(section, "bold"))
			fmt.Printf("%s\n", d.theme.Format(strings.Repeat("=", len(section)), "dim"))
			for _, step := range sectionSteps {
				if strings.HasPrefix(step, "Note:") {
					fmt.Printf("%s\n", d.theme.Format(step, "dim"))
				} else if strings.Contains(step, "->") {
					fmt.Printf("%s\n", d.theme.Format(step, "brightYellow"))
				} else if strings.HasPrefix(step, "Character") {
					fmt.Printf("%s\n", d.theme.Format(step, "brightPurple"))
				} else if strings.HasPrefix(step, "ASCII") || strings.HasPrefix(step, "Binary") {
					fmt.Printf("%s\n", d.theme.Format(step, "brightBlue"))
				} else {
					fmt.Printf("%s\n", step)
				}
			}
			fmt.Printf("%s\n", d.theme.Format("----------------------------------------", "dim blue"))
		}
	}

	// Add tablewriter table for steps
	table := tablewriter.NewWriter(os.Stdout)
	table.Header([]string{"#", "Step"})
	for i, step := range steps {
		// nolint:errcheck // Table operations are safe to ignore errors
		table.Append([]string{fmt.Sprintf("%d", i+1), step})
	}
	// nolint:errcheck // Table render is safe to ignore errors
	table.Render()
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
	fmt.Printf("%s\n", d.theme.Format("Version: "+AppVersion, "dim white"))
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
		fmt.Printf("\n%s", d.theme.Format(message, "brightGreen bold"))
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
