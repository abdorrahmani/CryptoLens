package cli

import (
	"fmt"
	"strings"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

const (
	version = "1.3.0"
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
	fmt.Printf("\n%s\n", d.theme.Format("CryptoLens - Cryptographic Operations", "bold brightCyan"))
	fmt.Printf("%s\n", d.theme.Format("=================================", "dim blue"))
	fmt.Printf("%s\n", d.theme.Format("Select an operation:", "bold"))
	fmt.Printf("%s\n", d.theme.Format("1. Base64 Encoding/Decoding", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("2. Caesar Cipher", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("3. AES Encryption/Decryption", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("4. SHA-256 Hashing", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("5. RSA Encryption/Decryption", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("6. HMAC (Hash-based Message Authentication)", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("7. PBKDF (Password-Based Key Derivation)", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("8. Diffie-Hellman Key Exchange", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("9. X25519 Key Exchange", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("10. JWT (JSON Web Token)", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("11. ChaCha20-Poly1305 Encryption", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("12. Attack Simulations", "red"))
	fmt.Printf("%s\n", d.theme.Format("13. Exit", "red"))
	fmt.Printf("\n%s", d.theme.Format("Enter your choice (1-13): ", "green"))
}

// ShowAttackMenu displays the attack simulation menu
func (d *ConsoleDisplay) ShowAttackMenu() {
	fmt.Printf("\n%s\n", d.theme.Format("Attack Simulations", "brightRed"))
	fmt.Printf("%s\n", d.theme.Format("==================", "red"))
	fmt.Printf("%s\n", d.theme.Format("Select an attack to simulate:", "bold"))
	fmt.Printf("%s\n", d.theme.Format("1. ECB Mode Vulnerability", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("2. Nonce Reuse in AEAD (ChaCha20-Poly1305)", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("3. Timing Attack (HMAC verification)", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("4. Brute Force on Weak Keys or Passwords", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("5. JWT None Algorithm Attack", "yellow"))
	fmt.Printf("%s\n", d.theme.Format("6. Back to Main Menu", "red"))
	fmt.Printf("\n%s", d.theme.Format("Enter your choice (1-6): ", "green"))
}

// ShowResult displays the processing result and steps
func (d *ConsoleDisplay) ShowResult(result string, steps []string) {
	fmt.Printf("\n%s\n", d.theme.Format("Result:", "brightGreen"))
	fmt.Printf("%s\n", d.theme.Format(result, "brightGreen"))

	fmt.Printf("\n%s\n", d.theme.Format("Processing Steps:", "brightCyan"))

	// Process steps in sequence
	for _, step := range steps {
		// Handle section headers
		if strings.HasPrefix(step, "📌") || strings.HasPrefix(step, "🔢") ||
			strings.HasPrefix(step, "📈") || strings.HasPrefix(step, "🔒") ||
			strings.HasPrefix(step, "📚") {
			fmt.Printf("\n%s\n", d.theme.Format(step, "bold"))
			fmt.Printf("%s\n", d.theme.Format(strings.Repeat("=", len(step)), "dim"))
			continue
		}

		// Handle separators
		if strings.HasPrefix(step, "----------------------------------------") {
			fmt.Printf("%s\n", d.theme.Format(step, "dim blue"))
			continue
		}

		// Handle arrows
		if strings.Contains(step, "↓") {
			fmt.Printf("%s\n", d.theme.Format(step, "brightYellow bold"))
			continue
		}

		// Handle success indicators
		if strings.Contains(step, "✅") {
			fmt.Printf("%s\n", d.theme.Format(step, "brightGreen"))
			continue
		}

		// Handle warning indicators
		if strings.Contains(step, "⚠️") {
			fmt.Printf("%s\n", d.theme.Format(step, "brightRed"))
			continue
		}

		// Handle step numbers
		if strings.HasPrefix(step, "Step") {
			fmt.Printf("\n%s\n", d.theme.Format(step, "bold brightCyan"))
			continue
		}

		// Handle bullet points
		if strings.HasPrefix(step, "•") {
			fmt.Printf("%s\n", d.theme.Format(step, "brightYellow"))
			continue
		}

		// Handle ASCII diagrams
		if strings.Contains(step, "┌") || strings.Contains(step, "│") ||
			strings.Contains(step, "└") || strings.Contains(step, "─") {
			fmt.Printf("%s\n", d.theme.Format(step, "brightBlue"))
			continue
		}

		// Handle labels with colons
		if strings.Contains(step, ":") {
			parts := strings.SplitN(step, ":", 2)
			if len(parts) == 2 {
				fmt.Printf("%s %s\n", d.theme.Format(parts[0]+":", "bold"), d.theme.Format(parts[1], "white"))
			} else {
				fmt.Printf("%s\n", d.theme.Format(step, "white"))
			}
			continue
		}

		// Default case
		fmt.Printf("%s\n", d.theme.Format(step, "white"))
	}
}

// ShowError displays an error message
func (d *ConsoleDisplay) ShowError(err error) {
	fmt.Printf("\n%s %s\n", d.theme.Format("Error:", "brightRed"), d.theme.Format(err.Error(), "red"))
	if err.Error() == "invalid base64 string: illegal base64 data at input byte 0" {
		fmt.Printf("%s\n", d.theme.Format("Note: For AES decryption, please enter the previously encrypted text in base64 format", "yellow"))
	}
	fmt.Printf("%s\n", d.theme.Format("----------------------------------------", "blue"))
}

// ShowWelcome displays the welcome message
func (d *ConsoleDisplay) ShowWelcome() {
	asciiArt := `
  ____                  _        _                   
 / ___|_ __ _   _ _ __ | |_ ___ | |    ___ _ __  ___ 
| |   | '__| | | | '_ \| __/ _ \| |   / _ | '_ \/ __|
| |___| |  | |_| | |_) | || (_) | |__|  __| | | \__ \
 \____|_|   \__, | .__/ \__\___/|_____\___|_| |_|___/
            |___/|_|                                                                
`
	width := utils.GetTerminalWidth()

	lines := strings.Split(strings.TrimSpace(asciiArt), "\n")

	maxLen := 0
	for _, line := range lines {
		if len(line) > maxLen {
			maxLen = len(line)
		}
	}

	// Calculate padding for centering
	padding := (width - maxLen) / 2
	if padding < 0 {
		padding = 0
	}

	// Center each line
	centeredArt := ""
	for _, line := range lines {
		centeredArt += strings.Repeat(" ", padding) + line + "\n"
	}

	fmt.Printf("%s\n", d.theme.Format(centeredArt, "blue"))
	fmt.Printf("%s %s\n", d.theme.Format("Welcome to CryptoLens!", "brightCyan"), d.theme.Format(fmt.Sprintf("v%s", version), "brightRed"))
	fmt.Printf("%s\n", d.theme.Format("This program demonstrates various encryption methods.", "white"))
	fmt.Printf("%s\n", d.theme.Format("----------------------------------------", "blue"))
}

// ShowGoodbye displays the goodbye message
func (d *ConsoleDisplay) ShowGoodbye() {
	fmt.Printf("\n%s\n", d.theme.Format("Thank you for using CryptoLens!", "brightCyan"))
	fmt.Printf("%s\n", d.theme.Format("Goodbye!", "brightCyan"))
}

// ShowMessage displays the prompt for user input
func (d *ConsoleDisplay) ShowMessage(message string) {
	if message == "aes_decrypt" {
		fmt.Printf("\n%s", d.theme.Format("Enter the encrypted text (in base64 format): ", "brightGreen"))
	} else {
		fmt.Printf("\n%s", d.theme.Format(message, "brightGreen bold"))
	}
}

// ShowProcessingMessage displays the message being processed
func (d *ConsoleDisplay) ShowProcessingMessage(message string) {
	fmt.Printf("\n%s %s\n", d.theme.Format("Processing message:", "brightPurple"), d.theme.Format(message, "purple"))
	fmt.Printf("%s\n", d.theme.Format("----------------------------------------", "blue"))
}

// ShowOperationPrompt displays the operation selection prompt
func (d *ConsoleDisplay) ShowOperationPrompt() {
	fmt.Printf("\n%s\n", d.theme.Format("Choose operation:", "brightCyan"))
	fmt.Printf("%s\n", d.theme.Format("1. Encrypt", "brightYellow"))
	fmt.Printf("%s\n", d.theme.Format("2. Decrypt", "brightYellow"))
	fmt.Printf("\n%s", d.theme.Format("Enter your choice (1-2): ", "brightGreen"))
}
