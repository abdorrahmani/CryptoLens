package cli

import (
	"fmt"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
)

// ConsoleDisplay implements DisplayHandler for console output
type ConsoleDisplay struct{}

// NewConsoleDisplay creates a new console display handler
func NewConsoleDisplay() *ConsoleDisplay {
	return &ConsoleDisplay{}
}

// ShowMenu displays the main menu
func (d *ConsoleDisplay) ShowMenu() {
	fmt.Printf("\n%s%sCryptoLens - Choose an encryption method:%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s1.%s Base64 Encoding\n", colorYellow, colorReset)
	fmt.Printf("%s2.%s Caesar Cipher\n", colorYellow, colorReset)
	fmt.Printf("%s3.%s AES Encryption\n", colorYellow, colorReset)
	fmt.Printf("%s4.%s SHA-256 Hashing\n", colorYellow, colorReset)
	fmt.Printf("%s5.%s Exit\n", colorYellow, colorReset)
	fmt.Printf("\n%sEnter your choice (1-5):%s ", colorGreen, colorReset)
}

// ShowResult displays the processing result and steps
func (d *ConsoleDisplay) ShowResult(result string, steps []string) {
	fmt.Printf("\n%sResult:%s %s%s%s\n", colorBold, colorReset, colorGreen, result, colorReset)
	fmt.Printf("\n%sProcessing Steps:%s\n", colorBold, colorReset)
	for i, step := range steps {
		fmt.Printf("%s%d.%s %s\n", colorYellow, i+1, colorReset, step)
	}
	fmt.Printf("%s----------------------------------------%s\n", colorBlue, colorReset)
}

// ShowError displays an error message
func (d *ConsoleDisplay) ShowError(err error) {
	fmt.Printf("\n%sError:%s %s%v%s\n", colorBold, colorReset, colorRed, err, colorReset)
	if err.Error() == "invalid base64 string: illegal base64 data at input byte 0" {
		fmt.Printf("%sNote: For AES decryption, please enter the previously encrypted text in base64 format%s\n", colorYellow, colorReset)
	}
	fmt.Printf("%s----------------------------------------%s\n", colorBlue, colorReset)
}

// ShowWelcome displays the welcome message
func (d *ConsoleDisplay) ShowWelcome() {
	fmt.Printf("%s%sWelcome to CryptoLens!%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%sThis program demonstrates various encryption methods.%s\n", colorWhite, colorReset)
	fmt.Printf("%s----------------------------------------%s\n", colorBlue, colorReset)
}

// ShowGoodbye displays the goodbye message
func (d *ConsoleDisplay) ShowGoodbye() {
	fmt.Printf("\n%sThank you for using CryptoLens!%s\n", colorCyan, colorReset)
	fmt.Printf("%sGoodbye!%s\n", colorCyan, colorReset)
}

// ShowMessage displays the prompt for user input
func (d *ConsoleDisplay) ShowMessage(message string) {
	if message == "aes_decrypt" {
		fmt.Printf("\n%sEnter the encrypted text (in base64 format):%s ", colorGreen, colorReset)
	} else {
		fmt.Printf("\n%sEnter text to process:%s ", colorGreen, colorReset)
	}
}

// ShowProcessingMessage displays the message being processed
func (d *ConsoleDisplay) ShowProcessingMessage(message string) {
	fmt.Printf("\n%sProcessing message:%s %s%s%s\n", colorBold, colorReset, colorPurple, message, colorReset)
	fmt.Printf("%s----------------------------------------%s\n", colorBlue, colorReset)
}

// ShowOperationPrompt displays the operation selection prompt
func (d *ConsoleDisplay) ShowOperationPrompt() {
	fmt.Printf("\n%sChoose operation:%s\n", colorBold, colorReset)
	fmt.Printf("%s1.%s Encrypt\n", colorYellow, colorReset)
	fmt.Printf("%s2.%s Decrypt\n", colorYellow, colorReset)
	fmt.Printf("\n%sEnter your choice (1-2):%s ", colorGreen, colorReset)
}
