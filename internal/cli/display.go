package cli

import (
	"fmt"
	"strings"
)

// ANSI color codes
const (
	colorReset        = "\033[0m"
	colorRed          = "\033[31m"
	colorGreen        = "\033[32m"
	colorYellow       = "\033[33m"
	colorBlue         = "\033[34m"
	colorPurple       = "\033[35m"
	colorCyan         = "\033[36m"
	colorWhite        = "\033[37m"
	colorBold         = "\033[1m"
	colorDim          = "\033[2m"
	colorItalic       = "\033[3m"
	colorUnderline    = "\033[4m"
	colorBrightRed    = "\033[91m"
	colorBrightGreen  = "\033[92m"
	colorBrightYellow = "\033[93m"
	colorBrightBlue   = "\033[94m"
	colorBrightPurple = "\033[95m"
	colorBrightCyan   = "\033[96m"
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
	fmt.Printf("%s5.%s RSA Encryption\n", colorYellow, colorReset)
	fmt.Printf("%s6.%s Exit\n", colorYellow, colorReset)
	fmt.Printf("\n%sEnter your choice (1-6):%s ", colorGreen, colorReset)
}

// ShowResult displays the processing result and steps
func (d *ConsoleDisplay) ShowResult(result string, steps []string) {
	fmt.Printf("\n%s%sResult:%s\n", colorBold, colorBrightGreen, colorReset)
	fmt.Printf("%s%s%s\n", colorBrightGreen, result, colorReset)

	fmt.Printf("\n%s%sProcessing Steps:%s\n", colorBold, colorBrightCyan, colorReset)
	for i, step := range steps {
		if strings.HasPrefix(step, "Note:") {
			fmt.Printf("%s%s%s\n", colorDim, step, colorReset)
		} else if strings.HasPrefix(step, "How") || strings.HasPrefix(step, "Security") {
			fmt.Printf("\n%s%s%s\n", colorBold, step, colorReset)
		} else if strings.Contains(step, "->") {
			fmt.Printf("%s%s%s\n", colorBrightYellow, step, colorReset)
		} else if strings.HasPrefix(step, "Character") {
			fmt.Printf("%s%s%s\n", colorBrightPurple, step, colorReset)
		} else if strings.HasPrefix(step, "ASCII") || strings.HasPrefix(step, "Binary") {
			fmt.Printf("%s%s%s\n", colorBrightBlue, step, colorReset)
		} else {
			fmt.Printf("%s%d.%s %s\n", colorYellow, i+1, colorReset, step)
		}
	}
	fmt.Printf("%s%s----------------------------------------%s\n", colorDim, colorBlue, colorReset)
}

// ShowError displays an error message
func (d *ConsoleDisplay) ShowError(err error) {
	fmt.Printf("\n%s%sError:%s %s%v%s\n", colorBold, colorBrightRed, colorReset, colorRed, err, colorReset)
	if err.Error() == "invalid base64 string: illegal base64 data at input byte 0" {
		fmt.Printf("%s%sNote: For AES decryption, please enter the previously encrypted text in base64 format%s\n", colorDim, colorYellow, colorReset)
	}
	fmt.Printf("%s%s----------------------------------------%s\n", colorDim, colorBlue, colorReset)
}

// ShowWelcome displays the welcome message
func (d *ConsoleDisplay) ShowWelcome() {
	fmt.Printf("%s%sWelcome to CryptoLens!%s\n", colorBold, colorBrightCyan, colorReset)
	fmt.Printf("%s%sThis program demonstrates various encryption methods.%s\n", colorDim, colorWhite, colorReset)
	fmt.Printf("%s%s----------------------------------------%s\n", colorDim, colorBlue, colorReset)
}

// ShowGoodbye displays the goodbye message
func (d *ConsoleDisplay) ShowGoodbye() {
	fmt.Printf("\n%s%sThank you for using CryptoLens!%s\n", colorBrightCyan, colorBold, colorReset)
	fmt.Printf("%s%sGoodbye!%s\n", colorBrightCyan, colorBold, colorReset)
}

// ShowMessage displays the prompt for user input
func (d *ConsoleDisplay) ShowMessage(message string) {
	if message == "aes_decrypt" {
		fmt.Printf("\n%s%sEnter the encrypted text (in base64 format):%s ", colorBrightGreen, colorBold, colorReset)
	} else {
		fmt.Printf("\n%s%sEnter text to process:%s ", colorBrightGreen, colorBold, colorReset)
	}
}

// ShowProcessingMessage displays the message being processed
func (d *ConsoleDisplay) ShowProcessingMessage(message string) {
	fmt.Printf("\n%s%sProcessing message:%s %s%s%s\n", colorBold, colorBrightPurple, colorReset, colorPurple, message, colorReset)
	fmt.Printf("%s%s----------------------------------------%s\n", colorDim, colorBlue, colorReset)
}

// ShowOperationPrompt displays the operation selection prompt
func (d *ConsoleDisplay) ShowOperationPrompt() {
	fmt.Printf("\n%s%sChoose operation:%s\n", colorBold, colorBrightCyan, colorReset)
	fmt.Printf("%s%s1.%s Encrypt\n", colorBrightYellow, colorBold, colorReset)
	fmt.Printf("%s%s2.%s Decrypt\n", colorBrightYellow, colorBold, colorReset)
	fmt.Printf("\n%s%sEnter your choice (1-2):%s ", colorBrightGreen, colorBold, colorReset)
}
