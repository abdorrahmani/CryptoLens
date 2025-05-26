package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/abdorrahmani/cryptolens/internal/crypto"
)

// ConsoleInput implements UserInputHandler for console input
type ConsoleInput struct {
	scanner *bufio.Scanner
}

// NewConsoleInput creates a new console input handler
func NewConsoleInput() *ConsoleInput {
	return &ConsoleInput{
		scanner: bufio.NewScanner(os.Stdin),
	}
}

func (i *ConsoleInput) GetChoice() (int, error) {
	i.scanner.Scan()
	choice, err := strconv.Atoi(strings.TrimSpace(i.scanner.Text()))
	if err != nil {
		return 0, fmt.Errorf("invalid input: please enter a number between 1 and 5")
	}
	if choice < 1 || choice > 5 {
		return 0, fmt.Errorf("invalid choice: please enter a number between 1 and 5")
	}
	return choice, nil
}

func (i *ConsoleInput) GetText() (string, error) {
	i.scanner.Scan()
	text := i.scanner.Text()
	if text == "" {
		return "", fmt.Errorf("text cannot be empty")
	}
	return text, nil
}

func (i *ConsoleInput) GetOperation() (string, error) {
	fmt.Printf("\n%sChoose operation:%s\n", colorBold, colorReset)
	fmt.Printf("%s1.%s Encrypt\n", colorYellow, colorReset)
	fmt.Printf("%s2.%s Decrypt\n", colorYellow, colorReset)
	fmt.Printf("\n%sEnter your choice (1-2):%s ", colorGreen, colorReset)

	i.scanner.Scan()
	choice, err := strconv.Atoi(strings.TrimSpace(i.scanner.Text()))
	if err != nil {
		return "", fmt.Errorf("invalid input: please enter a number between 1 and 2")
	}
	if choice < 1 || choice > 2 {
		return "", fmt.Errorf("invalid choice: please enter a number between 1 and 2")
	}

	if choice == 1 {
		return crypto.OperationEncrypt, nil
	}
	return crypto.OperationDecrypt, nil
}
