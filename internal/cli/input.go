package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/abdorrahmani/cryptolens/internal/crypto"
	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// ConsoleInput implements UserInputHandler for console input
type ConsoleInput struct {
	scanner *bufio.Scanner
	theme   utils.Theme
}

// NewConsoleInput creates a new console input handler
func NewConsoleInput() *ConsoleInput {
	return &ConsoleInput{
		scanner: bufio.NewScanner(os.Stdin),
		theme:   utils.DefaultTheme,
	}
}

func (i *ConsoleInput) GetChoice() (int, error) {
	i.scanner.Scan()
	choice, err := strconv.Atoi(strings.TrimSpace(i.scanner.Text()))
	if err != nil {
		return 0, fmt.Errorf("invalid input: please enter a number between 1 and 7")
	}
	if choice < 1 || choice > 7 {
		return 0, fmt.Errorf("invalid choice: please enter a number between 1 and 7")
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
	fmt.Printf("\n%s\n", i.theme.Format("Choose operation:", "bold"))
	fmt.Printf("%s\n", i.theme.Format("1. Encrypt", "yellow"))
	fmt.Printf("%s\n", i.theme.Format("2. Decrypt", "yellow"))
	fmt.Printf("\n%s", i.theme.Format("Enter your choice (1-2): ", "green"))

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

// GetIntInput prompts for an integer input within a specified range
func GetIntInput(prompt string, min, max int) int {
	for {
		fmt.Print(prompt)
		var input int
		_, err := fmt.Scanln(&input)
		if err != nil || input < min || input > max {
			fmt.Printf("Please enter a number between %d and %d\n", min, max)
			continue
		}
		return input
	}
}
