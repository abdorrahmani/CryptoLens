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
	scanner  *bufio.Scanner
	theme    utils.Theme
	isDHMode bool
}

// NewConsoleInput creates a new console input handler
func NewConsoleInput() *ConsoleInput {
	return &ConsoleInput{
		scanner:  bufio.NewScanner(os.Stdin),
		theme:    utils.DefaultTheme,
		isDHMode: false,
	}
}

func (i *ConsoleInput) GetChoice() (int, error) {
	i.scanner.Scan()
	choice, err := strconv.Atoi(strings.TrimSpace(i.scanner.Text()))
	if err != nil {
		return 0, fmt.Errorf("invalid input: please enter a number between 1 and 13")
	}
	if choice < 1 || choice > 13 {
		return 0, fmt.Errorf("invalid choice: please enter a number between 1 and 13")
	}
	return choice, nil
}

func (i *ConsoleInput) GetText() (string, error) {
	i.scanner.Scan()
	text := i.scanner.Text()
	// Allow empty text for DH demonstration
	if text == "" && i.isDHMode {
		return "", nil
	}
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

// GetTextInput gets text input with a default value
func GetTextInput(defaultValue string) string {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultValue
	}
	return input
}

// GetIntInput gets an integer input within a range
func GetIntInput(prompt string, minValue, maxValue int) int {
	for {
		fmt.Print(prompt)
		input := GetTextInput("")
		if input == "" {
			return 0
		}

		value, err := strconv.Atoi(input)
		if err != nil || value < minValue || value > maxValue {
			fmt.Printf("Please enter a number between %d and %d\n", minValue, maxValue)
			continue
		}
		return value
	}
}

// SetDHMode sets the DH mode flag
func (i *ConsoleInput) SetDHMode(isDH bool) {
	i.isDHMode = isDH
}

// GetAttackChoice gets the user's choice from the attack menu
func (i *ConsoleInput) GetAttackChoice() (int, error) {
	i.scanner.Scan()
	choice, err := strconv.Atoi(strings.TrimSpace(i.scanner.Text()))
	if err != nil {
		return 0, fmt.Errorf("invalid input: please enter a number between 1 and 6")
	}
	if choice < 1 || choice > 6 {
		return 0, fmt.Errorf("invalid choice: please enter a number between 1 and 6")
	}
	return choice, nil
}
