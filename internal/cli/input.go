package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
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
