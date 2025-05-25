package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/abdorrahmani/cryptolens/internal/crypto"
)

type Menu struct {
	scanner *bufio.Scanner
}

func NewMenu() *Menu {
	return &Menu{
		scanner: bufio.NewScanner(os.Stdin),
	}
}

func (m *Menu) Run() error {
	for {
		m.displayMenu()
		choice, err := m.getUserChoice()
		if err != nil {
			return err
		}

		if choice == 5 {
			fmt.Println("Thank you for using CryptoLens!")
			return nil
		}

		if err := m.handleChoice(choice); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}
}

func (m *Menu) displayMenu() {
	fmt.Println("\nAvailable Encryption Methods:")
	fmt.Println("1. Base64 Encoding")
	fmt.Println("2. Caesar Cipher")
	fmt.Println("3. AES Encryption")
	fmt.Println("4. SHA-256 Hashing")
	fmt.Println("5. Exit")
	fmt.Print("\nEnter your choice (1-5): ")
}

func (m *Menu) getUserChoice() (int, error) {
	m.scanner.Scan()
	choice, err := strconv.Atoi(strings.TrimSpace(m.scanner.Text()))
	if err != nil {
		return 0, fmt.Errorf("invalid input: please enter a number between 1 and 5")
	}
	if choice < 1 || choice > 5 {
		return 0, fmt.Errorf("invalid choice: please enter a number between 1 and 5")
	}
	return choice, nil
}

func (m *Menu) handleChoice(choice int) error {
	fmt.Print("\nEnter the text to process: ")
	m.scanner.Scan()
	text := m.scanner.Text()

	var processor crypto.Processor
	var err error

	switch choice {
	case 1:
		processor = crypto.NewBase64Processor()
	case 2:
		processor = crypto.NewCaesarCipherProcessor()
	case 3:
		processor = crypto.NewAESProcessor()
	case 4:
		processor = crypto.NewSHA256Processor()
	default:
		return fmt.Errorf("invalid choice")
	}

	result, steps, err := processor.Process(text)
	if err != nil {
		return err
	}

	fmt.Println("\nProcessing Steps:")
	for i, step := range steps {
		fmt.Printf("%d. %s\n", i+1, step)
	}

	fmt.Printf("\nResult: %s\n", result)
	return nil
}
