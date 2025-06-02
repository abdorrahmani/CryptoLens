package cli

import (
	"fmt"
	"os"

	"github.com/abdorrahmani/cryptolens/internal/crypto"
)

type CLI struct {
	factory ProcessorFactory
}

func NewCLI(factory ProcessorFactory) *CLI {
	return &CLI{
		factory: factory,
	}
}

func (c *CLI) Run() error {
	algorithm := GetAlgorithmChoice()
	processor, err := c.factory.CreateProcessor(1) // HMAC is choice 1
	if err != nil {
		return err
	}

	if algorithm == "hmac" {
		hashAlgo := GetHMACHashAlgorithm()
		if configurable, ok := processor.(crypto.ConfigurableProcessor); ok {
			if err := configurable.Configure(map[string]interface{}{
				"hashAlgorithm": hashAlgo,
			}); err != nil {
				return fmt.Errorf("failed to configure HMAC processor: %w", err)
			}
		}

		// Get text input
		fmt.Print("Enter text to process: ")
		var text string
		fmt.Scanln(&text)

		// Process the text
		result, steps, err := processor.Process(text, crypto.OperationEncrypt)
		if err != nil {
			return err
		}

		// Display results
		c.PrintResult(result)
		for _, step := range steps {
			c.PrintTextln(step)
		}
	}

	return nil
}

func GetAlgorithmChoice() string {
	fmt.Println("Select algorithm:")
	fmt.Println("1. HMAC")
	fmt.Println("2. Exit")

	var choice int
	fmt.Print("Enter your choice (1-2): ")
	fmt.Scan(&choice)

	switch choice {
	case 1:
		return "hmac"
	case 2:
		os.Exit(0)
	default:
		fmt.Println("Invalid choice. Please try again.")
		return GetAlgorithmChoice()
	}
	return ""
}

func (c *CLI) PrintResult(result string) {
	fmt.Println("Result:", result)
}

func (c *CLI) PrintError(err error) {
	fmt.Println("Error:", err)
}

func (c *CLI) PrintUsage() {
	fmt.Println("Usage: cryptolens [command]")
	fmt.Println("Commands:")
	fmt.Println("  encrypt - Encrypt data")
	fmt.Println("  decrypt - Decrypt data")
	fmt.Println("  exit    - Exit the program")
}

func (c *CLI) PrintText(text string) {
	fmt.Print(text)
}

func (c *CLI) PrintTextln(text string) {
	fmt.Println(text)
}

func (c *CLI) PrintTextf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func (c *CLI) PrintTextlnf(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}
