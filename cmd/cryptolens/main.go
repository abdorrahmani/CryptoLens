package main

import (
	"fmt"
	"os"

	"github.com/abdorrahmani/cryptolens/internal/cli"
	"github.com/abdorrahmani/cryptolens/internal/config"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig("")
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Create components
	display := cli.NewConsoleDisplay()
	input := cli.NewConsoleInput()
	factory := cli.NewCryptoProcessorFactory()

	// Configure factory with settings
	factory.SetConfig(cfg)

	// Create and run menu
	menu := cli.NewMenu(display, input, factory)
	if err := menu.Run(); err != nil {
		display.ShowError(err)
		os.Exit(1)
	}
}
