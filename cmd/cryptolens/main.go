package main

import (
	"os"

	"github.com/abdorrahmani/cryptolens/internal/cli"
)

func main() {
	// Create components
	display := cli.NewConsoleDisplay()
	input := cli.NewConsoleInput()
	factory := cli.NewCryptoProcessorFactory()

	// Create and run menu
	menu := cli.NewMenu(display, input, factory)
	if err := menu.Run(); err != nil {
		display.ShowError(err)
		os.Exit(1)
	}
}
