package utils

import (
	"os"

	"golang.org/x/term"
)

// GetTerminalWidth returns the width of the terminal window
func GetTerminalWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 80
	}
	return width
}
