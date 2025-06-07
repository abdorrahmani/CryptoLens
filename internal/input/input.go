package input

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

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
