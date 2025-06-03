package cli

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/abdorrahmani/cryptolens/internal/crypto"
	"github.com/abdorrahmani/cryptolens/internal/utils"
)

func TestConsoleInput(t *testing.T) {
	// Create a buffer with test input
	input := "1\nHello, World!\n2\n"
	reader := bufio.NewReader(strings.NewReader(input))
	inputHandler := &ConsoleInput{
		scanner: bufio.NewScanner(reader),
		theme:   utils.DefaultTheme,
	}

	// Test GetChoice
	choice, err := inputHandler.GetChoice()
	if err != nil {
		t.Errorf("GetChoice failed: %v", err)
	}
	if choice != 1 {
		t.Errorf("Expected choice 1, got %d", choice)
	}

	// Test GetText
	text, err := inputHandler.GetText()
	if err != nil {
		t.Errorf("GetText failed: %v", err)
	}
	if text != "Hello, World!" {
		t.Errorf("Expected text 'Hello, World!', got '%s'", text)
	}

	// Test GetOperation
	operation, err := inputHandler.GetOperation()
	if err != nil {
		t.Errorf("GetOperation failed: %v", err)
	}
	if operation != crypto.OperationDecrypt {
		t.Errorf("Expected operation 'decrypt', got '%s'", operation)
	}
}

func TestGetIntInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		min      int
		max      int
		expected int
	}{
		{
			name:     "valid input",
			input:    "5\n",
			min:      1,
			max:      10,
			expected: 5,
		},
		{
			name:     "min boundary",
			input:    "1\n",
			min:      1,
			max:      10,
			expected: 1,
		},
		{
			name:     "max boundary",
			input:    "10\n",
			min:      1,
			max:      10,
			expected: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldStdin := os.Stdin
			r, w, _ := os.Pipe()
			os.Stdin = r
			w.WriteString(tt.input)
			w.Close()

			result := GetIntInput("Enter a number: ", tt.min, tt.max)
			if result != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, result)
			}

			os.Stdin = oldStdin
		})
	}
}

func TestGetTextInput(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		defaultValue string
		expected     string
	}{
		{
			name:         "valid input",
			input:        "test input\n",
			defaultValue: "default",
			expected:     "test input",
		},
		{
			name:         "empty input",
			input:        "\n",
			defaultValue: "default",
			expected:     "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldStdin := os.Stdin
			r, w, _ := os.Pipe()
			os.Stdin = r
			w.WriteString(tt.input)
			w.Close()

			result := GetTextInput(tt.defaultValue)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}

			os.Stdin = oldStdin
		})
	}
}
