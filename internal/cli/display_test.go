package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

func TestConsoleDisplay(t *testing.T) {
	display := NewConsoleDisplay()

	// Helper function to capture output
	captureOutput := func(f func()) string {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		// Create a channel to receive the output
		outputCh := make(chan string)
		go func() {
			var buf strings.Builder
			io.Copy(&buf, r)
			outputCh <- buf.String()
		}()

		// Run the function
		f()

		// Close the writer and restore stdout
		w.Close()
		os.Stdout = oldStdout

		// Get the output
		return <-outputCh
	}

	// Test ShowMenu
	output := captureOutput(display.ShowMenu)
	if !strings.Contains(output, "CryptoLens") {
		t.Error("ShowMenu did not produce expected output")
	}

	// Test ShowWelcome
	output = captureOutput(display.ShowWelcome)
	if !strings.Contains(output, "Welcome to CryptoLens") {
		t.Error("ShowWelcome did not produce expected output")
	}

	// Test ShowGoodbye
	output = captureOutput(display.ShowGoodbye)
	if !strings.Contains(output, "Goodbye") {
		t.Error("ShowGoodbye did not produce expected output")
	}

	// Test ShowMessage
	output = captureOutput(func() { display.ShowMessage("test message") })
	if !strings.Contains(output, "test message") {
		t.Error("ShowMessage did not produce expected output")
	}

	// Test ShowProcessingMessage
	output = captureOutput(func() { display.ShowProcessingMessage("processing") })
	if !strings.Contains(output, "processing") {
		t.Error("ShowProcessingMessage did not produce expected output")
	}

	// Test ShowOperationPrompt
	output = captureOutput(display.ShowOperationPrompt)
	if !strings.Contains(output, "Choose operation") {
		t.Error("ShowOperationPrompt did not produce expected output")
	}

	// Test ShowError
	output = captureOutput(func() { display.ShowError(fmt.Errorf("test error")) })
	if !strings.Contains(output, "test error") {
		t.Error("ShowError did not produce expected output")
	}

	// Test ShowResult
	output = captureOutput(func() { display.ShowResult("test result", []string{"step1", "step2"}) })
	if !strings.Contains(output, "test result") || !strings.Contains(output, "step1") || !strings.Contains(output, "step2") {
		t.Error("ShowResult did not produce expected output")
	}
}

func TestDisplayTheme(t *testing.T) {
	display := NewConsoleDisplay()
	if display.theme != utils.DefaultTheme {
		t.Errorf("Expected default theme, got %v", display.theme)
	}
}
