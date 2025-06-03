package utils

import (
	"strings"
	"testing"
)

func TestNewColorTheme(t *testing.T) {
	theme := NewColorTheme()
	if theme == nil {
		t.Fatal("NewColorTheme returned nil")
	}
	if theme.colors == nil {
		t.Fatal("Theme colors map is nil")
	}
}

func TestGetColor(t *testing.T) {
	theme := NewColorTheme()

	// Test existing colors
	testCases := []string{
		"red", "green", "yellow", "blue", "purple", "cyan", "white",
		"bold", "dim", "italic", "underline",
		"brightRed", "brightGreen", "brightYellow", "brightBlue", "brightPurple", "brightCyan",
	}

	for _, color := range testCases {
		result := theme.GetColor(color)
		if result == "" {
			t.Errorf("GetColor returned empty string for color: %s", color)
		}
		if !strings.HasPrefix(result, "\033[") {
			t.Errorf("GetColor returned invalid ANSI code for color: %s", color)
		}
	}

	// Test non-existent color
	result := theme.GetColor("nonexistent")
	if result != theme.colors["reset"] {
		t.Error("GetColor did not return reset color for nonexistent color")
	}
}

func TestFormat(t *testing.T) {
	theme := NewColorTheme()
	text := "test"
	style := "bold"

	formatted := theme.Format(text, style)
	if !strings.Contains(formatted, text) {
		t.Error("Formatted text does not contain original text")
	}
	if !strings.HasPrefix(formatted, theme.GetColor(style)) {
		t.Error("Formatted text does not start with style color")
	}
	if !strings.HasSuffix(formatted, theme.GetColor("reset")) {
		t.Error("Formatted text does not end with reset color")
	}
}

func TestDefaultTheme(t *testing.T) {
	if DefaultTheme == nil {
		t.Fatal("DefaultTheme is nil")
	}

	// Test that DefaultTheme implements Theme interface
	text := "test"
	formatted := DefaultTheme.Format(text, "bold")
	if !strings.Contains(formatted, text) {
		t.Error("DefaultTheme.Format did not work correctly")
	}
}
