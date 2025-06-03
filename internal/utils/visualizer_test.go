package utils

import (
	"strings"
	"testing"
)

func TestNewVisualizer(t *testing.T) {
	v := NewVisualizer()
	if v == nil {
		t.Fatal("NewVisualizer returned nil")
	}
	if v.steps == nil {
		t.Fatal("Visualizer steps slice is nil")
	}
	if len(v.steps) != 0 {
		t.Fatal("New visualizer should have empty steps")
	}
	if v.theme == nil {
		t.Fatal("Visualizer theme is nil")
	}
}

func TestAddStep(t *testing.T) {
	v := NewVisualizer()

	// Test different step types
	testCases := []struct {
		step     string
		expected string
	}{
		{"Note: This is a note", "\033[2m"},
		{"How to use", "\033[1m"},
		{"Security considerations", "\033[1m"},
		{"Input -> Output", "\033[93m"},
		{"Character: A", "\033[95m"},
		{"ASCII: 65", "\033[94m"},
		{"Binary: 01000001", "\033[94m"},
		{"Regular step", ""},
	}

	for _, tc := range testCases {
		v.AddStep(tc.step)
		lastStep := v.steps[len(v.steps)-1]
		if tc.expected != "" && !strings.Contains(lastStep, tc.expected) {
			t.Errorf("Step '%s' was not formatted with expected style '%s'", tc.step, tc.expected)
		}
	}
}

func TestAddBinaryStep(t *testing.T) {
	v := NewVisualizer()
	data := []byte{65, 66, 67} // ABC
	v.AddBinaryStep("Test", data)

	lastStep := v.steps[len(v.steps)-1]
	if !strings.Contains(lastStep, "Test:") {
		t.Error("Binary step does not contain label")
	}
	if !strings.Contains(lastStep, "01000001") {
		t.Error("Binary step does not contain binary representation")
	}
}

func TestAddHexStep(t *testing.T) {
	v := NewVisualizer()
	data := []byte{65, 66, 67} // ABC
	v.AddHexStep("Test", data)

	lastStep := v.steps[len(v.steps)-1]
	if !strings.Contains(lastStep, "Test:") {
		t.Error("Hex step does not contain label")
	}
	if !strings.Contains(lastStep, "41") {
		t.Error("Hex step does not contain hex representation")
	}
}

func TestAddTextStep(t *testing.T) {
	v := NewVisualizer()
	v.AddTextStep("Test", "Hello")

	lastStep := v.steps[len(v.steps)-1]
	if !strings.Contains(lastStep, "Test:") {
		t.Error("Text step does not contain label")
	}
	if !strings.Contains(lastStep, "Hello") {
		t.Error("Text step does not contain text")
	}
}

func TestAddArrow(t *testing.T) {
	v := NewVisualizer()
	v.AddArrow()

	lastStep := v.steps[len(v.steps)-1]
	if !strings.Contains(lastStep, "↓") {
		t.Error("Arrow step does not contain arrow symbol")
	}
}

func TestAddSeparator(t *testing.T) {
	v := NewVisualizer()
	v.AddSeparator()

	lastStep := v.steps[len(v.steps)-1]
	if !strings.Contains(lastStep, "----------------------------------------") {
		t.Error("Separator step does not contain separator line")
	}
}

func TestAddNote(t *testing.T) {
	v := NewVisualizer()
	v.AddNote("Test note")

	lastStep := v.steps[len(v.steps)-1]
	if !strings.Contains(lastStep, "Note: Test note") {
		t.Error("Note step does not contain note text")
	}
}

func TestGetSteps(t *testing.T) {
	v := NewVisualizer()
	v.AddStep("Step 1")
	v.AddStep("Step 2")

	steps := v.GetSteps()
	if len(steps) != 2 {
		t.Errorf("GetSteps returned %d steps, expected 2", len(steps))
	}
	if steps[0] != v.steps[0] || steps[1] != v.steps[1] {
		t.Error("GetSteps returned incorrect steps")
	}
}
