package utils

import (
	"fmt"
	"strings"
)

// Visualizer helps display encryption steps in a graphical format
type Visualizer struct {
	steps []string
}

// NewVisualizer creates a new visualizer instance
func NewVisualizer() *Visualizer {
	return &Visualizer{
		steps: make([]string, 0),
	}
}

// AddStep adds a step to the visualization
func (v *Visualizer) AddStep(step string) {
	v.steps = append(v.steps, step)
}

// AddBinaryStep adds a step showing binary representation
func (v *Visualizer) AddBinaryStep(label string, data []byte) {
	binary := make([]string, len(data))
	for i, b := range data {
		binary[i] = fmt.Sprintf("%08b", b)
	}
	v.steps = append(v.steps, fmt.Sprintf("%s: %s", label, strings.Join(binary, " ")))
}

// AddHexStep adds a step showing hexadecimal representation
func (v *Visualizer) AddHexStep(label string, data []byte) {
	hex := make([]string, len(data))
	for i, b := range data {
		hex[i] = fmt.Sprintf("%02x", b)
	}
	v.steps = append(v.steps, fmt.Sprintf("%s: %s", label, strings.Join(hex, " ")))
}

// AddTextStep adds a step showing text representation
func (v *Visualizer) AddTextStep(label string, text string) {
	v.steps = append(v.steps, fmt.Sprintf("%s: %s", label, text))
}

// AddArrow adds a visual arrow to show transformation
func (v *Visualizer) AddArrow() {
	v.steps = append(v.steps, "    ↓")
}

// AddSeparator adds a visual separator
func (v *Visualizer) AddSeparator() {
	v.steps = append(v.steps, "----------------------------------------")
}

// AddNote adds an explanatory note
func (v *Visualizer) AddNote(note string) {
	v.steps = append(v.steps, fmt.Sprintf("Note: %s", note))
}

// GetSteps returns all visualization steps
func (v *Visualizer) GetSteps() []string {
	return v.steps
}

// Display prints the visualization to the console
func (v *Visualizer) Display() {
	fmt.Println("\nEncryption Process Visualization:")
	fmt.Println("=================================")
	for _, step := range v.steps {
		fmt.Println(step)
	}
	fmt.Println("=================================")
}
