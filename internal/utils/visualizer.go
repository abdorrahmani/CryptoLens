package utils

import (
	"fmt"
	"strings"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
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
		binary[i] = fmt.Sprintf("%s%08b%s", colorYellow, b, colorReset)
	}
	v.steps = append(v.steps, fmt.Sprintf("%s%s:%s %s", colorBold, label, colorReset, strings.Join(binary, " ")))
}

// AddHexStep adds a step showing hexadecimal representation
func (v *Visualizer) AddHexStep(label string, data []byte) {
	hex := make([]string, len(data))
	for i, b := range data {
		hex[i] = fmt.Sprintf("%s%02x%s", colorGreen, b, colorReset)
	}
	v.steps = append(v.steps, fmt.Sprintf("%s%s:%s %s", colorBold, label, colorReset, strings.Join(hex, " ")))
}

// AddTextStep adds a step showing text representation
func (v *Visualizer) AddTextStep(label string, text string) {
	v.steps = append(v.steps, fmt.Sprintf("%s%s:%s %s%s%s", colorBold, label, colorReset, colorPurple, text, colorReset))
}

// AddArrow adds a visual arrow to show transformation
func (v *Visualizer) AddArrow() {
	v.steps = append(v.steps, fmt.Sprintf("%s    ↓%s", colorCyan, colorReset))
}

// AddSeparator adds a visual separator
func (v *Visualizer) AddSeparator() {
	v.steps = append(v.steps, fmt.Sprintf("%s----------------------------------------%s", colorBlue, colorReset))
}

// AddNote adds an explanatory note
func (v *Visualizer) AddNote(note string) {
	v.steps = append(v.steps, fmt.Sprintf("%sNote:%s %s", colorYellow, colorReset, note))
}

// GetSteps returns all visualization steps
func (v *Visualizer) GetSteps() []string {
	return v.steps
}

// Display prints the visualization to the console
func (v *Visualizer) Display() {
	fmt.Printf("\n%sEncryption Process Visualization:%s\n", colorBold, colorReset)
	fmt.Printf("%s=================================%s\n", colorBlue, colorReset)
	for _, step := range v.steps {
		fmt.Println(step)
	}
	fmt.Printf("%s=================================%s\n", colorBlue, colorReset)
}
