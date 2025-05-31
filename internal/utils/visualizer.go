package utils

import (
	"fmt"
	"strings"
)

// Visualizer helps display encryption steps in a graphical format
type Visualizer struct {
	steps []string
	theme Theme
}

// NewVisualizer creates a new visualizer instance
func NewVisualizer() *Visualizer {
	return &Visualizer{
		steps: make([]string, 0),
		theme: DefaultTheme,
	}
}

// AddStep adds a step to the visualization
func (v *Visualizer) AddStep(step string) {
	if strings.HasPrefix(step, "Note:") {
		v.steps = append(v.steps, v.theme.Format(step, "dim"))
	} else if strings.HasPrefix(step, "How") || strings.HasPrefix(step, "Security") {
		v.steps = append(v.steps, v.theme.Format(step, "bold"))
	} else if strings.Contains(step, "->") {
		v.steps = append(v.steps, v.theme.Format(step, "brightYellow"))
	} else if strings.HasPrefix(step, "Character") {
		v.steps = append(v.steps, v.theme.Format(step, "brightPurple"))
	} else if strings.HasPrefix(step, "ASCII") || strings.HasPrefix(step, "Binary") {
		v.steps = append(v.steps, v.theme.Format(step, "brightBlue"))
	} else {
		v.steps = append(v.steps, step)
	}
}

// AddBinaryStep adds a step showing binary representation
func (v *Visualizer) AddBinaryStep(label string, data []byte) {
	binary := make([]string, len(data))
	for i, b := range data {
		binary[i] = v.theme.Format(fmt.Sprintf("%08b", b), "brightYellow")
	}
	v.steps = append(v.steps, v.theme.Format(fmt.Sprintf("%s: %s", label, strings.Join(binary, " ")), "brightBlue bold"))
}

// AddHexStep adds a step showing hexadecimal representation
func (v *Visualizer) AddHexStep(label string, data []byte) {
	hex := make([]string, len(data))
	for i, b := range data {
		hex[i] = v.theme.Format(fmt.Sprintf("%02x", b), "brightGreen")
	}
	v.steps = append(v.steps, v.theme.Format(fmt.Sprintf("%s: %s", label, strings.Join(hex, " ")), "brightBlue bold"))
}

// AddTextStep adds a step showing text representation
func (v *Visualizer) AddTextStep(label string, text string) {
	v.steps = append(v.steps, v.theme.Format(fmt.Sprintf("%s: %s", label, text), "brightPurple bold"))
}

// AddArrow adds a visual arrow to show transformation
func (v *Visualizer) AddArrow() {
	v.steps = append(v.steps, v.theme.Format("    ↓", "brightYellow bold"))
}

// AddSeparator adds a visual separator
func (v *Visualizer) AddSeparator() {
	v.steps = append(v.steps, v.theme.Format("----------------------------------------", "dim blue"))
}

// AddNote adds an explanatory note
func (v *Visualizer) AddNote(note string) {
	v.steps = append(v.steps, v.theme.Format(fmt.Sprintf("Note: %s", note), "dim yellow"))
}

// GetSteps returns all visualization steps
func (v *Visualizer) GetSteps() []string {
	return v.steps
}

// Display prints the visualization to the console
func (v *Visualizer) Display() {
	fmt.Printf("\n%s\n", v.theme.Format("Encryption Process Visualization:", "bold brightCyan"))
	fmt.Printf("%s\n", v.theme.Format("=================================", "dim blue"))
	for _, step := range v.steps {
		fmt.Println(step)
	}
	fmt.Printf("%s\n", v.theme.Format("=================================", "dim blue"))
}
