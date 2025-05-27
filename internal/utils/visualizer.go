package utils

import (
	"fmt"
	"strings"
)

// ANSI color codes
const (
	colorReset        = "\033[0m"
	colorRed          = "\033[31m"
	colorGreen        = "\033[32m"
	colorYellow       = "\033[33m"
	colorBlue         = "\033[34m"
	colorPurple       = "\033[35m"
	colorCyan         = "\033[36m"
	colorWhite        = "\033[37m"
	colorBold         = "\033[1m"
	colorDim          = "\033[2m"
	colorItalic       = "\033[3m"
	colorUnderline    = "\033[4m"
	colorBrightRed    = "\033[91m"
	colorBrightGreen  = "\033[92m"
	colorBrightYellow = "\033[93m"
	colorBrightBlue   = "\033[94m"
	colorBrightPurple = "\033[95m"
	colorBrightCyan   = "\033[96m"
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
	if strings.HasPrefix(step, "Note:") {
		v.steps = append(v.steps, fmt.Sprintf("%s%s%s", colorDim, step, colorReset))
	} else if strings.HasPrefix(step, "How") || strings.HasPrefix(step, "Security") {
		v.steps = append(v.steps, fmt.Sprintf("\n%s%s%s", colorBold, step, colorReset))
	} else if strings.Contains(step, "->") {
		v.steps = append(v.steps, fmt.Sprintf("%s%s%s", colorBrightYellow, step, colorReset))
	} else if strings.HasPrefix(step, "Character") {
		v.steps = append(v.steps, fmt.Sprintf("%s%s%s", colorBrightPurple, step, colorReset))
	} else if strings.HasPrefix(step, "ASCII") || strings.HasPrefix(step, "Binary") {
		v.steps = append(v.steps, fmt.Sprintf("%s%s%s", colorBrightBlue, step, colorReset))
	} else {
		v.steps = append(v.steps, step)
	}
}

// AddBinaryStep adds a step showing binary representation
func (v *Visualizer) AddBinaryStep(label string, data []byte) {
	binary := make([]string, len(data))
	for i, b := range data {
		binary[i] = fmt.Sprintf("%s%08b%s", colorBrightYellow, b, colorReset)
	}
	v.steps = append(v.steps, fmt.Sprintf("%s%s%s:%s %s", colorBold, colorBrightBlue, label, colorReset, strings.Join(binary, " ")))
}

// AddHexStep adds a step showing hexadecimal representation
func (v *Visualizer) AddHexStep(label string, data []byte) {
	hex := make([]string, len(data))
	for i, b := range data {
		hex[i] = fmt.Sprintf("%s%02x%s", colorBrightGreen, b, colorReset)
	}
	v.steps = append(v.steps, fmt.Sprintf("%s%s%s:%s %s", colorBold, colorBrightBlue, label, colorReset, strings.Join(hex, " ")))
}

// AddTextStep adds a step showing text representation
func (v *Visualizer) AddTextStep(label string, text string) {
	v.steps = append(v.steps, fmt.Sprintf("%s%s%s:%s %s%s%s", colorBold, colorBrightPurple, label, colorReset, colorPurple, text, colorReset))
}

// AddArrow adds a visual arrow to show transformation
func (v *Visualizer) AddArrow() {
	v.steps = append(v.steps, fmt.Sprintf("%s%s    ↓%s", colorBrightYellow, colorBold, colorReset))
}

// AddSeparator adds a visual separator
func (v *Visualizer) AddSeparator() {
	v.steps = append(v.steps, fmt.Sprintf("%s%s----------------------------------------%s", colorDim, colorBlue, colorReset))
}

// AddNote adds an explanatory note
func (v *Visualizer) AddNote(note string) {
	v.steps = append(v.steps, fmt.Sprintf("%s%sNote:%s %s", colorDim, colorYellow, colorReset, note))
}

// GetSteps returns all visualization steps
func (v *Visualizer) GetSteps() []string {
	return v.steps
}

// Display prints the visualization to the console
func (v *Visualizer) Display() {
	fmt.Printf("\n%s%sEncryption Process Visualization:%s\n", colorBold, colorBrightCyan, colorReset)
	fmt.Printf("%s%s=================================%s\n", colorDim, colorBlue, colorReset)
	for _, step := range v.steps {
		fmt.Println(step)
	}
	fmt.Printf("%s%s=================================%s\n", colorDim, colorBlue, colorReset)
}
