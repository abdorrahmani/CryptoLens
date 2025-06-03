package utils

// VisualizerInterface defines the contract for visualization operations
type VisualizerInterface interface {
	// AddStep adds a step to the visualization
	AddStep(step string)
	// AddBinaryStep adds a step showing binary representation
	AddBinaryStep(label string, data []byte)
	// AddHexStep adds a step showing hexadecimal representation
	AddHexStep(label string, data []byte)
	// AddTextStep adds a step showing text representation
	AddTextStep(label string, text string)
	// AddArrow adds a visual arrow to show transformation
	AddArrow()
	// AddSeparator adds a visual separator
	AddSeparator()
	// AddNote adds an explanatory note
	AddNote(note string)
	// GetSteps returns all visualization steps
	GetSteps() []string
	// Display prints the visualization to the console
	Display()
}
