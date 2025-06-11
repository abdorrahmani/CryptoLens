package attacks

import (
	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// AttackProcessor defines the interface for all attack simulations
type AttackProcessor interface {
	Configure(config map[string]interface{}) error
	Process(text string, operation string) (string, []string, error)
}

// BaseProcessor provides common functionality for all attack processors
type BaseProcessor struct {
	visualizer *utils.Visualizer
}

// NewBaseProcessor creates a new base processor
func NewBaseProcessor() *BaseProcessor {
	return &BaseProcessor{
		visualizer: utils.NewVisualizer(),
	}
}

// AddStep adds a step to the visualization
func (p *BaseProcessor) AddStep(step string) {
	p.visualizer.AddStep(step)
}

// AddNote adds a note to the visualization
func (p *BaseProcessor) AddNote(note string) {
	p.visualizer.AddNote(note)
}

// AddSeparator adds a separator to the visualization
func (p *BaseProcessor) AddSeparator() {
	p.visualizer.AddSeparator()
}

// AddTextStep adds a text step to the visualization
func (p *BaseProcessor) AddTextStep(title, text string) {
	p.visualizer.AddTextStep(title, text)
}

// AddHexStep adds a hex step to the visualization
func (p *BaseProcessor) AddHexStep(title string, data []byte) {
	p.visualizer.AddHexStep(title, data)
}

// AddArrow adds an arrow to the visualization
func (p *BaseProcessor) AddArrow() {
	p.visualizer.AddArrow()
}

// GetSteps returns the visualization steps
func (p *BaseProcessor) GetSteps() []string {
	return p.visualizer.GetSteps()
}

// AttackConfig holds common configuration for attacks
type AttackConfig struct {
	KeySize    int
	Iterations int
	Salt       []byte
	Key        []byte
}

// NewAttackConfig creates a new attack configuration with default values
func NewAttackConfig() *AttackConfig {
	return &AttackConfig{
		KeySize:    256,
		Iterations: 100,
	}
}
