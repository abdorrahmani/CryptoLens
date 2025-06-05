package cli

import (
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/crypto"
)

// AlgorithmHandler defines the interface for handling specific algorithms
type AlgorithmHandler interface {
	Handle(processor crypto.Processor, text string, operation string) (string, []string, error)
}

// HMACHandler handles HMAC algorithm processing
type HMACHandler struct {
	display DisplayHandler
	input   UserInputHandler
}

// NewHMACHandler creates a new HMAC handler
func NewHMACHandler(display DisplayHandler, input UserInputHandler) *HMACHandler {
	return &HMACHandler{
		display: display,
		input:   input,
	}
}

// Handle processes HMAC operations
func (h *HMACHandler) Handle(processor crypto.Processor, text string, operation string) (string, []string, error) {
	if configurable, ok := processor.(crypto.ConfigurableProcessor); ok {
		hashAlgo := GetHMACHashAlgorithm()
		if hashAlgo == "benchmark" {
			benchmarkRunner := NewBenchmarkRunner(h.display, h.input)
			return benchmarkRunner.RunHMACBenchmark()
		}
		if err := configurable.Configure(map[string]interface{}{
			"hashAlgorithm": hashAlgo,
		}); err != nil {
			return "", nil, fmt.Errorf("failed to configure HMAC processor: %w", err)
		}
	}

	result, steps, err := processor.Process(text, operation)
	if err != nil {
		return "", nil, fmt.Errorf("failed to process text: %w", err)
	}

	return result, steps, nil
}

// PBKDFHandler handles PBKDF algorithm processing
type PBKDFHandler struct {
	display DisplayHandler
	input   UserInputHandler
}

// NewPBKDFHandler creates a new PBKDF handler
func NewPBKDFHandler(display DisplayHandler, input UserInputHandler) *PBKDFHandler {
	return &PBKDFHandler{
		display: display,
		input:   input,
	}
}

// Handle processes PBKDF operations
func (h *PBKDFHandler) Handle(processor crypto.Processor, text string, operation string) (string, []string, error) {
	if configurable, ok := processor.(crypto.ConfigurableProcessor); ok {
		algo := GetPBKDFAlgorithm()
		if algo == "benchmark" {
			benchmarkRunner := NewBenchmarkRunner(h.display, h.input)
			return benchmarkRunner.RunPBKDFBenchmark()
		}
		if err := configurable.Configure(map[string]interface{}{
			"algorithm": algo,
		}); err != nil {
			return "", nil, fmt.Errorf("failed to configure PBKDF processor: %w", err)
		}
	}

	result, steps, err := processor.Process(text, operation)
	if err != nil {
		return "", nil, fmt.Errorf("failed to process text: %w", err)
	}

	return result, steps, nil
}

// DefaultHandler handles default algorithm processing
type DefaultHandler struct {
	display DisplayHandler
	input   UserInputHandler
}

// NewDefaultHandler creates a new default handler
func NewDefaultHandler(display DisplayHandler, input UserInputHandler) *DefaultHandler {
	return &DefaultHandler{
		display: display,
		input:   input,
	}
}

// Handle processes default operations
func (h *DefaultHandler) Handle(processor crypto.Processor, text string, operation string) (string, []string, error) {
	result, steps, err := processor.Process(text, operation)
	if err != nil {
		return "", nil, fmt.Errorf("failed to process text: %w", err)
	}

	return result, steps, nil
}