package crypto

import (
	"testing"
)

func TestSHA256Processor_Configure(t *testing.T) {
	processor := NewSHA256Processor()
	config := map[string]interface{}{}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure SHA256Processor: %v", err)
	}
}

func TestSHA256Processor_Process(t *testing.T) {
	processor := NewSHA256Processor()
	input := "hello world"
	result, steps, err := processor.Process(input, OperationEncrypt)
	if err != nil {
		t.Fatalf("SHA256Processor.Process() error = %v", err)
	}
	if result == "" {
		t.Error("Expected non-empty result for SHA-256 hash")
	}
	if len(steps) == 0 {
		t.Error("Expected non-empty steps for SHA-256 hash")
	}
}
