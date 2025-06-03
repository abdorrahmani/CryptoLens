package crypto

import (
	"testing"
)

func TestPBKDFProcessor_Configure(t *testing.T) {
	processor := NewPBKDFProcessor()
	config := map[string]interface{}{
		"iterations": 1000,
		"saltSize":   8,
		"keyFile":    "test_pbkdf_key.bin",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure PBKDFProcessor: %v", err)
	}
}

func TestPBKDFProcessor_Process_SHA256(t *testing.T) {
	processor := NewPBKDFProcessor()
	config := map[string]interface{}{
		"iterations": 1000,
		"saltSize":   8,
		"keyFile":    "test_pbkdf_key.bin",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure PBKDFProcessor: %v", err)
	}
	input := "password123"
	result, steps, err := processor.Process(input, OperationEncrypt)
	if err != nil {
		t.Fatalf("PBKDFProcessor.Process() error = %v", err)
	}
	if result == "" {
		t.Error("Expected non-empty result for PBKDF2-SHA256")
	}
	if len(steps) == 0 {
		t.Error("Expected non-empty steps for PBKDF2-SHA256")
	}
}
