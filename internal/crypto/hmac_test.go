package crypto

import (
	"testing"
)

func TestHMACProcessor_Configure(t *testing.T) {
	processor := NewHMACProcessor()
	config := map[string]interface{}{
		"hashAlgorithm": HashSHA256,
		"keyFile":       "test_hmac_key.bin",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure HMACProcessor: %v", err)
	}
}

func TestHMACProcessor_Process_SHA256(t *testing.T) {
	processor := NewHMACProcessor()
	config := map[string]interface{}{
		"hashAlgorithm": HashSHA256,
		"keyFile":       "test_hmac_key.bin",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure HMACProcessor: %v", err)
	}
	input := "hello world"
	result, steps, err := processor.Process(input, OperationEncrypt)
	if err != nil {
		t.Fatalf("HMACProcessor.Process() error = %v", err)
	}
	if result == "" {
		t.Error("Expected non-empty result for HMAC SHA-256")
	}
	if len(steps) == 0 {
		t.Error("Expected non-empty steps for HMAC SHA-256")
	}
}

func TestHMACProcessor_Process_InvalidOperation(t *testing.T) {
	processor := NewHMACProcessor()
	config := map[string]interface{}{
		"hashAlgorithm": HashSHA256,
		"keyFile":       "test_hmac_key.bin",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure HMACProcessor: %v", err)
	}
	_, _, err := processor.Process("test", "invalid")
	if err == nil {
		t.Error("Expected error for invalid operation, got nil")
	}
}
