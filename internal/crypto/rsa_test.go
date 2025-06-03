package crypto

import (
	"testing"
)

func TestRSAProcessor_Configure(t *testing.T) {
	processor := NewRSAProcessor()
	config := map[string]interface{}{
		"keySize": 2048,
		"publicKeyFile": "test_rsa_public.pem",
		"privateKeyFile": "test_rsa_private.pem",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure RSAProcessor: %v", err)
	}
}

func TestRSAProcessor_Process_EncryptDecrypt(t *testing.T) {
	processor := NewRSAProcessor()
	config := map[string]interface{}{
		"keySize": 2048,
		"publicKeyFile": "test_rsa_public.pem",
		"privateKeyFile": "test_rsa_private.pem",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure RSAProcessor: %v", err)
	}
	plaintext := "Hello, RSA!"
	ciphertext, steps, err := processor.Process(plaintext, OperationEncrypt)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if ciphertext == "" {
		t.Error("Expected non-empty ciphertext")
	}
	if len(steps) == 0 {
		t.Error("Expected non-empty steps for encryption")
	}
	decrypted, steps, err := processor.Process(ciphertext, OperationDecrypt)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("Decryption result = %v, want %v", decrypted, plaintext)
	}
	if len(steps) == 0 {
		t.Error("Expected non-empty steps for decryption")
	}
}

func TestRSAProcessor_Process_InvalidOperation(t *testing.T) {
	processor := NewRSAProcessor()
	config := map[string]interface{}{
		"keySize": 2048,
		"publicKeyFile": "test_rsa_public.pem",
		"privateKeyFile": "test_rsa_private.pem",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure RSAProcessor: %v", err)
	}
	_, _, err := processor.Process("test", "invalid")
	if err == nil {
		t.Error("Expected error for invalid operation, got nil")
	}
} 