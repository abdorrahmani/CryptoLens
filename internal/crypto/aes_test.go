package crypto

import (
	"encoding/base64"
	"testing"
)

func TestNewAESProcessor(t *testing.T) {
	processor := NewAESProcessor()
	if processor == nil {
		t.Fatal("NewAESProcessor returned nil")
	}
	if processor.keySize != 256 {
		t.Errorf("Expected default key size 256, got %d", processor.keySize)
	}
}

func TestAESProcessor_Configure(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		keySize int
		keyFile string
	}{
		{
			name: "valid config",
			config: map[string]interface{}{
				"keySize": 128,
				"keyFile": "test_key.bin",
			},
			wantErr: false,
			keySize: 128,
			keyFile: "test_key.bin",
		},
		{
			name: "invalid key size",
			config: map[string]interface{}{
				"keySize": 512,
				"keyFile": "test_key.bin",
			},
			wantErr: true,
		},
		{
			name:    "default values",
			config:  map[string]interface{}{},
			wantErr: false,
			keySize: 256,
			keyFile: "aes_key.bin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewAESProcessor()
			err := processor.Configure(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("AESProcessor.Configure() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if processor.keySize != tt.keySize {
					t.Errorf("keySize = %v, want %v", processor.keySize, tt.keySize)
				}
			}
		})
	}
}

func TestAESProcessor_Process(t *testing.T) {
	processor := NewAESProcessor()
	err := processor.Configure(map[string]interface{}{
		"keySize": 256,
		"keyFile": "test_aes_key.bin",
	})
	if err != nil {
		t.Fatalf("Failed to configure processor: %v", err)
	}

	// Test encryption
	plaintext := "Hello, World!"
	result, steps, err := processor.Process(plaintext, OperationEncrypt)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if result == "" {
		t.Error("Encryption returned empty result")
	}
	if len(steps) == 0 {
		t.Error("Encryption returned no steps")
	}

	// Verify the result is valid base64
	_, err = base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Errorf("Encryption result is not valid base64: %v", err)
	}

	// Test decryption
	decrypted, steps, err := processor.Process(result, OperationDecrypt)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("Decryption result = %v, want %v", decrypted, plaintext)
	}
	if len(steps) == 0 {
		t.Error("Decryption returned no steps")
	}
}

func TestAESProcessor_Padding(t *testing.T) {
	processor := NewAESProcessor()

	// Test padding
	data := []byte("test")
	padded := processor.pad(data)
	if len(padded) != 16 {
		t.Errorf("Padded length = %v, want 16", len(padded))
	}

	// Test unpadding
	unpadded, err := processor.unpad(padded)
	if err != nil {
		t.Errorf("Unpadding failed: %v", err)
	}
	if string(unpadded) != "test" {
		t.Errorf("Unpadded result = %v, want test", string(unpadded))
	}

	// Test invalid padding
	invalidPadded := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17}
	_, err = processor.unpad(invalidPadded)
	if err == nil {
		t.Error("Expected error for invalid padding, got nil")
	}
}

func TestAESProcessor_Process_EmptyInput(t *testing.T) {
	processor := NewAESProcessor()
	err := processor.Configure(map[string]interface{}{
		"keySize": 256,
		"keyFile": "test_aes_key.bin",
	})
	if err != nil {
		t.Fatalf("Failed to configure processor: %v", err)
	}

	// Test empty input
	_, _, err = processor.Process("", OperationEncrypt)
	if err == nil {
		t.Error("Expected error for empty input, got nil")
	}
}

func TestAESProcessor_Process_InvalidOperation(t *testing.T) {
	processor := NewAESProcessor()
	err := processor.Configure(map[string]interface{}{
		"keySize": 256,
		"keyFile": "test_aes_key.bin",
	})
	if err != nil {
		t.Fatalf("Failed to configure processor: %v", err)
	}

	// Test invalid operation
	_, _, err = processor.Process("test", "invalid")
	if err == nil {
		t.Error("Expected error for invalid operation, got nil")
	}
}

func TestAESProcessor_Process_InvalidBase64(t *testing.T) {
	processor := NewAESProcessor()
	err := processor.Configure(map[string]interface{}{
		"keySize": 256,
		"keyFile": "test_aes_key.bin",
	})
	if err != nil {
		t.Fatalf("Failed to configure processor: %v", err)
	}

	// Test invalid base64 input for decryption
	_, _, err = processor.Process("invalid-base64", OperationDecrypt)
	if err == nil {
		t.Error("Expected error for invalid base64 input, got nil")
	}
}
