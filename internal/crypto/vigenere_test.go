package crypto

import (
	"testing"
)

func TestNewVigenereProcessor(t *testing.T) {
	processor := NewVigenereProcessor()
	if processor == nil {
		t.Error("NewVigenereProcessor returned nil")
	}
	if processor.key != "KEY" {
		t.Errorf("Expected default key 'KEY', got %s", processor.key)
	}
}

func TestVigenereProcessor_Configure(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		key     string
	}{
		{
			name: "valid key",
			config: map[string]interface{}{
				"key": "SECRET",
			},
			wantErr: false,
			key:     "SECRET",
		},
		{
			name: "empty key",
			config: map[string]interface{}{
				"key": "",
			},
			wantErr: true,
			key:     "KEY",
		},
		{
			name: "non-alphabetic key",
			config: map[string]interface{}{
				"key": "123!@#",
			},
			wantErr: true,
			key:     "KEY",
		},
		{
			name:    "default key",
			config:  map[string]interface{}{},
			wantErr: false,
			key:     "KEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewVigenereProcessor()
			err := processor.Configure(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("VigenereProcessor.Configure() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if processor.key != tt.key {
				t.Errorf("key = %v, want %v", processor.key, tt.key)
			}
		})
	}
}

func TestVigenereProcessor_Process_Encrypt(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		key     string
		want    string
		wantErr bool
	}{
		{
			name:    "simple text",
			input:   "HELLO",
			key:     "KEY",
			want:    "RIJVS",
			wantErr: false,
		},
		{
			name:    "with spaces",
			input:   "HELLO WORLD",
			key:     "KEY",
			want:    "RIJVS UYVJN",
			wantErr: false,
		},
		{
			name:    "with punctuation",
			input:   "HELLO, WORLD!",
			key:     "KEY",
			want:    "RIJVS, UYVJN!",
			wantErr: false,
		},
		{
			name:    "longer key",
			input:   "HELLO",
			key:     "SECRETKEY",
			want:    "ZINCS",
			wantErr: false,
		},
		{
			name:    "shorter key",
			input:   "HELLO",
			key:     "A",
			want:    "HELLO",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewVigenereProcessor()
			err := processor.Configure(map[string]interface{}{
				"key": tt.key,
			})
			if err != nil {
				t.Fatalf("Failed to configure processor: %v", err)
			}

			got, steps, err := processor.Process(tt.input, OperationEncrypt)
			if (err != nil) != tt.wantErr {
				t.Errorf("VigenereProcessor.Process() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("VigenereProcessor.Process() = %v, want %v", got, tt.want)
			}
			if len(steps) == 0 {
				t.Error("VigenereProcessor.Process() returned no steps")
			}
		})
	}
}

func TestVigenereProcessor_Process_Decrypt(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		key     string
		want    string
		wantErr bool
	}{
		{
			name:    "simple text",
			input:   "RIJVS",
			key:     "KEY",
			want:    "HELLO",
			wantErr: false,
		},
		{
			name:    "with spaces",
			input:   "RIJVS UYVJN",
			key:     "KEY",
			want:    "HELLO WORLD",
			wantErr: false,
		},
		{
			name:    "with punctuation",
			input:   "RIJVS, UYVJN!",
			key:     "KEY",
			want:    "HELLO, WORLD!",
			wantErr: false,
		},
		{
			name:    "longer key",
			input:   "ZINCS",
			key:     "SECRETKEY",
			want:    "HELLO",
			wantErr: false,
		},
		{
			name:    "shorter key",
			input:   "HELLO",
			key:     "A",
			want:    "HELLO",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewVigenereProcessor()
			err := processor.Configure(map[string]interface{}{
				"key": tt.key,
			})
			if err != nil {
				t.Fatalf("Failed to configure processor: %v", err)
			}

			got, steps, err := processor.Process(tt.input, OperationDecrypt)
			if (err != nil) != tt.wantErr {
				t.Errorf("VigenereProcessor.Process() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("VigenereProcessor.Process() = %v, want %v", got, tt.want)
			}
			if len(steps) == 0 {
				t.Error("VigenereProcessor.Process() returned no steps")
			}
		})
	}
}

func TestVigenereProcessor_Process_InvalidOperation(t *testing.T) {
	processor := NewVigenereProcessor()
	_, _, err := processor.Process("test", "invalid")
	if err == nil {
		t.Error("Expected error for invalid operation, got nil")
	}
}

func TestVigenereProcessor_Process_NonAlphabetic(t *testing.T) {
	processor := NewVigenereProcessor()
	input := "1234567890!@#$%^&*()_+-=[]{}|;:,.<>?/~`"

	// Encrypt
	encrypted, _, err := processor.Process(input, OperationEncrypt)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt
	decrypted, _, err := processor.Process(encrypted, OperationDecrypt)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Compare
	if decrypted != input {
		t.Errorf("Non-alphabetic characters were modified: got %v, want %v", decrypted, input)
	}
}

func TestVigenereProcessor_Process_CaseSensitivity(t *testing.T) {
	processor := NewVigenereProcessor()
	original := "Hello World"
	key := "SecretKey"

	// Configure processor
	err := processor.Configure(map[string]interface{}{
		"key": key,
	})
	if err != nil {
		t.Fatalf("Failed to configure processor: %v", err)
	}

	// Encrypt
	encrypted, _, err := processor.Process(original, OperationEncrypt)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt
	decrypted, _, err := processor.Process(encrypted, OperationDecrypt)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Compare
	if decrypted != original {
		t.Errorf("Case sensitivity test failed: got %v, want %v", decrypted, original)
	}
}
