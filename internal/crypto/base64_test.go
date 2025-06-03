package crypto

import (
	"testing"
)

func TestNewBase64Processor(t *testing.T) {
	processor := NewBase64Processor()
	if processor == nil {
		t.Error("NewBase64Processor returned nil")
	}
}

func TestBase64Processor_Configure(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
	}{
		{
			name:    "empty config",
			config:  map[string]interface{}{},
			wantErr: false,
		},
		{
			name: "valid config",
			config: map[string]interface{}{
				"paddingChar": "=",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewBase64Processor()
			err := processor.Configure(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Base64Processor.Configure() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBase64Processor_Process_Encode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "simple string",
			input:   "Hello, World!",
			want:    "SGVsbG8sIFdvcmxkIQ==",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    "",
			wantErr: false,
		},
		{
			name:    "special characters",
			input:   "!@#$%^&*()",
			want:    "IUAjJCVeJiooKQ==",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewBase64Processor()
			got, steps, err := processor.Process(tt.input, OperationEncrypt)
			if (err != nil) != tt.wantErr {
				t.Errorf("Base64Processor.Process() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Base64Processor.Process() = %v, want %v", got, tt.want)
			}
			if len(steps) == 0 {
				t.Error("Base64Processor.Process() returned no steps")
			}
		})
	}
}

func TestBase64Processor_Process_Decode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "valid base64",
			input:   "SGVsbG8sIFdvcmxkIQ==",
			want:    "Hello, World!",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    "",
			wantErr: false,
		},
		{
			name:    "invalid base64",
			input:   "invalid-base64!",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewBase64Processor()
			got, steps, err := processor.Process(tt.input, OperationDecrypt)
			if (err != nil) != tt.wantErr {
				t.Errorf("Base64Processor.Process() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Base64Processor.Process() = %v, want %v", got, tt.want)
			}
			if !tt.wantErr && len(steps) == 0 {
				t.Error("Base64Processor.Process() returned no steps")
			}
		})
	}
}

func TestBase64Processor_Process_InvalidOperation(t *testing.T) {
	processor := NewBase64Processor()
	_, _, err := processor.Process("test", "invalid")
	if err == nil {
		t.Error("Expected error for invalid operation, got nil")
	}
}

func TestBase64Processor_Process_RoundTrip(t *testing.T) {
	processor := NewBase64Processor()
	original := "Hello, World! This is a test of Base64 encoding and decoding."

	// Encode
	encoded, _, err := processor.Process(original, OperationEncrypt)
	if err != nil {
		t.Fatalf("Encoding failed: %v", err)
	}

	// Decode
	decoded, _, err := processor.Process(encoded, OperationDecrypt)
	if err != nil {
		t.Fatalf("Decoding failed: %v", err)
	}

	// Compare
	if decoded != original {
		t.Errorf("Round trip failed: got %v, want %v", decoded, original)
	}
}

func TestBase64Processor_Process_LargeInput(t *testing.T) {
	processor := NewBase64Processor()

	// Create a large input string
	largeInput := make([]byte, 1000)
	for i := range largeInput {
		largeInput[i] = byte(i % 256)
	}

	// Encode
	encoded, _, err := processor.Process(string(largeInput), OperationEncrypt)
	if err != nil {
		t.Fatalf("Encoding large input failed: %v", err)
	}

	// Decode
	decoded, _, err := processor.Process(encoded, OperationDecrypt)
	if err != nil {
		t.Fatalf("Decoding large input failed: %v", err)
	}

	// Compare
	if decoded != string(largeInput) {
		t.Error("Large input round trip failed")
	}
}
