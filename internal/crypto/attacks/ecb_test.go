package attacks

import (
	"encoding/base64"
	"testing"
)

func TestECBProcessor_Configure(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]interface{}
		wantErr     bool
		description string
	}{
		{
			name: "valid key size 128",
			config: map[string]interface{}{
				"keySize": 128,
			},
			wantErr:     false,
			description: "should accept 128-bit key size",
		},
		{
			name: "valid key size 192",
			config: map[string]interface{}{
				"keySize": 192,
			},
			wantErr:     false,
			description: "should accept 192-bit key size",
		},
		{
			name: "valid key size 256",
			config: map[string]interface{}{
				"keySize": 256,
			},
			wantErr:     false,
			description: "should accept 256-bit key size",
		},
		{
			name: "invalid key size",
			config: map[string]interface{}{
				"keySize": 512,
			},
			wantErr:     true,
			description: "should reject invalid key size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewECBProcessor()
			err := p.Configure(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ECBProcessor.Configure() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestECBProcessor_Process(t *testing.T) {
	tests := []struct {
		name        string
		text        string
		operation   string
		wantErr     bool
		description string
	}{
		{
			name:        "empty text",
			text:        "",
			operation:   "encrypt",
			wantErr:     false,
			description: "should handle empty text",
		},
		{
			name:        "short text",
			text:        "Hello",
			operation:   "encrypt",
			wantErr:     false,
			description: "should handle short text",
		},
		{
			name:        "long text",
			text:        "This is a longer text that will span multiple blocks",
			operation:   "encrypt",
			wantErr:     false,
			description: "should handle long text",
		},
		{
			name:        "repeating text",
			text:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			operation:   "encrypt",
			wantErr:     false,
			description: "should handle repeating text to show pattern leakage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewECBProcessor()
			err := p.Configure(map[string]interface{}{
				"keySize": 256,
			})
			if err != nil {
				t.Fatalf("failed to configure processor: %v", err)
			}

			result, steps, err := p.Process(tt.text, tt.operation)
			if (err != nil) != tt.wantErr {
				t.Errorf("ECBProcessor.Process() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify result is valid base64
				_, err := base64.StdEncoding.DecodeString(result)
				if err != nil {
					t.Errorf("result is not valid base64: %v", err)
				}

				// Verify steps are not empty
				if len(steps) == 0 {
					t.Error("expected non-empty steps")
				}

				// For repeating text, verify pattern detection
				if tt.name == "repeating text" {
					patternFound := false
					for _, step := range steps {
						if step == "• Ciphertext pattern found in blocks: [0 1]" {
							patternFound = true
							break
						}
					}
					if !patternFound {
						t.Error("expected pattern detection for repeating text")
					}
				}
			}
		})
	}
}

func TestECBProcessor_Pad(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantLen     int
		description string
	}{
		{
			name:        "empty input",
			input:       []byte{},
			wantLen:     16,
			description: "should pad empty input to block size",
		},
		{
			name:        "partial block",
			input:       []byte("Hello"),
			wantLen:     16,
			description: "should pad partial block to block size",
		},
		{
			name:        "full block",
			input:       []byte("1234567890123456"),
			wantLen:     32,
			description: "should pad full block to next block size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewECBProcessor()
			result := p.pad(tt.input)
			if len(result) != tt.wantLen {
				t.Errorf("pad() length = %v, want %v", len(result), tt.wantLen)
			}

			// Verify padding bytes
			padding := result[len(tt.input):]
			paddingValue := int(padding[0])
			if paddingValue != len(padding) {
				t.Errorf("invalid padding value: got %v, want %v", paddingValue, len(padding))
			}
			for i := 1; i < len(padding); i++ {
				if padding[i] != padding[0] {
					t.Errorf("inconsistent padding at index %d: got %v, want %v", i, padding[i], padding[0])
				}
			}
		})
	}
}
