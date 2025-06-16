package attacks

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNonceReuseProcessor_Configure(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]interface{}
		wantErr     bool
		description string
	}{
		{
			name: "valid key size",
			config: map[string]interface{}{
				"keySize": 256,
			},
			wantErr:     false,
			description: "should accept 256-bit key size",
		},
		{
			name: "invalid key size",
			config: map[string]interface{}{
				"keySize": 128,
			},
			wantErr:     true,
			description: "should reject non-256-bit key size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewNonceReuseProcessor()
			err := p.Configure(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NonceReuseProcessor.Configure() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNonceReuseProcessor_Process(t *testing.T) {
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
			text:        "This is a longer text that will be encrypted with the same nonce",
			operation:   "encrypt",
			wantErr:     false,
			description: "should handle long text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewNonceReuseProcessor()
			err := p.Configure(map[string]interface{}{
				"keySize": 256,
			})
			if err != nil {
				t.Fatalf("failed to configure processor: %v", err)
			}

			result, steps, err := p.Process(tt.text, tt.operation)
			if (err != nil) != tt.wantErr {
				t.Errorf("NonceReuseProcessor.Process() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify result contains two base64 encoded ciphertexts
				if len(result) == 0 {
					t.Error("expected non-empty result")
				}

				// Verify steps are not empty
				if len(steps) == 0 {
					t.Error("expected non-empty steps")
				}

				// Verify result format
				if len(result) < 2 {
					t.Error("expected result to contain two ciphertexts")
				}

				// Verify base64 encoding
				parts := strings.Split(result, "\n")
				if len(parts) != 2 {
					t.Error("expected two lines in result")
				}

				// Extract base64 parts from the result lines
				for _, part := range parts {
					// Each line should be in format "Ciphertext X: <base64>"
					base64Part := strings.TrimPrefix(part, "Ciphertext 1: ")
					base64Part = strings.TrimPrefix(base64Part, "Ciphertext 2: ")
					base64Part = strings.TrimSpace(base64Part)

					_, err := base64.StdEncoding.DecodeString(base64Part)
					if err != nil {
						t.Errorf("result contains invalid base64: %v", err)
					}
				}
			}
		})
	}
}

func TestNonceReuseProcessor_XorBytes(t *testing.T) {
	tests := []struct {
		name        string
		a           []byte
		b           []byte
		want        []byte
		description string
	}{
		{
			name:        "equal length",
			a:           []byte{1, 2, 3},
			b:           []byte{4, 5, 6},
			want:        []byte{5, 7, 5}, // 1^4, 2^5, 3^6
			description: "should XOR bytes of equal length",
		},
		{
			name:        "a longer than b",
			a:           []byte{1, 2, 3, 4},
			b:           []byte{5, 6},
			want:        []byte{4, 4, 3, 4}, // 1^5, 2^6, 3^0, 4^0
			description: "should handle a longer than b",
		},
		{
			name:        "b longer than a",
			a:           []byte{1, 2},
			b:           []byte{3, 4, 5, 6},
			want:        []byte{2, 6, 5, 6}, // 1^3, 2^4, 0^5, 0^6
			description: "should handle b longer than a",
		},
		{
			name:        "empty inputs",
			a:           []byte{},
			b:           []byte{},
			want:        []byte{},
			description: "should handle empty inputs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewNonceReuseProcessor()
			got := p.xorBytes(tt.a, tt.b)
			if len(got) != len(tt.want) {
				t.Errorf("xorBytes() length = %v, want %v", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("xorBytes()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}
