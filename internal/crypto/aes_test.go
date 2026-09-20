package crypto

import (
	"encoding/base64"
	"strings"
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
				"keyFile": "keys/test_key.bin",
			},
			wantErr: false,
			keySize: 128,
			keyFile: "test_key.bin",
		},
		{
			name: "invalid key size",
			config: map[string]interface{}{
				"keySize": 512,
				"keyFile": "keys/test_key.bin",
			},
			wantErr: true,
		},
		{
			name:    "default values",
			config:  map[string]interface{}{},
			wantErr: false,
			keySize: 256,
			keyFile: "keys/aes_key.bin",
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
		"keyFile": "keys/test_aes_key.bin",
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
		"keyFile": "keys/test_aes_key.bin",
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
		"keyFile": "keys/test_aes_key.bin",
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
		"keyFile": "keys/test_aes_key.bin",
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

// aesSteps configures a processor and returns its joined step output.
func aesSteps(t *testing.T, input, operation string) string {
	t.Helper()
	p := NewAESProcessor()
	if err := p.Configure(map[string]interface{}{"keySize": 256, "keyFile": "keys/test_aes_key.bin"}); err != nil {
		t.Fatalf("configure: %v", err)
	}
	_, steps, err := p.Process(input, operation)
	if err != nil {
		t.Fatalf("Process(%q, %q): %v", input, operation, err)
	}
	return strings.Join(steps, "\n")
}

func aesAssertContains(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			t.Errorf("expected steps to contain %q, but they did not", n)
		}
	}
}

// The encryption output must teach the block-cipher vs mode distinction, the
// CBC chaining formula, PKCS#7 padding, and the lack of authentication.
func TestAES_EncryptEducationalContent(t *testing.T) {
	steps := aesSteps(t, "Hi", OperationEncrypt)
	aesAssertContains(t, steps,
		"block cipher and the mode",
		"CBC mode: chaining",
		"C[1] = AES_encrypt(P[1] XOR IV)",
		"PKCS#7 padding",
		"NOT authenticity",
		"ChaCha20-Poly1305",
		"14 transformation rounds", // AES-256 round count
	)
}

// PKCS#7 detail must be computed for the specific input length.
func TestAES_PaddingExplanationIsConcrete(t *testing.T) {
	// "Hi" is 2 bytes → 14 padding bytes of 0x0E.
	steps := aesSteps(t, "Hi", OperationEncrypt)
	aesAssertContains(t, steps, "14 byte(s) of padding", "0x0E")
}

// The decryption walkthrough must show the CBC decryption formula and unpadding.
func TestAES_DecryptEducationalContent(t *testing.T) {
	p := NewAESProcessor()
	if err := p.Configure(map[string]interface{}{"keySize": 256, "keyFile": "keys/test_aes_key.bin"}); err != nil {
		t.Fatalf("configure: %v", err)
	}
	enc, _, err := p.Process("Hello", OperationEncrypt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	_, steps, err := p.Process(enc, OperationDecrypt)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	joined := strings.Join(steps, "\n")
	aesAssertContains(t, joined,
		"P[1] = AES_decrypt(C[1]) XOR IV",
		"Extracted IV",
		"padding and removed",
	)
}

// unpad must reject padding whose bytes are internally inconsistent, not just a
// bad final byte (full PKCS#7 validation).
func TestAES_UnpadRejectsInconsistentPadding(t *testing.T) {
	p := NewAESProcessor()
	// Last byte claims 3 padding bytes, but the preceding two are not 0x03.
	bad := make([]byte, 16)
	bad[13], bad[14], bad[15] = 0x01, 0x02, 0x03
	if _, err := p.unpad(bad); err == nil {
		t.Error("expected error for inconsistent PKCS#7 padding, got nil")
	}

	// Well-formed padding of 3 must succeed.
	good := make([]byte, 16)
	good[13], good[14], good[15] = 0x03, 0x03, 0x03
	if _, err := p.unpad(good); err != nil {
		t.Errorf("valid padding rejected: %v", err)
	}
}
