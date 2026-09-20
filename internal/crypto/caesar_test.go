package crypto

import (
	"strings"
	"testing"
)

func TestNewCaesarProcessor(t *testing.T) {
	processor := NewCaesarProcessor()
	if processor == nil {
		t.Fatal("NewCaesarProcessor returned nil")
	}
	if processor.shift != 3 {
		t.Errorf("Expected default shift 3, got %d", processor.shift)
	}
}

func TestCaesarProcessor_Configure(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		shift   int
	}{
		{
			name: "valid shift",
			config: map[string]interface{}{
				"shift": 5,
			},
			wantErr: false,
			shift:   5,
		},
		{
			name: "zero shift",
			config: map[string]interface{}{
				"shift": 0,
			},
			wantErr: false,
			shift:   0,
		},
		{
			name: "negative shift",
			config: map[string]interface{}{
				"shift": -3,
			},
			wantErr: false,
			shift:   -3,
		},
		{
			name:    "default shift",
			config:  map[string]interface{}{},
			wantErr: false,
			shift:   3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewCaesarProcessor()
			err := processor.Configure(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("CaesarProcessor.Configure() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if processor.shift != tt.shift {
				t.Errorf("shift = %v, want %v", processor.shift, tt.shift)
			}
		})
	}
}

func TestCaesarProcessor_Process_Encrypt(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		shift   int
		want    string
		wantErr bool
	}{
		{
			name:    "simple text",
			input:   "HELLO",
			shift:   3,
			want:    "KHOOR",
			wantErr: false,
		},
		{
			name:    "with spaces",
			input:   "HELLO WORLD",
			shift:   3,
			want:    "KHOOR ZRUOG",
			wantErr: false,
		},
		{
			name:    "with punctuation",
			input:   "HELLO, WORLD!",
			shift:   3,
			want:    "KHOOR, ZRUOG!",
			wantErr: false,
		},
		{
			name:    "zero shift",
			input:   "HELLO",
			shift:   0,
			want:    "HELLO",
			wantErr: false,
		},
		{
			name:    "negative shift",
			input:   "HELLO",
			shift:   -3,
			want:    "EBIIL",
			wantErr: false,
		},
		{
			name:    "large shift",
			input:   "HELLO",
			shift:   27,
			want:    "IFMMP",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewCaesarProcessor()
			err := processor.Configure(map[string]interface{}{
				"shift": tt.shift,
			})
			if err != nil {
				t.Fatalf("Failed to configure processor: %v", err)
			}

			got, steps, err := processor.Process(tt.input, OperationEncrypt)
			if (err != nil) != tt.wantErr {
				t.Errorf("CaesarProcessor.Process() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CaesarProcessor.Process() = %v, want %v", got, tt.want)
			}
			if len(steps) == 0 {
				t.Error("CaesarProcessor.Process() returned no steps")
			}
		})
	}
}

func TestCaesarProcessor_Process_Decrypt(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		shift   int
		want    string
		wantErr bool
	}{
		{
			name:    "simple text",
			input:   "KHOOR",
			shift:   3,
			want:    "HELLO",
			wantErr: false,
		},
		{
			name:    "with spaces",
			input:   "KHOOR ZRUOG",
			shift:   3,
			want:    "HELLO WORLD",
			wantErr: false,
		},
		{
			name:    "with punctuation",
			input:   "KHOOR, ZRUOG!",
			shift:   3,
			want:    "HELLO, WORLD!",
			wantErr: false,
		},
		{
			name:    "zero shift",
			input:   "HELLO",
			shift:   0,
			want:    "HELLO",
			wantErr: false,
		},
		{
			name:    "negative shift",
			input:   "EBIIL",
			shift:   -3,
			want:    "HELLO",
			wantErr: false,
		},
		{
			name:    "large shift",
			input:   "IFMMP",
			shift:   27,
			want:    "HELLO",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewCaesarProcessor()
			err := processor.Configure(map[string]interface{}{
				"shift": tt.shift,
			})
			if err != nil {
				t.Fatalf("Failed to configure processor: %v", err)
			}

			got, steps, err := processor.Process(tt.input, OperationDecrypt)
			if (err != nil) != tt.wantErr {
				t.Errorf("CaesarProcessor.Process() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CaesarProcessor.Process() = %v, want %v", got, tt.want)
			}
			if len(steps) == 0 {
				t.Error("CaesarProcessor.Process() returned no steps")
			}
		})
	}
}

func TestCaesarProcessor_Process_InvalidOperation(t *testing.T) {
	processor := NewCaesarProcessor()
	_, _, err := processor.Process("test", "invalid")
	if err == nil {
		t.Error("Expected error for invalid operation, got nil")
	}
}

func TestCaesarProcessor_Process_RoundTrip(t *testing.T) {
	processor := NewCaesarProcessor()
	original := "HELLO, WORLD! This is a test of the Caesar cipher."

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
		t.Errorf("Round trip failed: got %v, want %v", decrypted, original)
	}
}

func TestCaesarProcessor_Process_NonAlphabetic(t *testing.T) {
	processor := NewCaesarProcessor()
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

// caesarSteps runs the processor with a given shift and returns the joined steps.
func caesarSteps(t *testing.T, input, operation string, shift int) string {
	t.Helper()
	p := NewCaesarProcessor()
	if err := p.Configure(map[string]interface{}{"shift": shift}); err != nil {
		t.Fatalf("configure: %v", err)
	}
	_, steps, err := p.Process(input, operation)
	if err != nil {
		t.Fatalf("Process(%q, %q) error: %v", input, operation, err)
	}
	return strings.Join(steps, "\n")
}

func caesarAssertContains(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			t.Errorf("expected steps to contain %q, but they did not", n)
		}
	}
}

// The output must teach the mechanics: substitution table, formula, and the
// brute-force weakness — not just describe the cipher.
func TestCaesar_EducationalContent(t *testing.T) {
	steps := caesarSteps(t, "HELLO", OperationEncrypt, 3)
	caesarAssertContains(t, steps,
		"Substitution table",
		"C = (P + shift) mod 26", // formula shown
		"brute-forcing all 25 shifts",
		"frequency analysis",
		"Julius Caesar",
	)
}

// The substitution table must reflect the actual shift: shift 3 maps A→D.
func TestCaesar_SubstitutionTableReflectsShift(t *testing.T) {
	steps := caesarSteps(t, "A", OperationEncrypt, 3)
	// Cipher alphabet for shift 3 begins D E F G H...
	caesarAssertContains(t, steps, "D E F G H")
}

// The brute-force section must mark the real key and contain the plaintext at
// that shift so the reader sees the attack succeed.
func TestCaesar_BruteForceMarksRealKey(t *testing.T) {
	// "KHOOR" is "HELLO" encrypted with shift 3; decrypting should reveal it.
	steps := caesarSteps(t, "KHOOR", OperationDecrypt, 3)
	caesarAssertContains(t, steps, "← the real key", "HELLO")
}

// A shift of 13 (ROT13) should be called out as the self-inverse special case.
func TestCaesar_ROT13Note(t *testing.T) {
	steps := caesarSteps(t, "HELLO", OperationEncrypt, 13)
	caesarAssertContains(t, steps, "ROT13")
}

// Out-of-range shifts should be normalized and explained (27 ≡ 1).
func TestCaesar_NormalizesShift(t *testing.T) {
	steps := caesarSteps(t, "HELLO", OperationEncrypt, 27)
	caesarAssertContains(t, steps, "equivalent to a shift of 1")
}

// Long inputs must cap the per-character walkthrough rather than flooding.
func TestCaesar_WalkthroughCapped(t *testing.T) {
	long := strings.Repeat("A", 50)
	steps := caesarSteps(t, long, OperationEncrypt, 3)
	caesarAssertContains(t, steps, "more letter(s) transformed the same way")
}
