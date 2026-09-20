package crypto

import (
	"strings"
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

// joinSteps returns all visualization steps as one string for substring checks.
func joinSteps(t *testing.T, input, operation string) string {
	t.Helper()
	_, steps, err := NewBase64Processor().Process(input, operation)
	if err != nil {
		t.Fatalf("Process(%q, %q) unexpected error: %v", input, operation, err)
	}
	return strings.Join(steps, "\n")
}

func assertContainsAll(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			t.Errorf("expected steps to contain %q, but they did not", n)
		}
	}
}

// The educational output must teach the index-based alphabet and the
// 3-bytes-to-4-characters mechanic, not just describe them.
func TestBase64Encode_EducationalContent(t *testing.T) {
	steps := joinSteps(t, "Hi", OperationEncrypt)
	assertContainsAll(t, steps,
		"The Base64 alphabet",    // index table present
		"3 bytes ↔ 4 characters", // core mechanic explained
		"Worked example",         // concrete walkthrough present
		"Concatenate into",       // bit-string construction shown
		"6-bit groups",           // regrouping shown
		"Base64URL",              // JWT-relevant variant mentioned
		"NOT encryption",         // security framing present
	)
}

// The index table must teach indices (A=0), not ASCII codes (A=65), since the
// old version showed ASCII values that do not drive the encoding.
func TestBase64_AlphabetShowsIndicesNotASCII(t *testing.T) {
	steps := joinSteps(t, "Hi", OperationEncrypt)
	assertContainsAll(t, steps, "index → character", " 0-25  A B C")
	if strings.Contains(steps, "A(65)") {
		t.Error("alphabet table still shows ASCII codes (A(65)); it should show indices")
	}
}

// Padding analysis must be computed for the specific input length.
func TestBase64Encode_PaddingAnalysis(t *testing.T) {
	cases := []struct {
		input  string
		expect string
	}{
		{"A", "Remainder 1"},      // 1 byte  -> "=="
		{"Hi", "Remainder 2"},     // 2 bytes -> "="
		{"Hel", "no '=' padding"}, // 3 bytes -> none
	}
	for _, c := range cases {
		steps := joinSteps(t, c.input, OperationEncrypt)
		if !strings.Contains(steps, c.expect) {
			t.Errorf("input %q: expected padding analysis %q in steps", c.input, c.expect)
		}
	}
}

// The decode walkthrough must reverse the transformation correctly: "SGk="
// decodes to "Hi", so byte values 72 and 105 should appear, plus the note
// about discarded leftover bits.
func TestBase64Decode_WorkedExample(t *testing.T) {
	steps := joinSteps(t, "SGk=", OperationDecrypt)
	assertContainsAll(t, steps,
		"Worked example",
		"Index (0-63)",
		"6-bit value",
		"72",  // 'H'
		"105", // 'i'
		"leftover",
		"padding marker",
	)
}

// Empty input should not fabricate a worked example.
func TestBase64Encode_EmptyNoWorkedExample(t *testing.T) {
	steps := joinSteps(t, "", OperationEncrypt)
	if strings.Contains(steps, "Worked example") {
		t.Error("empty input should not produce a worked example")
	}
	if !strings.Contains(steps, "The Base64 alphabet") {
		t.Error("empty input should still show the educational intro")
	}
}
