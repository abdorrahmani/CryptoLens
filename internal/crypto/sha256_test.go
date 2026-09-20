package crypto

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestSHA256Processor_Configure(t *testing.T) {
	processor := NewSHA256Processor()
	config := map[string]interface{}{}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure SHA256Processor: %v", err)
	}
}

func TestSHA256Processor_Process(t *testing.T) {
	processor := NewSHA256Processor()
	input := "hello world"
	result, steps, err := processor.Process(input, OperationEncrypt)
	if err != nil {
		t.Fatalf("SHA256Processor.Process() error = %v", err)
	}
	if result == "" {
		t.Error("Expected non-empty result for SHA-256 hash")
	}
	if len(steps) == 0 {
		t.Error("Expected non-empty steps for SHA-256 hash")
	}
}

// The digest must match the canonical FIPS 180-4 test vector for "abc".
func TestSHA256Processor_KnownVector(t *testing.T) {
	const wantHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	result, _, err := NewSHA256Processor().Process("abc", OperationEncrypt)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("result not valid base64: %v", err)
	}
	gotHex := ""
	for _, b := range raw {
		gotHex += string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&0x0f])
	}
	if gotHex != wantHex {
		t.Errorf("SHA-256(\"abc\") = %s, want %s", gotHex, wantHex)
	}
}

func shaSteps(t *testing.T, input string) string {
	t.Helper()
	_, steps, err := NewSHA256Processor().Process(input, OperationEncrypt)
	if err != nil {
		t.Fatalf("Process(%q): %v", input, err)
	}
	return strings.Join(steps, "\n")
}

func shaAssertContains(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			t.Errorf("expected steps to contain %q, but they did not", n)
		}
	}
}

// The output must teach one-wayness, the family context, the avalanche effect,
// and the HMAC/KDF pitfalls — not just describe the algorithm.
func TestSHA256_EducationalContent(t *testing.T) {
	steps := shaSteps(t, "hello")
	shaAssertContains(t, steps,
		"ONE-WAY",
		"SHA-1", // family context
		"avalanche effect",
		"Bits changed:",    // live demonstration
		"Length-extension", // key weakness
		"HMAC",             // mitigation pointer
		"nothing-up-my-sleeve",
	)
}

// Padding must be computed for the specific input: "abc" (24 bits) needs 423
// zero bits and fits in a single 512-bit block.
func TestSHA256_PaddingIsConcrete(t *testing.T) {
	steps := shaSteps(t, "abc")
	shaAssertContains(t, steps, "24 bits", "423 '0' bits", "1 block(s)")
}

// The avalanche demo must report a bit-difference near half of 256.
func TestSHA256_AvalancheIsSubstantial(t *testing.T) {
	_, steps, err := NewSHA256Processor().Process("avalanche", OperationEncrypt)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	joined := strings.Join(steps, "\n")
	// Extract "Bits changed: N of 256" and sanity-check N is in a plausible range.
	i := strings.Index(joined, "Bits changed: ")
	if i < 0 {
		t.Fatal("avalanche demo missing")
	}
	var n int
	if _, err := fmt.Sscanf(joined[i:], "Bits changed: %d", &n); err != nil {
		t.Fatalf("could not parse bit count: %v", err)
	}
	if n < 90 || n > 165 {
		t.Errorf("avalanche bit change = %d, expected roughly half of 256", n)
	}
}
