package crypto

import (
	"strings"
	"testing"
)

func TestHMACProcessor_Configure(t *testing.T) {
	processor := NewHMACProcessor()
	config := map[string]interface{}{
		"hashAlgorithm": HashSHA256,
		"keyFile":       "keys/test_hmac_key.bin",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure HMACProcessor: %v", err)
	}
}

func TestHMACProcessor_Process_SHA256(t *testing.T) {
	processor := NewHMACProcessor()
	config := map[string]interface{}{
		"hashAlgorithm": HashSHA256,
		"keyFile":       "keys/test_hmac_key.bin",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure HMACProcessor: %v", err)
	}
	input := "hello world"
	result, steps, err := processor.Process(input, OperationEncrypt)
	if err != nil {
		t.Fatalf("HMACProcessor.Process() error = %v", err)
	}
	if result == "" {
		t.Error("Expected non-empty result for HMAC SHA-256")
	}
	if len(steps) == 0 {
		t.Error("Expected non-empty steps for HMAC SHA-256")
	}
}

func TestHMACProcessor_Process_InvalidOperation(t *testing.T) {
	processor := NewHMACProcessor()
	config := map[string]interface{}{
		"hashAlgorithm": HashSHA256,
		"keyFile":       "keys/test_hmac_key.bin",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure HMACProcessor: %v", err)
	}
	_, _, err := processor.Process("test", "invalid")
	if err == nil {
		t.Error("Expected error for invalid operation, got nil")
	}
}

func newTestHMAC(t *testing.T, algo string) *HMACProcessor {
	t.Helper()
	p := NewHMACProcessor()
	if err := p.Configure(map[string]interface{}{
		"hashAlgorithm": algo,
		"keyFile":       "keys/test_hmac_key.bin",
	}); err != nil {
		t.Fatalf("configure: %v", err)
	}
	return p
}

func hmacSteps(t *testing.T, algo, input string) string {
	t.Helper()
	_, steps, err := newTestHMAC(t, algo).Process(input, OperationEncrypt)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	return strings.Join(steps, "\n")
}

func hmacAssertContains(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			t.Errorf("expected steps to contain %q, but they did not", n)
		}
	}
}

// The output must teach the nested construction, why it exists (length
// extension), the verification workflow, and constant-time comparison.
func TestHMAC_EducationalContent(t *testing.T) {
	steps := hmacSteps(t, HashSHA256, "hi")
	hmacAssertContains(t, steps,
		"Authenticity",
		"length-extension attack",
		"H( (K⊕opad) ‖ H( (K⊕ipad) ‖ m ) )", // the nested formula
		"Inner hash",                        // intermediate value shown
		"Verification",
		"REJECT",        // tamper case demonstrated
		"CONSTANT TIME", // timing-safe comparison
	)
}

// The hand-computed construction must match Go's crypto/hmac for every
// supported algorithm — this is asserted in the output and re-checked here.
func TestHMAC_HandComputationMatchesLibrary(t *testing.T) {
	for _, algo := range []string{
		HashSHA1, HashSHA256, HashSHA512,
		HashBLAKE2b256, HashBLAKE2b512, HashBLAKE3,
	} {
		steps := hmacSteps(t, algo, "verify me")
		if !strings.Contains(steps, "matches Go's crypto/hmac output exactly") {
			t.Errorf("%s: hand-computed tag did not match the library", algo)
		}
		if strings.Contains(steps, "does NOT match") {
			t.Errorf("%s: construction mismatch reported", algo)
		}
	}
}

// The verification demo must actually accept the real message and reject a
// tampered one.
func TestHMAC_VerificationDemo(t *testing.T) {
	steps := hmacSteps(t, HashSHA256, "transfer $10")
	hmacAssertContains(t, steps,
		"→ ACCEPT ✅",
		"→ REJECT ✅",
		"hmac.Equal(sent, recomputed) = false",
	)
}
