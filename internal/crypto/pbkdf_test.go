package crypto

import (
	"strings"
	"testing"
)

func TestPBKDFProcessor_Configure(t *testing.T) {
	processor := NewPBKDFProcessor()
	config := map[string]interface{}{
		"iterations": 1000,
		"saltSize":   8,
		"keyFile":    "keys/test_pbkdf_key.bin",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure PBKDFProcessor: %v", err)
	}
}

func TestPBKDFProcessor_Process_SHA256(t *testing.T) {
	processor := NewPBKDFProcessor()
	config := map[string]interface{}{
		"iterations": 1000,
		"saltSize":   8,
		"keyFile":    "keys/test_pbkdf_key.bin",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure PBKDFProcessor: %v", err)
	}
	input := "password123"
	result, steps, err := processor.Process(input, OperationEncrypt)
	if err != nil {
		t.Fatalf("PBKDFProcessor.Process() error = %v", err)
	}
	if result == "" {
		t.Error("Expected non-empty result for PBKDF2-SHA256")
	}
	if len(steps) == 0 {
		t.Error("Expected non-empty steps for PBKDF2-SHA256")
	}
}

func newTestPBKDF(t *testing.T, algo string) *PBKDFProcessor {
	t.Helper()
	p := NewPBKDFProcessor()
	if err := p.Configure(map[string]interface{}{
		"algorithm": algo,
		"keyFile":   "keys/test_pbkdf_key.bin",
	}); err != nil {
		t.Fatalf("configure %s: %v", algo, err)
	}
	return p
}

func pbkdfSteps(t *testing.T, algo, input string) string {
	t.Helper()
	_, steps, err := newTestPBKDF(t, algo).Process(input, OperationEncrypt)
	if err != nil {
		t.Fatalf("Process(%s): %v", algo, err)
	}
	return strings.Join(steps, "\n")
}

func pbkdfAssertContains(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			t.Errorf("expected steps to contain %q, but they did not", n)
		}
	}
}

// The output must teach why a KDF exists (salt + work factor vs a fast hash),
// rainbow tables, and the algorithm comparison.
func TestPBKDF_EducationalContent(t *testing.T) {
	steps := pbkdfSteps(t, AlgoArgon2id, "correct horse battery")
	pbkdfAssertContains(t, steps,
		"password-based KDF",
		"rainbow table", // salt purpose
		"WORK FACTOR",   // tunable cost
		"memory-hard",   // argon2/scrypt property
		"brute force",   // ties to menu 12
		"NEVER the password",
	)
}

// Each algorithm must actually run and be named in the output — this guards the
// previously-broken behavior where every choice silently ran PBKDF2.
func TestPBKDF_AllAlgorithmsRun(t *testing.T) {
	cases := map[string]string{
		AlgoPBKDF2:   "PBKDF2-SHA256",
		AlgoArgon2id: "Argon2id",
		AlgoScrypt:   "scrypt",
	}
	seen := map[string]bool{}
	for algo, label := range cases {
		out, steps, err := newTestPBKDF(t, algo).Process("hunter2!", OperationEncrypt)
		if err != nil {
			t.Fatalf("%s: %v", algo, err)
		}
		if !strings.Contains(strings.Join(steps, "\n"), label) {
			t.Errorf("%s: expected output to mention %q", algo, label)
		}
		if seen[out] {
			t.Errorf("%s: produced a derived key identical to another algorithm — "+
				"algorithm selection is being ignored", algo)
		}
		seen[out] = true
	}
}

// An unknown algorithm must be rejected at Configure time.
func TestPBKDF_RejectsUnknownAlgorithm(t *testing.T) {
	p := NewPBKDFProcessor()
	err := p.Configure(map[string]interface{}{
		"algorithm": "bcrypt",
		"keyFile":   "keys/test_pbkdf_key.bin",
	})
	if err == nil {
		t.Error("expected error for unsupported algorithm, got nil")
	}
}
