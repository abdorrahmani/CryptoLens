package crypto

import (
	"strings"
	"testing"
)

func TestNewMLDSAProcessor(t *testing.T) {
	p := NewMLDSAProcessor()
	if p == nil {
		t.Fatal("NewMLDSAProcessor returned nil")
	}
	if p.level != 65 {
		t.Errorf("expected default level 65, got %d", p.level)
	}
}

func TestMLDSAProcessor_Configure(t *testing.T) {
	p := NewMLDSAProcessor()
	for _, lvl := range []int{44, 65, 87} {
		if err := p.Configure(map[string]interface{}{"level": lvl}); err != nil {
			t.Errorf("configure %d: %v", lvl, err)
		}
	}
	if err := p.Configure(map[string]interface{}{"level": 99}); err == nil {
		t.Error("expected error for invalid level 99")
	}
}

// Signing then verifying must succeed for every parameter set.
func TestMLDSAProcessor_SignVerifyAllLevels(t *testing.T) {
	for _, lvl := range []int{44, 65, 87} {
		p := NewMLDSAProcessor()
		if err := p.Configure(map[string]interface{}{"level": lvl}); err != nil {
			t.Fatalf("configure %d: %v", lvl, err)
		}
		result, steps, err := p.Process("sign me", "")
		if err != nil {
			t.Fatalf("process %d: %v", lvl, err)
		}
		if result == "" || len(steps) == 0 {
			t.Errorf("level %d: empty result/steps", lvl)
		}
	}
}

// The output must teach the signature purpose, quantum motivation, the tamper
// rejection, and the size trade-off.
func TestMLDSAProcessor_EducationalContent(t *testing.T) {
	p := NewMLDSAProcessor()
	_, steps, err := p.Process("Transfer $100 to Alice", "")
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	joined := strings.Join(steps, "\n")
	for _, needle := range []string{
		"FIPS 204",
		"Shor's algorithm",
		"Sign the message with the PRIVATE key",
		"verifies with the PUBLIC key",
		"REJECTED",
		"ML-KEM", // cross-reference to the KEM
	} {
		if !strings.Contains(joined, needle) {
			t.Errorf("expected ML-DSA steps to contain %q", needle)
		}
	}
}
