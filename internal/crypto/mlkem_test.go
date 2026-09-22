package crypto

import (
	"strings"
	"testing"
)

func TestNewMLKEMProcessor(t *testing.T) {
	p := NewMLKEMProcessor()
	if p == nil {
		t.Fatal("NewMLKEMProcessor returned nil")
	}
	if p.level != 768 {
		t.Errorf("expected default level 768, got %d", p.level)
	}
}

func TestMLKEMProcessor_Configure(t *testing.T) {
	p := NewMLKEMProcessor()
	if err := p.Configure(map[string]any{"level": 1024}); err != nil {
		t.Fatalf("configure 1024: %v", err)
	}
	if p.level != 1024 {
		t.Errorf("expected level 1024, got %d", p.level)
	}
	if err := p.Configure(map[string]any{"level": 512}); err == nil {
		t.Error("expected error for invalid level 512")
	}
}

// The demonstration must round-trip (Alice and Bob agree) for both parameter
// sets, and the shared secret must be 32 bytes.
func TestMLKEMProcessor_RoundTrip(t *testing.T) {
	for _, level := range []int{768, 1024} {
		p := NewMLKEMProcessor()
		if err := p.Configure(map[string]any{"level": level}); err != nil {
			t.Fatalf("configure %d: %v", level, err)
		}
		r, err := p.run()
		if err != nil {
			t.Fatalf("run %d: %v", level, err)
		}
		if len(r.sharedBob) != 32 || len(r.sharedAli) != 32 {
			t.Errorf("level %d: shared secret not 32 bytes", level)
		}
		if string(r.sharedBob) != string(r.sharedAli) {
			t.Errorf("level %d: encapsulated and decapsulated secrets differ", level)
		}
	}
}

// The output must teach the KEM idea, the quantum motivation, the size
// trade-off, and the hybrid-deployment guidance.
func TestMLKEMProcessor_EducationalContent(t *testing.T) {
	p := NewMLKEMProcessor()
	_, steps, err := p.Process("", "")
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	joined := strings.Join(steps, "\n")
	for _, needle := range []string{
		"FIPS 203",
		"Shor's algorithm",
		"Encapsulate",
		"Decapsulate",
		"HYBRID",
		"ML-DSA", // cross-reference to signatures
	} {
		if !strings.Contains(joined, needle) {
			t.Errorf("expected ML-KEM steps to contain %q", needle)
		}
	}
}
