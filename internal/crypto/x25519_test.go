package crypto

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func TestNewX25519Processor(t *testing.T) {
	processor := NewX25519Processor()
	if processor == nil {
		t.Fatal("NewX25519Processor returned nil")
	}
	if processor.keyManager == nil {
		t.Fatal("keyManager is nil")
	}
}

func TestX25519Processor_Configure(t *testing.T) {
	processor := NewX25519Processor()

	// Test with valid configuration
	config := map[string]interface{}{
		"privateKeyFile": "test_private.bin",
	}
	err := processor.Configure(config)
	if err != nil {
		t.Errorf("Configure failed with valid config: %v", err)
	}

	// Test with invalid configuration
	invalidConfig := map[string]interface{}{
		"privateKeyFile": 123, // Invalid type
	}
	err = processor.Configure(invalidConfig)
	if err == nil {
		t.Error("Configure should fail with invalid config")
	}
}

func TestX25519Processor_Process(t *testing.T) {
	processor := NewX25519Processor()

	// Test key exchange
	result, steps, err := processor.Process("", "")
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	// Verify result
	if result == "" {
		t.Error("Process returned empty result")
	}

	// Verify steps
	if len(steps) == 0 {
		t.Error("Process returned no steps")
	}

	// Verify key exchange steps are present
	keyExchangeFound := false
	sharedSecretFound := false
	for _, step := range steps {
		if step == "Step 2: Public Key Calculation" {
			keyExchangeFound = true
		}
		if step == "Step 3: Shared Secret Calculation" {
			sharedSecretFound = true
		}
	}
	if !keyExchangeFound {
		t.Error("Key exchange step not found in output")
	}
	if !sharedSecretFound {
		t.Error("Shared secret calculation step not found in output")
	}
}

func TestX25519KeyExchange(t *testing.T) {
	// Generate private keys
	alicePrivate := make([]byte, 32)
	bobPrivate := make([]byte, 32)

	_, err := rand.Read(alicePrivate)
	if err != nil {
		t.Fatalf("Failed to generate Alice's private key: %v", err)
	}
	_, err = rand.Read(bobPrivate)
	if err != nil {
		t.Fatalf("Failed to generate Bob's private key: %v", err)
	}

	// Apply X25519 key clamping
	alicePrivate[0] &= 248
	alicePrivate[31] &= 127
	alicePrivate[31] |= 64
	bobPrivate[0] &= 248
	bobPrivate[31] &= 127
	bobPrivate[31] |= 64

	// Generate public keys
	alicePublic, err := curve25519.X25519(alicePrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("Failed to generate Alice's public key: %v", err)
	}
	bobPublic, err := curve25519.X25519(bobPrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("Failed to generate Bob's public key: %v", err)
	}

	// Calculate shared secrets
	aliceShared, err := curve25519.X25519(alicePrivate, bobPublic)
	if err != nil {
		t.Fatalf("Failed to calculate Alice's shared secret: %v", err)
	}
	bobShared, err := curve25519.X25519(bobPrivate, alicePublic)
	if err != nil {
		t.Fatalf("Failed to calculate Bob's shared secret: %v", err)
	}

	// Verify shared secrets match
	if !bytes.Equal(aliceShared, bobShared) {
		t.Error("Shared secrets do not match")
	}
}

func TestX25519Performance(t *testing.T) {
	processor := NewX25519Processor()

	// Measure X25519 performance
	start := time.Now()
	_, _, err := processor.Process("", "")
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	x25519Duration := time.Since(start)

	// Verify performance is reasonable (should be under 100ms)
	if x25519Duration > 100*time.Millisecond {
		t.Errorf("X25519 performance too slow: %v", x25519Duration)
	}
}

func x25519Steps(t *testing.T) string {
	t.Helper()
	_, steps, err := NewX25519Processor().Process("", "")
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	return strings.Join(steps, "\n")
}

// The output must teach the ECDH nature, clamping, scalar multiplication, the
// need for authentication, and the TLS 1.3 role.
func TestX25519_EducationalContent(t *testing.T) {
	joined := x25519Steps(t)
	for _, needle := range []string{
		"ECDH",                  // elliptic-curve DH framing
		"clamp",                 // clamping explained
		"scalar multiplication", // the core op
		"(a·b)·G",               // the symmetry
		"MITM",                  // authentication requirement
		"Perfect Forward Secrecy",
		"TLS 1.3",
	} {
		if !strings.Contains(joined, needle) {
			t.Errorf("expected X25519 steps to contain %q", needle)
		}
	}
}

// Clamping must actually be applied: the generated private key's clamped bits
// must satisfy the X25519 invariants.
func TestX25519_ClampScalar(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = 0xff
	}
	c := clampScalar(raw)
	if c[0]&0x07 != 0 {
		t.Errorf("low 3 bits not cleared: %08b", c[0])
	}
	if c[31]&0x80 != 0 {
		t.Errorf("top bit not cleared: %08b", c[31])
	}
	if c[31]&0x40 == 0 {
		t.Errorf("bit 254 not set: %08b", c[31])
	}
	// The original must be untouched (clampScalar copies).
	if raw[0] != 0xff {
		t.Error("clampScalar mutated its input")
	}
}

// The security section must still surface the Curve25519 properties users rely on.
func TestX25519_SecurityProperties(t *testing.T) {
	joined := x25519Steps(t)
	for _, warning := range []string{
		"constant-time operations",
		"resistant to side-channel attacks",
		"better protection against timing attacks",
		"no known practical attacks against Curve25519",
		"smaller attack surface due to simpler implementation",
	} {
		if !strings.Contains(joined, warning) {
			t.Errorf("security property not found: %s", warning)
		}
	}
}
