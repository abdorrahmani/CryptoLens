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

func TestX25519TLSHandshake(t *testing.T) {
	processor := NewX25519Processor()

	// Run the TLS handshake simulation
	result, steps, err := processor.Process("", "")
	if err != nil {
		t.Fatalf("TLS handshake simulation failed: %v", err)
	}

	// Verify TLS handshake steps are present
	tlsSteps := []string{
		"1. Client Hello",
		"2. Server Hello",
		"3. Server Certificate",
		"4. Server Key Exchange",
		"5. Client Key Exchange",
		"6. Finished Messages",
		"7. Derived Session Keys",
	}

	for _, expectedStep := range tlsSteps {
		found := false
		for _, step := range steps {
			if step == expectedStep {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("TLS handshake step not found: %s", expectedStep)
		}
	}

	// Verify result contains success message
	if result == "" {
		t.Error("TLS handshake simulation returned empty result")
	}
}

func TestX25519SecurityWarnings(t *testing.T) {
	processor := NewX25519Processor()
	_, steps, err := processor.Process("", "")
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	expectedWarnings := []string{
		"Resistant to side-channel attacks",
		"Better protection against timing attacks",
		"Constant-time operations by design",
		"No known practical attacks against Curve25519",
		"Smaller attack surface due to simpler implementation",
	}

	for _, warning := range expectedWarnings {
		found := false
		for _, step := range steps {
			if strings.Contains(step, warning) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Security warning not found: %s", warning)
		}
	}
}
