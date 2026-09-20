package crypto

import (
	"strings"
	"testing"
)

func TestRSAProcessor_Configure(t *testing.T) {
	processor := NewRSAProcessor()
	config := map[string]interface{}{
		"keySize":        2048,
		"publicKeyFile":  "keys/test_rsa_public.pem",
		"privateKeyFile": "keys/test_rsa_private.pem",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure RSAProcessor: %v", err)
	}
}

func TestRSAProcessor_Process_EncryptDecrypt(t *testing.T) {
	processor := NewRSAProcessor()
	config := map[string]interface{}{
		"keySize":        2048,
		"publicKeyFile":  "keys/test_rsa_public.pem",
		"privateKeyFile": "keys/test_rsa_private.pem",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure RSAProcessor: %v", err)
	}
	plaintext := "Hello, RSA!"
	ciphertext, steps, err := processor.Process(plaintext, OperationEncrypt)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if ciphertext == "" {
		t.Error("Expected non-empty ciphertext")
	}
	if len(steps) == 0 {
		t.Error("Expected non-empty steps for encryption")
	}
	decrypted, steps, err := processor.Process(ciphertext, OperationDecrypt)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("Decryption result = %v, want %v", decrypted, plaintext)
	}
	if len(steps) == 0 {
		t.Error("Expected non-empty steps for decryption")
	}
}

func TestRSAProcessor_Process_InvalidOperation(t *testing.T) {
	processor := NewRSAProcessor()
	config := map[string]interface{}{
		"keySize":        2048,
		"publicKeyFile":  "keys/test_rsa_public.pem",
		"privateKeyFile": "keys/test_rsa_private.pem",
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure RSAProcessor: %v", err)
	}
	_, _, err := processor.Process("test", "invalid")
	if err == nil {
		t.Error("Expected error for invalid operation, got nil")
	}
}

func newTestRSA(t *testing.T) *RSAProcessor {
	t.Helper()
	p := NewRSAProcessor()
	if err := p.Configure(map[string]interface{}{
		"keySize":        2048,
		"publicKeyFile":  "keys/test_rsa_public.pem",
		"privateKeyFile": "keys/test_rsa_private.pem",
	}); err != nil {
		t.Fatalf("configure: %v", err)
	}
	return p
}

func rsaAssertContains(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			t.Errorf("expected steps to contain %q, but they did not", n)
		}
	}
}

// The output must teach the asymmetric key pair, the factoring trapdoor, the
// c=m^e mod n math, and real-world uses (hybrid, signatures).
func TestRSA_EducationalContent(t *testing.T) {
	p := newTestRSA(t)
	_, steps, err := p.Process("Hi", OperationEncrypt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	joined := strings.Join(steps, "\n")
	rsaAssertContains(t, joined,
		"PUBLIC-KEY",
		"trapdoor",
		"c = m^e mod n",
		"Worked example",
		"Hybrid encryption",
		"Shor's algorithm",
		"Public exponent (e): 65537",
	)
}

// The worked example must compute the classic p=61,q=53 result correctly so the
// arithmetic on screen is trustworthy.
func TestRSA_WorkedExampleIsCorrect(t *testing.T) {
	p := newTestRSA(t)
	_, steps, _ := p.Process("x", OperationEncrypt)
	joined := strings.Join(steps, "\n")
	rsaAssertContains(t, joined,
		"n = p·q = 3233",
		"φ(n) = (p−1)(q−1) = 3120",
		"d = e⁻¹ mod φ = 2753",
		"c = m^e mod n = 2790",
		"m = c^d mod n = 65",
	)
}

// Oversized messages must fail with a helpful, specific error before hitting the
// crypto library's opaque one.
func TestRSA_MessageTooLarge(t *testing.T) {
	p := newTestRSA(t)
	big := strings.Repeat("A", 300) // > 245-byte limit for RSA-2048 PKCS#1 v1.5
	_, _, err := p.Process(big, OperationEncrypt)
	if err == nil {
		t.Fatal("expected error for oversized message, got nil")
	}
	if !strings.Contains(err.Error(), "hybrid encryption") {
		t.Errorf("error should guide toward hybrid encryption, got: %v", err)
	}
}

// The decryption walkthrough must show the private-key formula and recovered bytes.
func TestRSA_DecryptEducationalContent(t *testing.T) {
	p := newTestRSA(t)
	enc, _, err := p.Process("secret", OperationEncrypt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	dec, steps, err := p.Process(enc, OperationDecrypt)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if dec != "secret" {
		t.Errorf("round trip: got %q, want %q", dec, "secret")
	}
	rsaAssertContains(t, strings.Join(steps, "\n"),
		"m = c^d mod n",
		"Recovered Bytes",
	)
}
