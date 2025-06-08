package crypto

import (
	"math/big"
	"path/filepath"
	"testing"
)

func TestNewDHProcessor(t *testing.T) {
	processor := NewDHProcessor()
	if processor == nil {
		t.Fatal("NewDHProcessor returned nil")
	}
	if processor.keySize != 2048 {
		t.Errorf("Expected keySize 2048, got %d", processor.keySize)
	}
	if processor.generator.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("Expected generator 2, got %s", processor.generator.Text(10))
	}
}

func TestDHProcessor_Configure(t *testing.T) {
	processor := NewDHProcessor()

	// Create a temporary directory for test files
	tempDir := t.TempDir()
	testPrimeFile := filepath.Join(tempDir, "test_prime.bin")

	// Test with valid configuration
	config := map[string]interface{}{
		"keySize":   4096,
		"generator": 5,
		"primeFile": testPrimeFile,
	}

	err := processor.Configure(config)
	if err != nil {
		t.Errorf("Configure failed with valid config: %v", err)
	}

	if processor.keySize != 4096 {
		t.Errorf("Expected keySize 4096, got %d", processor.keySize)
	}
	if processor.generator.Cmp(big.NewInt(5)) != 0 {
		t.Errorf("Expected generator 5, got %s", processor.generator.Text(10))
	}
}

func TestDHProcessor_Process(t *testing.T) {
	processor := NewDHProcessor()
	_, steps, err := processor.Process("", "")
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	expectedSteps := []string{
		"Step 1: Prime Number Setup",
		"Step 2: Private Key Generation",
		"Step 3: Public Key Calculation",
		"Step 4: Key Authentication",
		"Step 5: Shared Secret Calculation",
		"Step 6: Shared Secret Verification",
		"Step 7: Key Derivation",
		"Step 8: Using Shared Secret for AES Encryption",
	}

	for _, expectedStep := range expectedSteps {
		found := false
		for _, step := range steps {
			if step == expectedStep {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected step not found: %s", expectedStep)
		}
	}
}

func TestDHProcessor_GeneratePrivateKey(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()
	testPrimeFile := filepath.Join(tempDir, "test_prime.bin")

	processor := NewDHProcessor()
	config := map[string]interface{}{
		"primeFile": testPrimeFile,
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure processor: %v", err)
	}

	// Load prime first
	prime, err := processor.loadOrGeneratePrime()
	if err != nil {
		t.Fatalf("Failed to load/generate prime: %v", err)
	}
	processor.prime = prime

	// Test private key generation
	private, err := processor.generatePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	if private == nil {
		t.Fatal("Generated private key is nil")
	}

	// Verify private key is less than prime
	if private.Cmp(prime) >= 0 {
		t.Error("Private key should be less than prime")
	}
}

func TestDHProcessor_KeyExchange(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()
	testPrimeFile := filepath.Join(tempDir, "test_prime.bin")

	processor := NewDHProcessor()
	config := map[string]interface{}{
		"primeFile": testPrimeFile,
	}
	if err := processor.Configure(config); err != nil {
		t.Fatalf("Failed to configure processor: %v", err)
	}

	// Load prime first
	prime, err := processor.loadOrGeneratePrime()
	if err != nil {
		t.Fatalf("Failed to load/generate prime: %v", err)
	}
	processor.prime = prime

	// Generate private keys
	alicePrivate, err := processor.generatePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate Alice's private key: %v", err)
	}

	bobPrivate, err := processor.generatePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate Bob's private key: %v", err)
	}

	// Calculate public keys
	alicePublic := new(big.Int).Exp(processor.generator, alicePrivate, prime)
	bobPublic := new(big.Int).Exp(processor.generator, bobPrivate, prime)

	// Calculate shared secrets
	aliceShared := new(big.Int).Exp(bobPublic, alicePrivate, prime)
	bobShared := new(big.Int).Exp(alicePublic, bobPrivate, prime)

	// Verify shared secrets match
	if aliceShared.Cmp(bobShared) != 0 {
		t.Error("Shared secrets do not match")
	}
}

func TestDHProcessor_InvalidConfig(t *testing.T) {
	processor := NewDHProcessor()

	// Test with invalid key size
	config := map[string]interface{}{
		"keySize": "invalid",
	}

	err := processor.Configure(config)
	if err == nil {
		t.Error("Expected error with invalid key size")
	}

	// Test with invalid generator
	config = map[string]interface{}{
		"generator": "invalid",
	}

	err = processor.Configure(config)
	if err == nil {
		t.Error("Expected error with invalid generator")
	}
}
