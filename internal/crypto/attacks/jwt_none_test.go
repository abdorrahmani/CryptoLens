package attacks

import (
	"strings"
	"testing"
)

func TestNewJWTNoneProcessor(t *testing.T) {
	processor := NewJWTNoneProcessor()
	if processor == nil {
		t.Fatal("NewJWTNoneProcessor returned nil")
	}
	if processor.BaseProcessor == nil {
		t.Error("BaseProcessor is nil")
	}
	if processor.config == nil {
		t.Error("config is nil")
	}
}

func TestJWTNoneProcessor_Configure(t *testing.T) {
	processor := NewJWTNoneProcessor()

	// Test with nil config
	err := processor.Configure(nil)
	if err != nil {
		t.Errorf("Configure with nil config failed: %v", err)
	}

	// Test with empty config
	err = processor.Configure(map[string]interface{}{})
	if err != nil {
		t.Errorf("Configure with empty config failed: %v", err)
	}

	// Test with arbitrary config
	err = processor.Configure(map[string]interface{}{
		"keySize":   256,
		"algorithm": "HS256",
	})
	if err != nil {
		t.Errorf("Configure with arbitrary config failed: %v", err)
	}
}

func TestJWTNoneProcessor_Process_WithSampleToken(t *testing.T) {
	processor := NewJWTNoneProcessor()

	// Test with empty input (should create sample token)
	result, steps, err := processor.Process("", "attack")
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	// Check that we got a result
	if result == "" {
		t.Error("Expected non-empty result")
	}

	// Check that the result is a valid JWT format
	parts := strings.Split(result, ".")
	if len(parts) != 3 {
		t.Errorf("Expected 3 parts in JWT, got %d", len(parts))
	}

	// Check that the third part (signature) is empty
	if parts[2] != "" {
		t.Errorf("Expected empty signature, got: %s", parts[2])
	}

	// Check that we got steps
	if len(steps) == 0 {
		t.Error("Expected non-empty steps")
	}

	// Check for specific steps
	foundIntroduction := false
	foundSecurityImplications := false
	for _, step := range steps {
		if strings.Contains(step, "JWT None Algorithm Attack Demonstration") {
			foundIntroduction = true
		}
		if strings.Contains(step, "Security Implications") {
			foundSecurityImplications = true
		}
	}

	if !foundIntroduction {
		t.Error("Expected introduction step not found")
	}
	if !foundSecurityImplications {
		t.Error("Expected security implications step not found")
	}
}

func TestJWTNoneProcessor_Process_WithExistingToken(t *testing.T) {
	processor := NewJWTNoneProcessor()

	// Create a sample JWT token
	sampleToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0MjYyMn0.fake_signature"

	result, steps, err := processor.Process(sampleToken, "attack")
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	// Check that we got a result
	if result == "" {
		t.Error("Expected non-empty result")
	}

	// Check that the result is a valid JWT format
	parts := strings.Split(result, ".")
	if len(parts) != 3 {
		t.Errorf("Expected 3 parts in JWT, got %d", len(parts))
	}

	// Check that the third part (signature) is empty
	if parts[2] != "" {
		t.Errorf("Expected empty signature, got: %s", parts[2])
	}

	// Check that the payload is the same
	if parts[1] != "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0MjYyMn0" {
		t.Error("Expected payload to remain unchanged")
	}

	// Check that we got steps
	if len(steps) == 0 {
		t.Error("Expected non-empty steps")
	}
}

func TestJWTNoneProcessor_Process_WithInvalidToken(t *testing.T) {
	processor := NewJWTNoneProcessor()

	// Test with invalid JWT format
	_, _, err := processor.Process("invalid.jwt.token.format", "attack")
	if err == nil {
		t.Error("Expected error for invalid JWT format")
	}

	// Test with malformed JWT
	_, _, err = processor.Process("not.a.jwt", "attack")
	if err == nil {
		t.Error("Expected error for malformed JWT")
	}
}

func TestJWTNoneProcessor_createSampleToken(t *testing.T) {
	processor := NewJWTNoneProcessor()

	token, err := processor.createSampleToken()
	if err != nil {
		t.Fatalf("createSampleToken failed: %v", err)
	}

	// Check that we got a valid JWT
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("Expected 3 parts in JWT, got %d", len(parts))
	}

	// Check that all parts are non-empty
	for i, part := range parts {
		if part == "" {
			t.Errorf("Part %d is empty", i)
		}
	}
}

func TestJWTNoneProcessor_performNoneAttack(t *testing.T) {
	processor := NewJWTNoneProcessor()

	// Create a sample token
	originalToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0MjYyMn0.fake_signature"

	maliciousToken, err := processor.performNoneAttack(originalToken)
	if err != nil {
		t.Fatalf("performNoneAttack failed: %v", err)
	}

	// Check that we got a result
	if maliciousToken == "" {
		t.Error("Expected non-empty malicious token")
	}

	// Check that the result is a valid JWT format
	parts := strings.Split(maliciousToken, ".")
	if len(parts) != 3 {
		t.Errorf("Expected 3 parts in JWT, got %d", len(parts))
	}

	// Check that the third part (signature) is empty
	if parts[2] != "" {
		t.Errorf("Expected empty signature, got: %s", parts[2])
	}

	// Check that the payload is the same
	if parts[1] != "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0MjYyMn0" {
		t.Error("Expected payload to remain unchanged")
	}
}

func TestJWTNoneProcessor_performNoneAttack_WithInvalidToken(t *testing.T) {
	processor := NewJWTNoneProcessor()

	// Test with invalid token format
	_, err := processor.performNoneAttack("invalid.token")
	if err == nil {
		t.Error("Expected error for invalid token format")
	}

	// Test with token missing parts
	_, err = processor.performNoneAttack("part1.part2")
	if err == nil {
		t.Error("Expected error for token missing parts")
	}
}

func TestJWTNoneProcessor_Integration(t *testing.T) {
	processor := NewJWTNoneProcessor()

	// Test the complete flow
	result, steps, err := processor.Process("", "attack")
	if err != nil {
		t.Fatalf("Integration test failed: %v", err)
	}

	// Verify the result is a valid malicious JWT
	if !strings.Contains(result, ".") {
		t.Error("Result should contain dots for JWT format")
	}

	parts := strings.Split(result, ".")
	if len(parts) != 3 {
		t.Errorf("Expected 3 parts, got %d", len(parts))
	}

	// Verify the signature is empty
	if parts[2] != "" {
		t.Errorf("Expected empty signature, got: %s", parts[2])
	}

	// Verify we have educational content
	hasEducationalContent := false
	for _, step := range steps {
		if strings.Contains(step, "Security Implications") ||
			strings.Contains(step, "Best Practices") ||
			strings.Contains(step, "Implementation Fixes") {
			hasEducationalContent = true
			break
		}
	}

	if !hasEducationalContent {
		t.Error("Expected educational content in steps")
	}
}
