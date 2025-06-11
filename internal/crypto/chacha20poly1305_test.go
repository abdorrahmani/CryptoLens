package crypto

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// mockStdin creates a temporary stdin with predefined inputs
func mockStdin(inputs ...string) func() {
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r

	// Write all inputs with newlines
	for _, input := range inputs {
		if _, err := w.Write([]byte(input + "\n")); err != nil {
			// If we can't write to the pipe, we should restore stdin and panic
			os.Stdin = oldStdin
			panic(fmt.Sprintf("failed to write to mock stdin: %v", err))
		}
	}
	w.Close()

	return func() {
		os.Stdin = oldStdin
	}
}

func TestChaCha20Poly1305Processor(t *testing.T) {
	// Initialize processor
	processor := NewChaCha20Poly1305Processor()
	err := processor.Configure(map[string]interface{}{})
	require.NoError(t, err)

	t.Run("Basic Encryption and Decryption", func(t *testing.T) {
		// Test data
		plaintext := "Hello, World!"

		// Encrypt
		ciphertext, steps, err := processor.Process(plaintext, OperationEncrypt)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)
		require.NotEmpty(t, steps)

		// Decrypt
		decrypted, steps, err := processor.Process(ciphertext, OperationDecrypt)
		require.NoError(t, err)
		require.Equal(t, plaintext, decrypted)
		require.NotEmpty(t, steps)
	})

	t.Run("Empty Message", func(t *testing.T) {
		// Test empty string
		plaintext := ""

		// Encrypt
		ciphertext, steps, err := processor.Process(plaintext, OperationEncrypt)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)
		require.NotEmpty(t, steps)

		// Decrypt
		decrypted, steps, err := processor.Process(ciphertext, OperationDecrypt)
		require.NoError(t, err)
		require.Equal(t, plaintext, decrypted)
		require.NotEmpty(t, steps)
	})

	t.Run("Long Message", func(t *testing.T) {
		// Test long message
		plaintext := "This is a very long message that tests the encryption of larger data blocks. " +
			"It includes multiple sentences and various characters to ensure proper handling of " +
			"different data sizes and content types."

		// Encrypt
		ciphertext, steps, err := processor.Process(plaintext, OperationEncrypt)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)
		require.NotEmpty(t, steps)

		// Decrypt
		decrypted, steps, err := processor.Process(ciphertext, OperationDecrypt)
		require.NoError(t, err)
		require.Equal(t, plaintext, decrypted)
		require.NotEmpty(t, steps)
	})

	t.Run("Special Characters", func(t *testing.T) {
		// Test special characters
		plaintext := "!@#$%^&*()_+{}|:<>?~`-=[]\\;',./"

		// Encrypt
		ciphertext, steps, err := processor.Process(plaintext, OperationEncrypt)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)
		require.NotEmpty(t, steps)

		// Decrypt
		decrypted, steps, err := processor.Process(ciphertext, OperationDecrypt)
		require.NoError(t, err)
		require.Equal(t, plaintext, decrypted)
		require.NotEmpty(t, steps)
	})

	t.Run("Unicode Characters", func(t *testing.T) {
		// Test Unicode characters
		plaintext := "Hello, 世界! 🌍"

		// Encrypt
		ciphertext, steps, err := processor.Process(plaintext, OperationEncrypt)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)
		require.NotEmpty(t, steps)

		// Decrypt
		decrypted, steps, err := processor.Process(ciphertext, OperationDecrypt)
		require.NoError(t, err)
		require.Equal(t, plaintext, decrypted)
		require.NotEmpty(t, steps)
	})

	t.Run("Invalid Base64 Input", func(t *testing.T) {
		// Test invalid base64
		invalidInput := "not-base64-encoded"

		// Attempt decryption
		_, steps, err := processor.Process(invalidInput, OperationDecrypt)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode input")
		require.NotEmpty(t, steps)
	})

	t.Run("Tampered Ciphertext", func(t *testing.T) {
		// Mock stdin for interactive prompts
		restore := mockStdin(
			"1", // Use existing key
			"1", // Generate random nonce
			"",  // No AAD
			"2", // Flip a bit in ciphertext
			"1", // Use existing key for decryption
			"",  // No AAD for decryption
		)
		defer restore()

		// Encrypt a message
		plaintext := "Test message"
		ciphertext, _, err := processor.Process(plaintext, OperationEncrypt)
		require.NoError(t, err)

		// Decode the ciphertext
		decoded, err := base64.StdEncoding.DecodeString(ciphertext)
		require.NoError(t, err)

		// Tamper with the ciphertext (flip a bit)
		decoded[12] ^= 1 // Flip a bit in the ciphertext part

		// Re-encode
		tamperedCiphertext := base64.StdEncoding.EncodeToString(decoded)

		// Attempt decryption
		_, steps, err := processor.Process(tamperedCiphertext, OperationDecrypt)
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")
		require.NotEmpty(t, steps)
	})

	t.Run("Tampered Tag", func(t *testing.T) {
		// Mock stdin for interactive prompts
		restore := mockStdin(
			"1", // Use existing key
			"1", // Generate random nonce
			"",  // No AAD
			"3", // Corrupt the tag
			"1", // Use existing key for decryption
			"",  // No AAD for decryption
		)
		defer restore()

		// Encrypt a message
		plaintext := "Test message"
		ciphertext, _, err := processor.Process(plaintext, OperationEncrypt)
		require.NoError(t, err)

		// Decode the ciphertext
		decoded, err := base64.StdEncoding.DecodeString(ciphertext)
		require.NoError(t, err)

		// Tamper with the tag (flip all bits in first byte)
		tagStart := len(decoded) - 16
		decoded[tagStart] ^= 0xFF

		// Re-encode
		tamperedCiphertext := base64.StdEncoding.EncodeToString(decoded)

		// Attempt decryption
		_, steps, err := processor.Process(tamperedCiphertext, OperationDecrypt)
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")
		require.NotEmpty(t, steps)
	})

	t.Run("Invalid Key Size", func(t *testing.T) {
		// Test invalid key size
		err := processor.Configure(map[string]interface{}{
			"keySize": 128, // Invalid size
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid key size")
	})

	t.Run("Invalid Nonce Size", func(t *testing.T) {
		// Test invalid nonce size
		err := processor.Configure(map[string]interface{}{
			"nonceSize": 8, // Invalid size
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid nonce size")
	})

	t.Run("Invalid Tag Size", func(t *testing.T) {
		// Test invalid tag size
		err := processor.Configure(map[string]interface{}{
			"tagSize": 8, // Invalid size
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid tag size")
	})

	t.Run("With AAD", func(t *testing.T) {
		// Test with Additional Authenticated Data
		plaintext := "Message with AAD"
		aad := "Additional Authenticated Data"

		// Configure processor with AAD
		err := processor.Configure(map[string]interface{}{
			"aad": aad,
		})
		require.NoError(t, err)

		// Encrypt
		ciphertext, steps, err := processor.Process(plaintext, OperationEncrypt)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)
		require.NotEmpty(t, steps)

		// Decrypt with same AAD
		decrypted, steps, err := processor.Process(ciphertext, OperationDecrypt)
		require.NoError(t, err)
		require.Equal(t, plaintext, decrypted)
		require.NotEmpty(t, steps)
	})

	t.Run("Multiple Operations", func(t *testing.T) {
		// Test multiple encryption/decryption operations
		messages := []string{
			"First message",
			"Second message",
			"Third message",
		}

		for _, msg := range messages {
			// Encrypt
			ciphertext, steps, err := processor.Process(msg, OperationEncrypt)
			require.NoError(t, err)
			require.NotEmpty(t, ciphertext)
			require.NotEmpty(t, steps)

			// Decrypt
			decrypted, steps, err := processor.Process(ciphertext, OperationDecrypt)
			require.NoError(t, err)
			require.Equal(t, msg, decrypted)
			require.NotEmpty(t, steps)
		}
	})
}
