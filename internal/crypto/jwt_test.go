package crypto

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJWTProcessor(t *testing.T) {
	processor := NewJWTProcessor()
	assert.NotNil(t, processor)
	assert.Equal(t, "HS256", processor.algorithm)
	assert.Equal(t, "my-secret-key", processor.secretKey)
}

func TestJWTProcessor_Configure(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
	}{
		{
			name: "valid HS256 config",
			config: map[string]interface{}{
				"algorithm": "HS256",
				"secretKey": "test-secret",
			},
			wantErr: false,
		},
		{
			name: "valid RS256 config",
			config: map[string]interface{}{
				"algorithm": "RS256",
			},
			wantErr: false,
		},
		{
			name: "valid EdDSA config",
			config: map[string]interface{}{
				"algorithm": "EdDSA",
			},
			wantErr: false,
		},
		{
			name: "invalid algorithm",
			config: map[string]interface{}{
				"algorithm": "INVALID",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewJWTProcessor()
			err := processor.Configure(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestJWTProcessor_HS256(t *testing.T) {
	processor := NewJWTProcessor()
	err := processor.Configure(map[string]interface{}{
		"algorithm": "HS256",
		"secretKey": "test-secret-key",
	})
	require.NoError(t, err)

	claims := map[string]interface{}{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	// Test encoding
	token, steps, err := processor.Process(string(claimsJSON), "encrypt")
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.NotEmpty(t, steps)

	// Test decoding
	decoded, steps, err := processor.Process(token, "decrypt")
	require.NoError(t, err)
	assert.NotEmpty(t, decoded)
	assert.NotEmpty(t, steps)

	// Verify claims
	var decodedClaims map[string]interface{}
	err = json.Unmarshal([]byte(decoded), &decodedClaims)
	require.NoError(t, err)
	assert.Equal(t, claims["sub"], decodedClaims["sub"])
	assert.Equal(t, claims["name"], decodedClaims["name"])
}

func TestJWTProcessor_RS256(t *testing.T) {
	processor := NewJWTProcessor()
	err := processor.Configure(map[string]interface{}{
		"algorithm": "RS256",
	})
	require.NoError(t, err)

	claims := map[string]interface{}{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	// Test encoding
	token, steps, err := processor.Process(string(claimsJSON), "encrypt")
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.NotEmpty(t, steps)

	// Test decoding
	decoded, steps, err := processor.Process(token, "decrypt")
	require.NoError(t, err)
	assert.NotEmpty(t, decoded)
	assert.NotEmpty(t, steps)

	// Verify claims
	var decodedClaims map[string]interface{}
	err = json.Unmarshal([]byte(decoded), &decodedClaims)
	require.NoError(t, err)
	assert.Equal(t, claims["sub"], decodedClaims["sub"])
	assert.Equal(t, claims["name"], decodedClaims["name"])

	// Clean up generated files
	os.Remove("jwt_rsa_private.pem")
	os.Remove("jwt_rsa_public.pem")
}

func TestJWTProcessor_EdDSA(t *testing.T) {
	processor := NewJWTProcessor()
	err := processor.Configure(map[string]interface{}{
		"algorithm": "EdDSA",
	})
	require.NoError(t, err)

	claims := map[string]interface{}{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	// Test encoding
	token, steps, err := processor.Process(string(claimsJSON), "encrypt")
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.NotEmpty(t, steps)

	// Test decoding
	decoded, steps, err := processor.Process(token, "decrypt")
	require.NoError(t, err)
	assert.NotEmpty(t, decoded)
	assert.NotEmpty(t, steps)

	// Verify claims
	var decodedClaims map[string]interface{}
	err = json.Unmarshal([]byte(decoded), &decodedClaims)
	require.NoError(t, err)
	assert.Equal(t, claims["sub"], decodedClaims["sub"])
	assert.Equal(t, claims["name"], decodedClaims["name"])

	// Clean up generated files
	os.Remove("jwt_ed25519_private.pem")
	os.Remove("jwt_ed25519_public.pem")
}

func TestJWTProcessor_InvalidInput(t *testing.T) {
	processor := NewJWTProcessor()
	err := processor.Configure(map[string]interface{}{
		"algorithm": "HS256",
		"secretKey": "test-secret-key",
	})
	require.NoError(t, err)

	// Test invalid JSON
	_, _, err = processor.Process("invalid-json", "encrypt")
	assert.Error(t, err)

	// Test invalid token
	_, _, err = processor.Process("invalid.token.format", "decrypt")
	assert.Error(t, err)

	// Test invalid operation
	_, _, err = processor.Process("{}", "invalid-operation")
	assert.Error(t, err)
}

func TestJWTProcessor_ExpiredToken(t *testing.T) {
	processor := NewJWTProcessor()
	err := processor.Configure(map[string]interface{}{
		"algorithm": "HS256",
		"secretKey": "test-secret-key",
	})
	require.NoError(t, err)

	// Create a token that's already expired
	claims := map[string]interface{}{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Add(-2 * time.Hour).Unix(),
		"exp":  time.Now().Add(-1 * time.Hour).Unix(),
	}
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	// Test encoding
	token, _, err := processor.Process(string(claimsJSON), "encrypt")
	require.NoError(t, err)

	// Test decoding expired token
	_, steps, err := processor.Process(token, "decrypt")
	require.Error(t, err, "Expected error for expired token")
	assert.Contains(t, err.Error(), "token is expired")
	assert.Contains(t, steps, "❌ Signature Verification Failed:")
}

func TestJWTProcessor_KeyManagement(t *testing.T) {
	// Test HS256 key management
	t.Run("HS256 Key Management", func(t *testing.T) {
		processor := NewJWTProcessor()
		err := processor.Configure(map[string]interface{}{
			"algorithm": "HS256",
			"keyFile":   "test_jwt_key.bin",
		})
		require.NoError(t, err)

		claims := map[string]interface{}{"test": "value"}
		claimsJSON, _ := json.Marshal(claims)

		// First use should generate key
		_, _, err = processor.Process(string(claimsJSON), "encrypt")
		require.NoError(t, err)

		// Second use should load existing key
		_, _, err = processor.Process(string(claimsJSON), "encrypt")
		require.NoError(t, err)

		os.Remove("test_jwt_key.bin")
	})

	// Test RS256 key management
	t.Run("RS256 Key Management", func(t *testing.T) {
		processor := NewJWTProcessor()
		err := processor.Configure(map[string]interface{}{
			"algorithm": "RS256",
		})
		require.NoError(t, err)

		claims := map[string]interface{}{"test": "value"}
		claimsJSON, _ := json.Marshal(claims)

		// First use should generate key pair
		_, _, err = processor.Process(string(claimsJSON), "encrypt")
		require.NoError(t, err)

		// Second use should load existing keys
		_, _, err = processor.Process(string(claimsJSON), "encrypt")
		require.NoError(t, err)

		os.Remove("jwt_rsa_private.pem")
		os.Remove("jwt_rsa_public.pem")
	})

	// Test EdDSA key management
	t.Run("EdDSA Key Management", func(t *testing.T) {
		processor := NewJWTProcessor()
		err := processor.Configure(map[string]interface{}{
			"algorithm": "EdDSA",
		})
		require.NoError(t, err)

		claims := map[string]interface{}{"test": "value"}
		claimsJSON, _ := json.Marshal(claims)

		// First use should generate key pair
		_, _, err = processor.Process(string(claimsJSON), "encrypt")
		require.NoError(t, err)

		// Second use should load existing keys
		_, _, err = processor.Process(string(claimsJSON), "encrypt")
		require.NoError(t, err)

		os.Remove("jwt_ed25519_private.pem")
		os.Remove("jwt_ed25519_public.pem")
	})
}
