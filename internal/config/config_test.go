package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "cryptolens-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test loading default config
	config, err := LoadConfig("")
	if err != nil {
		t.Fatalf("Failed to load default config: %v", err)
	}

	// Verify default values
	if config.AES.DefaultKeySize != 256 {
		t.Errorf("Expected default AES key size 256, got %d", config.AES.DefaultKeySize)
	}
	if config.HMAC.KeySize != 256 {
		t.Errorf("Expected default HMAC key size 256, got %d", config.HMAC.KeySize)
	}
	if config.HMAC.HashAlgorithm != "sha256" {
		t.Errorf("Expected default HMAC algorithm sha256, got %s", config.HMAC.HashAlgorithm)
	}

	// Test loading with invalid path - should return default config
	invalidPath := filepath.Join(tempDir, "nonexistent", "config.yaml")
	config, err = LoadConfig(invalidPath)
	if err != nil {
		t.Errorf("Expected no error when loading from invalid path, got %v", err)
	}
	if config == nil {
		t.Error("Expected default config when loading from invalid path, got nil")
	}

	// Test loading with invalid YAML
	invalidConfigPath := filepath.Join(tempDir, "invalid.yaml")
	if err := os.WriteFile(invalidConfigPath, []byte("invalid: yaml: content"), 0600); err != nil {
		t.Fatalf("Failed to write invalid config: %v", err)
	}
	_, err = LoadConfig(invalidConfigPath)
	if err == nil {
		t.Error("Expected error when loading invalid YAML, got nil")
	}
}

func TestSaveConfig(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "cryptolens-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.yaml")

	// Create a test config
	config := createDefaultConfig()

	// Save the config
	err = SaveConfig(configPath, config)
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Load the saved config
	loadedConfig, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load saved config: %v", err)
	}

	// Verify the loaded config matches the original
	if loadedConfig.AES.DefaultKeySize != config.AES.DefaultKeySize {
		t.Errorf("Loaded AES key size %d does not match saved value %d",
			loadedConfig.AES.DefaultKeySize, config.AES.DefaultKeySize)
	}
	if loadedConfig.HMAC.KeySize != config.HMAC.KeySize {
		t.Errorf("Loaded HMAC key size %d does not match saved value %d",
			loadedConfig.HMAC.KeySize, config.HMAC.KeySize)
	}
	if loadedConfig.HMAC.HashAlgorithm != config.HMAC.HashAlgorithm {
		t.Errorf("Loaded HMAC algorithm %s does not match saved value %s",
			loadedConfig.HMAC.HashAlgorithm, config.HMAC.HashAlgorithm)
	}

	// Test saving to invalid path
	err = SaveConfig(filepath.Join(tempDir, "nonexistent", "config.yaml"), config)
	if err == nil {
		t.Error("Expected error when saving to invalid path, got nil")
	}
}

func TestConfigProvider(t *testing.T) {
	config := createDefaultConfig()

	// Test GetAESConfig
	aesConfig := config.GetAESConfig()
	if aesConfig.DefaultKeySize != 256 {
		t.Errorf("Expected AES key size 256, got %d", aesConfig.DefaultKeySize)
	}

	// Test GetBase64Config
	base64Config := config.GetBase64Config()
	if base64Config.PaddingChar != "=" {
		t.Errorf("Expected Base64 padding char =, got %s", base64Config.PaddingChar)
	}

	// Test GetCaesarConfig
	caesarConfig := config.GetCaesarConfig()
	if caesarConfig.DefaultShift != 3 {
		t.Errorf("Expected Caesar shift 3, got %d", caesarConfig.DefaultShift)
	}

	// Test GetRSAConfig
	rsaConfig := config.GetRSAConfig()
	if rsaConfig.KeySize != 2048 {
		t.Errorf("Expected RSA key size 2048, got %d", rsaConfig.KeySize)
	}

	// Test GetHMACConfig
	hmacConfig := config.GetHMACConfig()
	if hmacConfig.KeySize != 256 {
		t.Errorf("Expected HMAC key size 256, got %d", hmacConfig.KeySize)
	}
	if hmacConfig.HashAlgorithm != "sha256" {
		t.Errorf("Expected HMAC algorithm sha256, got %s", hmacConfig.HashAlgorithm)
	}

	// Test GetPBKDFConfig
	pbkdfConfig := config.GetPBKDFConfig()
	if pbkdfConfig.Iterations != 100000 {
		t.Errorf("Expected PBKDF iterations 100000, got %d", pbkdfConfig.Iterations)
	}
	if pbkdfConfig.Memory != 65536 {
		t.Errorf("Expected PBKDF memory 65536, got %d", pbkdfConfig.Memory)
	}
	if pbkdfConfig.Threads != 4 {
		t.Errorf("Expected PBKDF threads 4, got %d", pbkdfConfig.Threads)
	}
	if pbkdfConfig.KeyLength != 32 {
		t.Errorf("Expected PBKDF key length 32, got %d", pbkdfConfig.KeyLength)
	}
	if len(pbkdfConfig.AvailableAlgorithms) != 3 {
		t.Errorf("Expected 3 PBKDF algorithms, got %d", len(pbkdfConfig.AvailableAlgorithms))
	}

	// Test GetDHConfig
	dhConfig := config.GetDHConfig()
	if dhConfig.KeySize != 2048 {
		t.Errorf("Expected DH key size 2048, got %d", dhConfig.KeySize)
	}
	if dhConfig.Generator != 2 {
		t.Errorf("Expected DH generator 2, got %d", dhConfig.Generator)
	}

	// Test GetX25519Config
	x25519Config := config.GetX25519Config()
	if x25519Config.PrivateKeyFile == "" {
		t.Error("Expected X25519 private key file path, got empty string")
	}
	if x25519Config.PublicKeyFile == "" {
		t.Error("Expected X25519 public key file path, got empty string")
	}

	// Test GetJWTConfig
	jwtConfig := config.GetJWTConfig()
	if jwtConfig.Algorithm != "HS256" {
		t.Errorf("Expected JWT algorithm HS256, got %s", jwtConfig.Algorithm)
	}
	if len(jwtConfig.AvailableAlgorithms) != 3 {
		t.Errorf("Expected 3 JWT algorithms, got %d", len(jwtConfig.AvailableAlgorithms))
	}

	// Test GetGeneralConfig
	generalConfig := config.GetGeneralConfig()
	if generalConfig.LogLevel != "info" {
		t.Errorf("Expected log level info, got %s", generalConfig.LogLevel)
	}
	if generalConfig.Debug {
		t.Error("Expected debug mode to be false")
	}
}

func TestConfigSave(t *testing.T) {
	config := createDefaultConfig()

	// Test saving to a file
	tempDir, err := os.MkdirTemp("", "cryptolens-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.yaml")
	err = config.Save(configPath)
	if err != nil {
		t.Errorf("Failed to save config: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Config file was not created")
	}
}

func TestCreateDefaultConfig(t *testing.T) {
	config := createDefaultConfig()

	// Verify all default values are set correctly
	if config.AES.DefaultKeySize != 256 {
		t.Errorf("Expected AES key size 256, got %d", config.AES.DefaultKeySize)
	}
	if config.Base64.PaddingChar != "=" {
		t.Errorf("Expected Base64 padding char =, got %s", config.Base64.PaddingChar)
	}
	if config.Caesar.DefaultShift != 3 {
		t.Errorf("Expected Caesar shift 3, got %d", config.Caesar.DefaultShift)
	}
	if config.RSA.KeySize != 2048 {
		t.Errorf("Expected RSA key size 2048, got %d", config.RSA.KeySize)
	}
	if config.HMAC.KeySize != 256 {
		t.Errorf("Expected HMAC key size 256, got %d", config.HMAC.KeySize)
	}
	if config.HMAC.HashAlgorithm != "sha256" {
		t.Errorf("Expected HMAC algorithm sha256, got %s", config.HMAC.HashAlgorithm)
	}
	if config.PBKDF.Algorithm != "argon2id" {
		t.Errorf("Expected PBKDF algorithm argon2id, got %s", config.PBKDF.Algorithm)
	}
	if config.PBKDF.Iterations != 100000 {
		t.Errorf("Expected PBKDF iterations 100000, got %d", config.PBKDF.Iterations)
	}
	if config.DH.KeySize != 2048 {
		t.Errorf("Expected DH key size 2048, got %d", config.DH.KeySize)
	}
	if config.DH.Generator != 2 {
		t.Errorf("Expected DH generator 2, got %d", config.DH.Generator)
	}
	if config.JWT.Algorithm != "HS256" {
		t.Errorf("Expected JWT algorithm HS256, got %s", config.JWT.Algorithm)
	}
	if config.General.LogLevel != "info" {
		t.Errorf("Expected log level info, got %s", config.General.LogLevel)
	}
	if config.General.Debug {
		t.Error("Expected debug mode to be false")
	}
}
