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
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test loading non-existent config (should create default)
	configPath := filepath.Join(tempDir, "config.yaml")
	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify default values
	if config.AES.DefaultKeySize != 256 {
		t.Errorf("Expected AES default key size 256, got %d", config.AES.DefaultKeySize)
	}
	if config.Base64.PaddingChar != "=" {
		t.Errorf("Expected Base64 padding char '=', got %s", config.Base64.PaddingChar)
	}
	if config.Caesar.DefaultShift != 3 {
		t.Errorf("Expected Caesar default shift 3, got %d", config.Caesar.DefaultShift)
	}
	if config.RSA.KeySize != 2048 {
		t.Errorf("Expected RSA key size 2048, got %d", config.RSA.KeySize)
	}
	if config.HMAC.KeySize != 256 {
		t.Errorf("Expected HMAC key size 256, got %d", config.HMAC.KeySize)
	}
	if config.HMAC.HashAlgorithm != "sha256" {
		t.Errorf("Expected HMAC hash algorithm sha256, got %s", config.HMAC.HashAlgorithm)
	}
	if config.PBKDF.Algorithm != "argon2id" {
		t.Errorf("Expected PBKDF algorithm argon2id, got %s", config.PBKDF.Algorithm)
	}
	if config.PBKDF.Iterations != 100000 {
		t.Errorf("Expected PBKDF iterations 100000, got %d", config.PBKDF.Iterations)
	}
	if config.General.LogLevel != "info" {
		t.Errorf("Expected log level info, got %s", config.General.LogLevel)
	}
}

func TestSaveConfig(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "cryptolens-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test config
	config := createDefaultConfig()
	configPath := filepath.Join(tempDir, "config.yaml")

	// Save the config
	if err := config.Save(configPath); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Verify the file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatalf("Config file was not created")
	}

	// Load the saved config
	loadedConfig, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load saved config: %v", err)
	}

	// Verify the loaded config matches the saved config
	if loadedConfig.AES.DefaultKeySize != config.AES.DefaultKeySize {
		t.Errorf("AES key size mismatch: got %d, want %d", loadedConfig.AES.DefaultKeySize, config.AES.DefaultKeySize)
	}
	if loadedConfig.Base64.PaddingChar != config.Base64.PaddingChar {
		t.Errorf("Base64 padding char mismatch: got %s, want %s", loadedConfig.Base64.PaddingChar, config.Base64.PaddingChar)
	}
	if loadedConfig.Caesar.DefaultShift != config.Caesar.DefaultShift {
		t.Errorf("Caesar shift mismatch: got %d, want %d", loadedConfig.Caesar.DefaultShift, config.Caesar.DefaultShift)
	}
}

func TestConfigGetters(t *testing.T) {
	config := createDefaultConfig()

	// Test AES config getter
	aesConfig := config.GetAESConfig()
	if aesConfig.DefaultKeySize != config.AES.DefaultKeySize {
		t.Errorf("GetAESConfig mismatch: got %d, want %d", aesConfig.DefaultKeySize, config.AES.DefaultKeySize)
	}

	// Test Base64 config getter
	base64Config := config.GetBase64Config()
	if base64Config.PaddingChar != config.Base64.PaddingChar {
		t.Errorf("GetBase64Config mismatch: got %s, want %s", base64Config.PaddingChar, config.Base64.PaddingChar)
	}

	// Test Caesar config getter
	caesarConfig := config.GetCaesarConfig()
	if caesarConfig.DefaultShift != config.Caesar.DefaultShift {
		t.Errorf("GetCaesarConfig mismatch: got %d, want %d", caesarConfig.DefaultShift, config.Caesar.DefaultShift)
	}

	// Test RSA config getter
	rsaConfig := config.GetRSAConfig()
	if rsaConfig.KeySize != config.RSA.KeySize {
		t.Errorf("GetRSAConfig mismatch: got %d, want %d", rsaConfig.KeySize, config.RSA.KeySize)
	}

	// Test HMAC config getter
	hmacConfig := config.GetHMACConfig()
	if hmacConfig.KeySize != config.HMAC.KeySize {
		t.Errorf("GetHMACConfig mismatch: got %d, want %d", hmacConfig.KeySize, config.HMAC.KeySize)
	}

	// Test PBKDF config getter
	pbkdfConfig := config.GetPBKDFConfig()
	if pbkdfConfig.Algorithm != config.PBKDF.Algorithm {
		t.Errorf("GetPBKDFConfig mismatch: got %s, want %s", pbkdfConfig.Algorithm, config.PBKDF.Algorithm)
	}

	// Test General config getter
	generalConfig := config.GetGeneralConfig()
	if generalConfig.LogLevel != config.General.LogLevel {
		t.Errorf("GetGeneralConfig mismatch: got %s, want %s", generalConfig.LogLevel, config.General.LogLevel)
	}
}
