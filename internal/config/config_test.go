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
}

func TestConfigProvider(t *testing.T) {
	config := createDefaultConfig()

	// Test GetAESConfig
	aesConfig := config.GetAESConfig()
	if aesConfig.DefaultKeySize != 256 {
		t.Errorf("Expected AES key size 256, got %d", aesConfig.DefaultKeySize)
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
}
