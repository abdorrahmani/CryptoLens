package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	// AES configuration
	AES struct {
		DefaultKeySize int    `yaml:"defaultKeySize"`
		KeyFile        string `yaml:"keyFile"`
	} `yaml:"aes"`

	// Base64 configuration
	Base64 struct {
		PaddingChar string `yaml:"paddingChar"`
	} `yaml:"base64"`

	// Caesar cipher configuration
	Caesar struct {
		DefaultShift int `yaml:"defaultShift"`
	} `yaml:"caesar"`

	// General settings
	General struct {
		LogLevel string `yaml:"logLevel"`
		Debug    bool   `yaml:"debug"`
	} `yaml:"general"`
}

// LoadConfig loads the configuration from the specified file
func LoadConfig(configPath string) (*Config, error) {
	// If no config path is provided, use default
	if configPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}
		configPath = filepath.Join(homeDir, ".cryptolens", "config.yaml")
	}

	// Create config directory if it doesn't exist
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create default config
		config := createDefaultConfig()
		if err := SaveConfig(configPath, config); err != nil {
			return nil, fmt.Errorf("failed to create default config: %w", err)
		}
		return config, nil
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse config
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// SaveConfig saves the configuration to the specified file
func SaveConfig(configPath string, config *Config) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// createDefaultConfig creates a default configuration
func createDefaultConfig() *Config {
	config := &Config{}

	// Set AES defaults
	config.AES.DefaultKeySize = 256
	config.AES.KeyFile = "aes_key.bin"

	// Set Base64 defaults
	config.Base64.PaddingChar = "="

	// Set Caesar defaults
	config.Caesar.DefaultShift = 3

	// Set General defaults
	config.General.LogLevel = "info"
	config.General.Debug = false

	return config
}
