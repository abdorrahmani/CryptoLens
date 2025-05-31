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

	// RSA configuration
	RSA struct {
		KeySize        int    `yaml:"keySize"`
		PublicKeyFile  string `yaml:"publicKeyFile"`
		PrivateKeyFile string `yaml:"privateKeyFile"`
	} `yaml:"rsa"`

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

	// Get the project root directory (where the executable is)
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}
	projectRoot := filepath.Dir(execPath)

	// Create keys directory in project root
	keysDir := filepath.Join(projectRoot, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Update key paths to use project root
	config.RSA.PublicKeyFile = filepath.Join(keysDir, "rsa_public.pem")
	config.RSA.PrivateKeyFile = filepath.Join(keysDir, "rsa_private.pem")
	config.AES.KeyFile = filepath.Join(keysDir, "aes_key.bin")

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

	// Get the project root directory (where the executable is)
	execPath, err := os.Executable()
	if err != nil {
		// Fallback to current directory if executable path can't be determined
		execPath = "."
	}
	projectRoot := filepath.Dir(execPath)
	keysDir := filepath.Join(projectRoot, "keys")

	// Set AES defaults
	config.AES.DefaultKeySize = 256
	config.AES.KeyFile = filepath.Join(keysDir, "aes_key.bin")

	// Set Base64 defaults
	config.Base64.PaddingChar = "="

	// Set Caesar defaults
	config.Caesar.DefaultShift = 3

	// Set RSA defaults
	config.RSA.KeySize = 2048
	config.RSA.PublicKeyFile = filepath.Join(keysDir, "rsa_public.pem")
	config.RSA.PrivateKeyFile = filepath.Join(keysDir, "rsa_private.pem")

	// Set General defaults
	config.General.LogLevel = "info"
	config.General.Debug = false

	return config
}
