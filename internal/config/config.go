package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Provider defines the interface for configuration management
type Provider interface {
	GetAESConfig() AESConfig
	GetBase64Config() Base64Config
	GetCaesarConfig() CaesarConfig
	GetRSAConfig() RSAConfig
	GetHMACConfig() HMACConfig
	GetPBKDFConfig() PBKDFConfig
	GetDHConfig() DHConfig
	GetGeneralConfig() GeneralConfig
	Save(path string) error
}

// AESConfig represents AES-specific configuration
type AESConfig struct {
	DefaultKeySize int    `yaml:"defaultKeySize"`
	KeyFile        string `yaml:"keyFile"`
}

// Base64Config represents Base64-specific configuration
type Base64Config struct {
	PaddingChar string `yaml:"paddingChar"`
}

// CaesarConfig represents Caesar cipher-specific configuration
type CaesarConfig struct {
	DefaultShift int `yaml:"defaultShift"`
}

// RSAConfig represents RSA-specific configuration
type RSAConfig struct {
	KeySize        int    `yaml:"keySize"`
	PublicKeyFile  string `yaml:"publicKeyFile"`
	PrivateKeyFile string `yaml:"privateKeyFile"`
}

// HMACConfig represents HMAC-specific configuration
type HMACConfig struct {
	KeySize       int    `yaml:"keySize"`
	KeyFile       string `yaml:"keyFile"`
	HashAlgorithm string `yaml:"hashAlgorithm"`
}

// PBKDFConfig represents PBKDF-specific configuration
type PBKDFConfig struct {
	Algorithm           string   `yaml:"algorithm"`
	Iterations          int      `yaml:"iterations"`
	Memory              uint32   `yaml:"memory"`
	Threads             uint8    `yaml:"threads"`
	KeyLength           uint32   `yaml:"keyLength"`
	AvailableAlgorithms []string `yaml:"availableAlgorithms"`
}

// DHConfig represents Diffie-Hellman specific configuration
type DHConfig struct {
	KeySize          int    `yaml:"keySize"`
	Generator        int    `yaml:"generator"`
	PrimeFile        string `yaml:"primeFile"`
	PrivateKeyFile   string `yaml:"privateKeyFile"`
	PublicKeyFile    string `yaml:"publicKeyFile"`
	SharedSecretFile string `yaml:"sharedSecretFile"`
}

// GeneralConfig represents general application settings
type GeneralConfig struct {
	LogLevel string `yaml:"logLevel"`
	Debug    bool   `yaml:"debug"`
}

// Config implements Provider interface
type Config struct {
	AES     AESConfig     `yaml:"aes"`
	Base64  Base64Config  `yaml:"base64"`
	Caesar  CaesarConfig  `yaml:"caesar"`
	RSA     RSAConfig     `yaml:"rsa"`
	HMAC    HMACConfig    `yaml:"hmac"`
	PBKDF   PBKDFConfig   `yaml:"pbkdf"`
	DH      DHConfig      `yaml:"dh"`
	General GeneralConfig `yaml:"general"`
}

// GetAESConfig returns the AES configuration
func (c *Config) GetAESConfig() AESConfig {
	return c.AES
}

// GetBase64Config returns the Base64 configuration
func (c *Config) GetBase64Config() Base64Config {
	return c.Base64
}

// GetCaesarConfig returns the Caesar cipher configuration
func (c *Config) GetCaesarConfig() CaesarConfig {
	return c.Caesar
}

// GetRSAConfig returns the RSA configuration
func (c *Config) GetRSAConfig() RSAConfig {
	return c.RSA
}

// GetHMACConfig returns the HMAC configuration
func (c *Config) GetHMACConfig() HMACConfig {
	return c.HMAC
}

// GetPBKDFConfig returns the PBKDF configuration
func (c *Config) GetPBKDFConfig() PBKDFConfig {
	return c.PBKDF
}

// GetDHConfig returns the Diffie-Hellman configuration
func (c *Config) GetDHConfig() DHConfig {
	return c.DH
}

// GetGeneralConfig returns the general configuration
func (c *Config) GetGeneralConfig() GeneralConfig {
	return c.General
}

// Save saves the configuration to the specified file
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
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
	config.HMAC.KeyFile = filepath.Join(keysDir, "hmac_key.bin")

	// Ensure HMAC config has default values if not set
	if config.HMAC.KeySize == 0 {
		config.HMAC.KeySize = 256
	}
	if config.HMAC.HashAlgorithm == "" {
		config.HMAC.HashAlgorithm = "sha256"
	}

	// Set DH defaults
	config.DH.KeySize = 2048
	config.DH.Generator = 2
	config.DH.PrimeFile = filepath.Join(keysDir, "dh_prime.bin")
	config.DH.PrivateKeyFile = filepath.Join(keysDir, "dh_private.bin")
	config.DH.PublicKeyFile = filepath.Join(keysDir, "dh_public.bin")
	config.DH.SharedSecretFile = filepath.Join(keysDir, "dh_shared.bin")

	return &config, nil
}

// SaveConfig saves the configuration to the specified file
func SaveConfig(configPath string, config *Config) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
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

	// Set HMAC defaults
	config.HMAC.KeySize = 256
	config.HMAC.KeyFile = filepath.Join(keysDir, "hmac_key.bin")
	config.HMAC.HashAlgorithm = "sha256"

	// Set PBKDF defaults
	config.PBKDF.Algorithm = "argon2id"
	config.PBKDF.Iterations = 100000
	config.PBKDF.Memory = 65536
	config.PBKDF.Threads = 4
	config.PBKDF.KeyLength = 32
	config.PBKDF.AvailableAlgorithms = []string{"pbkdf2", "argon2id", "scrypt"}

	// Set DH defaults
	config.DH.KeySize = 2048
	config.DH.Generator = 2
	config.DH.PrimeFile = filepath.Join(keysDir, "dh_prime.bin")
	config.DH.PrivateKeyFile = filepath.Join(keysDir, "dh_private.bin")
	config.DH.PublicKeyFile = filepath.Join(keysDir, "dh_public.bin")
	config.DH.SharedSecretFile = filepath.Join(keysDir, "dh_shared.bin")

	// Set General defaults
	config.General.LogLevel = "info"
	config.General.Debug = false

	return config
}
