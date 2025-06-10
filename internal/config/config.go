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
	GetChaCha20Poly1305Config() ChaCha20Poly1305Config
	GetBase64Config() Base64Config
	GetCaesarConfig() CaesarConfig
	GetRSAConfig() RSAConfig
	GetHMACConfig() HMACConfig
	GetPBKDFConfig() PBKDFConfig
	GetDHConfig() DHConfig
	GetX25519Config() X25519Config
	GetJWTConfig() JWTConfig
	GetGeneralConfig() GeneralConfig
	Save(path string) error
}

// AESConfig represents AES-specific configuration
type AESConfig struct {
	DefaultKeySize int    `yaml:"defaultKeySize"`
	KeyFile        string `yaml:"keyFile"`
}

// ChaCha20Poly1305Config represents ChaCha20-Poly1305 specific configuration
type ChaCha20Poly1305Config struct {
	KeySize   int    `yaml:"keySize"`
	KeyFile   string `yaml:"keyFile"`
	NonceSize int    `yaml:"nonceSize"`
	TagSize   int    `yaml:"tagSize"`
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

// X25519Config represents X25519-specific configuration
type X25519Config struct {
	PrivateKeyFile   string `yaml:"privateKeyFile"`
	PublicKeyFile    string `yaml:"publicKeyFile"`
	SharedSecretFile string `yaml:"sharedSecretFile"`
}

// JWTConfig represents JWT-specific configuration
type JWTConfig struct {
	Algorithm             string   `yaml:"algorithm"`
	KeyFile               string   `yaml:"keyFile"`
	RSAPrivateKeyFile     string   `yaml:"rsaPrivateKeyFile"`
	RSAPublicKeyFile      string   `yaml:"rsaPublicKeyFile"`
	Ed25519PrivateKeyFile string   `yaml:"ed25519PrivateKeyFile"`
	Ed25519PublicKeyFile  string   `yaml:"ed25519PublicKeyFile"`
	AvailableAlgorithms   []string `yaml:"availableAlgorithms"`
}

// GeneralConfig represents general application settings
type GeneralConfig struct {
	LogLevel string `yaml:"logLevel"`
	Debug    bool   `yaml:"debug"`
}

// Config implements Provider interface
type Config struct {
	AES              AESConfig              `yaml:"aes"`
	ChaCha20Poly1305 ChaCha20Poly1305Config `yaml:"chacha20poly1305"`
	Base64           Base64Config           `yaml:"base64"`
	Caesar           CaesarConfig           `yaml:"caesar"`
	RSA              RSAConfig              `yaml:"rsa"`
	HMAC             HMACConfig             `yaml:"hmac"`
	PBKDF            PBKDFConfig            `yaml:"pbkdf"`
	DH               DHConfig               `yaml:"dh"`
	X25519           X25519Config           `yaml:"x25519"`
	JWT              JWTConfig              `yaml:"jwt"`
	General          GeneralConfig          `yaml:"general"`
}

// GetAESConfig returns the AES configuration
func (c *Config) GetAESConfig() AESConfig {
	return c.AES
}

// GetChaCha20Poly1305Config returns the ChaCha20-Poly1305 configuration
func (c *Config) GetChaCha20Poly1305Config() ChaCha20Poly1305Config {
	return c.ChaCha20Poly1305
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

// GetX25519Config returns the X25519 configuration
func (c *Config) GetX25519Config() X25519Config {
	return c.X25519
}

// GetJWTConfig returns the JWT configuration
func (c *Config) GetJWTConfig() JWTConfig {
	return c.JWT
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

	// Set X25519 defaults
	config.X25519.PrivateKeyFile = filepath.Join(keysDir, "x25519_private.bin")
	config.X25519.PublicKeyFile = filepath.Join(keysDir, "x25519_public.bin")
	config.X25519.SharedSecretFile = filepath.Join(keysDir, "x25519_shared.bin")

	// Set JWT defaults
	config.JWT.Algorithm = "HS256"
	config.JWT.KeyFile = filepath.Join(keysDir, "jwt_key.bin")
	config.JWT.RSAPrivateKeyFile = filepath.Join(keysDir, "jwt_rsa_private.pem")
	config.JWT.RSAPublicKeyFile = filepath.Join(keysDir, "jwt_rsa_public.pem")
	config.JWT.Ed25519PrivateKeyFile = filepath.Join(keysDir, "jwt_ed25519_private.bin")
	config.JWT.Ed25519PublicKeyFile = filepath.Join(keysDir, "jwt_ed25519_public.bin")
	config.JWT.AvailableAlgorithms = []string{"HS256", "RS256", "EdDSA"}

	// Set ChaCha20-Poly1305 defaults
	config.ChaCha20Poly1305.KeySize = 256
	config.ChaCha20Poly1305.KeyFile = filepath.Join(keysDir, "chacha20poly1305_key.bin")
	config.ChaCha20Poly1305.NonceSize = 12
	config.ChaCha20Poly1305.TagSize = 16

	// Set Caesar defaults
	config.Caesar.DefaultShift = 3

	// Set PBKDF defaults
	config.PBKDF.Algorithm = "argon2id"
	config.PBKDF.Iterations = 100000
	config.PBKDF.Memory = 65536
	config.PBKDF.Threads = 4
	config.PBKDF.KeyLength = 32
	config.PBKDF.AvailableAlgorithms = []string{"pbkdf2", "argon2id", "scrypt"}

	// Set General defaults
	config.General.LogLevel = "info"
	config.General.Debug = false

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

	// Set ChaCha20-Poly1305 defaults
	config.ChaCha20Poly1305.KeySize = 256
	config.ChaCha20Poly1305.KeyFile = filepath.Join(keysDir, "chacha20poly1305_key.bin")
	config.ChaCha20Poly1305.NonceSize = 12
	config.ChaCha20Poly1305.TagSize = 16

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

	// Set X25519 defaults
	config.X25519.PrivateKeyFile = filepath.Join(keysDir, "x25519_private.bin")
	config.X25519.PublicKeyFile = filepath.Join(keysDir, "x25519_public.bin")
	config.X25519.SharedSecretFile = filepath.Join(keysDir, "x25519_shared.bin")

	// Set JWT defaults
	config.JWT.Algorithm = "HS256"
	config.JWT.KeyFile = filepath.Join(keysDir, "jwt_key.bin")
	config.JWT.RSAPrivateKeyFile = filepath.Join(keysDir, "jwt_rsa_private.pem")
	config.JWT.RSAPublicKeyFile = filepath.Join(keysDir, "jwt_rsa_public.pem")
	config.JWT.Ed25519PrivateKeyFile = filepath.Join(keysDir, "jwt_ed25519_private.bin")
	config.JWT.Ed25519PublicKeyFile = filepath.Join(keysDir, "jwt_ed25519_public.bin")
	config.JWT.AvailableAlgorithms = []string{"HS256", "RS256", "EdDSA"}

	// Set General defaults
	config.General.LogLevel = "info"
	config.General.Debug = false

	return config
}
