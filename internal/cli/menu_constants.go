package cli

import "github.com/abdorrahmani/cryptolens/internal/crypto"

const (
	// AppVersion is the current version of the application
	AppVersion = "v1.3.0"

	// Menu options
	OptionBase64 = iota + 1
	OptionCaesar
	OptionAES
	OptionSHA256
	OptionRSA
	OptionHMAC
	OptionPBKDF
	OptionExit
)

// MenuOption represents a menu option with its configuration
type MenuOption struct {
	ID            int
	Name          string
	Description   string
	SkipOperation bool // Whether to skip operation selection (encrypt/decrypt)
}

// GetMenuOptions returns all available menu options
func GetMenuOptions() []MenuOption {
	return []MenuOption{
		{ID: OptionBase64, Name: "Base64 Encoding", Description: "Simple encoding/decoding"},
		{ID: OptionCaesar, Name: "Caesar Cipher", Description: "Classical substitution cipher"},
		{ID: OptionAES, Name: "AES Encryption", Description: "Advanced Encryption Standard"},
		{ID: OptionSHA256, Name: "SHA-256 Hashing", Description: "Cryptographic hash function"},
		{ID: OptionRSA, Name: "RSA Encryption", Description: "Public-key cryptography"},
		{ID: OptionHMAC, Name: "HMAC Authentication", Description: "Hash-based message authentication"},
		{ID: OptionPBKDF, Name: "Password-Based Key Derivation", Description: "Key derivation functions"},
		{ID: OptionExit, Name: "Exit", Description: "Exit the program"},
	}
}

// GetSkipOperationOptions returns a map of options that should skip operation selection
func GetSkipOperationOptions() map[int]bool {
	return map[int]bool{
		OptionSHA256: true,
		OptionHMAC:   true,
		OptionPBKDF:  true,
	}
}

// GetDefaultOperation returns the default operation for a given option
func GetDefaultOperation(_ int) string {
	return crypto.OperationEncrypt
}
