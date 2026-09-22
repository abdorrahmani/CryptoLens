package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// pkcs1v15Overhead is the number of bytes PKCS#1 v1.5 padding adds, so the
// largest message is (modulus bytes − 11).
const pkcs1v15Overhead = 11

// RSAProcessor implements RSA encryption/decryption
type RSAProcessor struct {
	BaseConfigurableProcessor
	keySize    int
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// NewRSAProcessor creates a new RSA processor
func NewRSAProcessor() *RSAProcessor {
	return &RSAProcessor{
		keySize: 2048, // Default to 2048-bit keys
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *RSAProcessor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}

	// Ensure keys directory exists
	if err := os.MkdirAll("keys", 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Configure key size if provided
	if keySize, ok := config["keySize"].(int); ok {
		switch keySize {
		case 1024, 2048, 4096:
			p.keySize = keySize
		default:
			return fmt.Errorf("invalid key size: %d (must be 1024, 2048, or 4096)", keySize)
		}
	}

	// Get key file paths
	publicKeyFile := "keys/rsa_public.pem"
	privateKeyFile := "keys/rsa_private.pem"
	if pub, ok := config["publicKeyFile"].(string); ok {
		publicKeyFile = pub
	}
	if priv, ok := config["privateKeyFile"].(string); ok {
		privateKeyFile = priv
	}

	// Generate or load keys
	if err := p.loadOrGenerateKeys(publicKeyFile, privateKeyFile); err != nil {
		return fmt.Errorf("failed to load/generate keys: %w", err)
	}

	return nil
}

// loadOrGenerateKeys loads existing keys or generates new ones
func (p *RSAProcessor) loadOrGenerateKeys(publicKeyFile, privateKeyFile string) error {
	// Try to load existing keys
	if p.loadKeys(publicKeyFile, privateKeyFile) == nil {
		return nil
	}

	// Generate new key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, p.keySize)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	// Save private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err := os.WriteFile(privateKeyFile, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save public key
	publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	if err := os.WriteFile(publicKeyFile, publicKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	p.privateKey = privateKey
	p.publicKey = &privateKey.PublicKey
	return nil
}

// loadKeys attempts to load existing keys
func (p *RSAProcessor) loadKeys(publicKeyFile, privateKeyFile string) error {
	// Load private key
	privateKeyData, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return err
	}
	privateKeyBlock, _ := pem.Decode(privateKeyData)
	if privateKeyBlock == nil {
		return fmt.Errorf("failed to decode private key PEM block")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Load public key
	publicKeyData, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return err
	}
	publicKeyBlock, _ := pem.Decode(publicKeyData)
	if publicKeyBlock == nil {
		return fmt.Errorf("failed to decode public key PEM block")
	}
	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	p.privateKey = privateKey
	p.publicKey = publicKey
	return nil
}

// maxMessageBytes is the largest plaintext this key can encrypt with PKCS#1 v1.5.
func (p *RSAProcessor) maxMessageBytes() int {
	return (p.publicKey.N.BitLen()+7)/8 - pkcs1v15Overhead
}

// Process handles RSA encryption/decryption
func (p *RSAProcessor) Process(text string, operation string) (string, []string, error) {
	// Validate operation type
	if operation != OperationEncrypt && operation != OperationDecrypt {
		return "", nil, fmt.Errorf("invalid operation: %s (must be 'encrypt' or 'decrypt')", operation)
	}

	v := utils.NewVisualizer()

	p.addIntro(v)
	p.addKeyDetails(v)

	if operation == OperationDecrypt {
		return p.decrypt(v, text)
	}
	return p.encrypt(v, text)
}

// --- explanatory sections --------------------------------------------------

func (p *RSAProcessor) addIntro(v *utils.Visualizer) {
	v.AddStep("📌 What is RSA?")
	v.AddStep("RSA (Rivest–Shamir–Adleman, 1977) was the first practical PUBLIC-KEY cipher.")
	v.AddStep("It is ASYMMETRIC: it uses a KEY PAIR instead of one shared secret.")
	v.AddStep("  • Public key  — shared with everyone; used to ENCRYPT (or verify signatures)")
	v.AddStep("  • Private key — kept secret; used to DECRYPT (or create signatures)")
	v.AddNote("Think of an open padlock you hand out freely: anyone can snap it shut on a box,")
	v.AddNote("but only you hold the key that opens it. That asymmetry is the whole idea.")
	v.AddSeparator()

	v.AddStep("📈 Why it is secure: the trapdoor")
	v.AddStep("Multiplying two large primes p·q = n is easy; FACTORING n back into p and q is")
	v.AddStep("infeasible for big enough n. The public key exposes n; only someone who knows")
	v.AddStep("the factors can derive the private key. That one-way-with-a-trapdoor is RSA.")
	v.AddSeparator()
}

// addKeyDetails shows the real parameters of the loaded key pair, plus a small
// worked example the reader can actually follow.
func (p *RSAProcessor) addKeyDetails(v *utils.Visualizer) {
	v.AddStep("🔢 This key pair")
	v.AddStep(fmt.Sprintf("Modulus size (n): %d bits (RSA-%d)", p.publicKey.N.BitLen(), p.keySize))
	v.AddStep(fmt.Sprintf("Public exponent (e): %d", p.publicKey.E))
	v.AddStep("Modulus n (first bytes): " + truncateHex(p.publicKey.N.Bytes(), 16))
	v.AddStep(fmt.Sprintf("Private exponent d: kept secret (%d bits) — never shown or shared", p.privateKey.D.BitLen()))
	v.AddStep(fmt.Sprintf("Max message size: %d bytes (modulus bytes − 11 for PKCS#1 v1.5 padding)", p.maxMessageBytes()))
	v.AddNote("e is almost always 65537: it is prime and has few 1-bits, making encryption fast.")
	v.AddSeparator()

	addRSAToyExample(v)
}

// addRSAToyExample runs the full RSA math on tiny textbook primes so the reader
// can see key generation, encryption and decryption end to end.
func addRSAToyExample(v *utils.Visualizer) {
	// Classic small example: p=61, q=53.
	p := big.NewInt(61)
	q := big.NewInt(53)
	n := new(big.Int).Mul(p, q) // 3233
	one := big.NewInt(1)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one)) // 3120
	e := big.NewInt(17)
	d := new(big.Int).ModInverse(e, phi) // 2753
	m := big.NewInt(65)                  // toy "message"
	c := new(big.Int).Exp(m, e, n)       // encrypt
	dec := new(big.Int).Exp(c, d, n)     // decrypt

	v.AddStep("📚 Worked example with tiny primes (real keys are hundreds of digits)")
	v.AddStep(fmt.Sprintf("1. Pick primes p=%s, q=%s", p, q))
	v.AddStep(fmt.Sprintf("2. Modulus  n = p·q = %s", n))
	v.AddStep(fmt.Sprintf("3. Totient  φ(n) = (p−1)(q−1) = %s", phi))
	v.AddStep(fmt.Sprintf("4. Public exponent  e = %s  (coprime with φ)", e))
	v.AddStep(fmt.Sprintf("5. Private exponent d = e⁻¹ mod φ = %s   (since e·d mod φ = 1)", d))
	v.AddStep(fmt.Sprintf("   Public key = (n=%s, e=%s)   Private key = (n=%s, d=%s)", n, e, n, d))
	v.AddStep(fmt.Sprintf("6. Encrypt m=%s:  c = m^e mod n = %s", m, c))
	v.AddStep(fmt.Sprintf("7. Decrypt c=%s:  m = c^d mod n = %s  ✅ recovered", c, dec))
	v.AddNote("The security rests on step 5: without p and q you cannot compute φ, and without")
	v.AddNote("φ you cannot find d. Factoring a 2048-bit n to get there is currently infeasible.")
	v.AddSeparator()
}

// --- encryption ------------------------------------------------------------

func (p *RSAProcessor) encrypt(v *utils.Visualizer, text string) (string, []string, error) {
	v.AddStep("📈 Encryption steps")
	v.AddStep("1. Convert the text to bytes (an integer m, with m < n)")
	v.AddStep("2. Add PKCS#1 v1.5 padding with random bytes")
	v.AddStep("3. Compute the ciphertext  c = m^e mod n  using the PUBLIC key")
	v.AddStep("4. Base64-encode the result")
	v.AddSeparator()

	v.AddTextStep("Input Text", text)
	v.AddHexStep("Text as Bytes", []byte(text))
	v.AddStep(fmt.Sprintf("Message length: %d byte(s)", len(text)))

	// Friendly size check before the library returns a cryptic error.
	if maxLen := p.maxMessageBytes(); len(text) > maxLen {
		return "", nil, fmt.Errorf(
			"message is %d bytes but RSA-%d with PKCS#1 v1.5 can encrypt at most %d bytes; "+
				"real systems use hybrid encryption (RSA to wrap an AES key, AES for the data)",
			len(text), p.keySize, maxLen)
	}
	v.AddNote("RSA encrypts one number smaller than n, so the message must fit in one block.")
	v.AddNote("PKCS#1 v1.5 also mixes in random bytes, so encrypting the same text twice gives")
	v.AddNote("different ciphertexts — that randomization is essential to RSA's security.")
	v.AddArrow()

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, p.publicKey, []byte(text))
	if err != nil {
		return "", nil, fmt.Errorf("failed to encrypt: %w", err)
	}
	v.AddStep(fmt.Sprintf("Ciphertext is exactly %d bytes = the modulus size, regardless of message length:", len(ciphertext)))
	v.AddStep("Ciphertext (first bytes): " + truncateHex(ciphertext, 24))
	v.AddArrow()

	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	v.AddTextStep("Base64 Encoded Result", encoded)

	p.addSecurityNotes(v)
	return encoded, v.GetSteps(), nil
}

// --- decryption ------------------------------------------------------------

func (p *RSAProcessor) decrypt(v *utils.Visualizer, text string) (string, []string, error) {
	v.AddStep("📈 Decryption steps (encryption in reverse)")
	v.AddStep("1. Base64-decode the input to recover the ciphertext integer c")
	v.AddStep("2. Compute  m = c^d mod n  using the PRIVATE key")
	v.AddStep("3. Strip the PKCS#1 v1.5 padding")
	v.AddStep("4. Interpret the remaining bytes as text")
	v.AddSeparator()

	v.AddTextStep("Encrypted Input (Base64)", text)
	v.AddArrow()

	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", nil, fmt.Errorf("invalid base64 string: %w", err)
	}
	v.AddStep(fmt.Sprintf("Ciphertext: %d bytes", len(data)))
	v.AddStep("Ciphertext (first bytes): " + truncateHex(data, 24))
	v.AddArrow()

	v.AddStep("Apply the private key: m = c^d mod n, then remove padding.")
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, p.privateKey, data)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decrypt (wrong key, corrupted data, or bad padding): %w", err)
	}
	v.AddArrow()
	v.AddHexStep("Recovered Bytes", plaintext)
	v.AddTextStep("Decrypted Text", string(plaintext))

	p.addSecurityNotes(v)
	return string(plaintext), v.GetSteps(), nil
}

// --- shared wrap-up --------------------------------------------------------

func (p *RSAProcessor) addSecurityNotes(v *utils.Visualizer) {
	v.AddSeparator()
	v.AddStep("📚 RSA in the real world")
	v.AddStep("• Hybrid encryption: RSA is slow and size-limited, so TLS/PGP use RSA only to")
	v.AddStep("  wrap a random AES key, then encrypt the bulk data with AES (menu 3).")
	v.AddStep("• Signatures: sign with the PRIVATE key, verify with the PUBLIC key — the")
	v.AddStep("  reverse of encryption. This proves authenticity (see JWT RS256, menu 10).")
	v.AddStep("• Padding matters: textbook RSA (no padding) is insecure. Modern code prefers")
	v.AddStep("  OAEP over the PKCS#1 v1.5 used here, which has known padding-oracle pitfalls.")
	v.AddSeparator()

	v.AddStep("🔒 Security notes")
	v.AddStep(fmt.Sprintf("• Use ≥ 2048-bit keys (this key is %d-bit); 1024-bit is deprecated.", p.keySize))
	v.AddStep("• The private key must stay secret; anyone holding it can decrypt and sign.")
	v.AddStep("• A large quantum computer running Shor's algorithm would break RSA — hence the")
	v.AddStep("  ongoing shift toward post-quantum algorithms for long-lived secrets.")
	v.AddStep("• For key agreement, elliptic-curve methods like X25519 (menu 9) are smaller/faster.")
	v.AddNote("This tool stores keys as PEM files under keys/ for the demo; protect real private keys.")
}

// truncateHex renders up to n bytes of data as hex, appending an ellipsis and
// the total length when the data is longer.
func truncateHex(data []byte, n int) string {
	shown := data
	if len(shown) > n {
		shown = shown[:n]
	}
	hexStr := ""
	for i, b := range shown {
		if i > 0 {
			hexStr += " "
		}
		hexStr += fmt.Sprintf("%02x", b)
	}
	if len(data) > n {
		hexStr += fmt.Sprintf(" … (%d bytes total)", len(data))
	}
	return hexStr
}
