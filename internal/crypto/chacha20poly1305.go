package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/abdorrahmani/cryptolens/internal/utils"
	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20Poly1305Processor implements the Processor interface for ChaCha20-Poly1305 operations
type ChaCha20Poly1305Processor struct {
	BaseConfigurableProcessor
	keyManager KeyManager
	keySize    int
	nonceSize  int
	tagSize    int
	aad        string
}

// NewChaCha20Poly1305Processor creates a new ChaCha20-Poly1305 processor
func NewChaCha20Poly1305Processor() *ChaCha20Poly1305Processor {
	return &ChaCha20Poly1305Processor{
		keySize:   256,
		nonceSize: 12,
		tagSize:   16,
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *ChaCha20Poly1305Processor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}

	// Configure key file if provided
	keyFile := "keys/chacha20poly1305_key.bin"
	if kf, ok := config["keyFile"].(string); ok {
		keyFile = kf
	}

	// Initialize key manager
	p.keyManager = NewFileKeyManager(256, keyFile) // ChaCha20-Poly1305 uses 256-bit keys
	if err := p.keyManager.LoadOrGenerateKey(); err != nil {
		return fmt.Errorf("failed to load/generate key: %w", err)
	}

	// Configure key size if provided
	if keySize, ok := config["keySize"].(int); ok {
		if keySize != 256 {
			return fmt.Errorf("invalid key size: %d (must be 256 bits)", keySize)
		}
		p.keySize = keySize
	}

	// Configure nonce size if provided
	if nonceSize, ok := config["nonceSize"].(int); ok {
		if nonceSize != 12 {
			return fmt.Errorf("invalid nonce size: %d (must be 12 bytes)", nonceSize)
		}
		p.nonceSize = nonceSize
	}

	// Configure tag size if provided
	if tagSize, ok := config["tagSize"].(int); ok {
		if tagSize != 16 {
			return fmt.Errorf("invalid tag size: %d (must be 16 bytes)", tagSize)
		}
		p.tagSize = tagSize
	}

	// Optional Additional Authenticated Data (authenticated, not encrypted).
	if aad, ok := config["aad"].(string); ok {
		p.aad = aad
	}

	return nil
}

// Process implements the Processor interface
func (p *ChaCha20Poly1305Processor) Process(text string, operation string) (string, []string, error) {
	if operation != OperationEncrypt && operation != OperationDecrypt {
		return "", nil, fmt.Errorf("invalid operation: %s (must be 'encrypt' or 'decrypt')", operation)
	}

	v := utils.NewVisualizer()
	addChaChaIntro(v)

	if operation == OperationEncrypt {
		return p.encrypt(text, v)
	}
	return p.decrypt(text, v)
}

// --- explanatory sections --------------------------------------------------

func addChaChaIntro(v *utils.Visualizer) {
	v.AddStep("📌 What is ChaCha20-Poly1305?")
	v.AddStep("It is an AEAD cipher — Authenticated Encryption with Associated Data — that does")
	v.AddStep("two jobs at once, combining two primitives:")
	v.AddStep("  • ChaCha20  — a fast stream cipher that provides CONFIDENTIALITY")
	v.AddStep("  • Poly1305  — a one-time MAC that provides INTEGRITY + AUTHENTICITY")
	v.AddNote("It is the modern alternative to AES-GCM, and unlike AES-CBC (menu 3) it detects")
	v.AddNote("any tampering. TLS 1.3, WireGuard, and SSH all use it — especially where there is")
	v.AddNote("no AES hardware acceleration, since ChaCha20 is fast and constant-time in software.")
	v.AddSeparator()

	v.AddStep("🔢 The three inputs")
	v.AddStep("• Key   — 32 bytes (256-bit), secret, shared by both sides")
	v.AddStep("• Nonce — 12 bytes (96-bit), unique per message, NOT secret (sent in the clear)")
	v.AddStep("• AAD   — optional data authenticated but not encrypted (e.g. headers/metadata)")
	v.AddStep("Output = ciphertext + a 16-byte authentication tag.")
	v.AddSeparator()

	v.AddStep("📈 How it works (encrypt-then-MAC)")
	v.AddStep("1. ChaCha20 turns the key+nonce into a keystream and XORs it with the plaintext.")
	v.AddStep("2. Poly1305 computes a tag over the AAD + ciphertext using a one-time key derived")
	v.AddStep("   from ChaCha20. Decryption recomputes the tag FIRST and refuses to output any")
	v.AddStep("   plaintext unless it matches — so tampered data is never even decrypted.")
	v.AddNote("⚠️ Nonce reuse is catastrophic: encrypting two messages with the same key+nonce")
	v.AddNote("leaks their XOR and breaks Poly1305's authentication. See the Nonce Reuse attack (menu 12).")
	v.AddSeparator()
}

// --- encryption ------------------------------------------------------------

func (p *ChaCha20Poly1305Processor) encrypt(text string, v *utils.Visualizer) (string, []string, error) {
	v.AddStep("📈 Encryption")
	v.AddTextStep("Plaintext", text)

	key := p.keyManager.GetKey()
	v.AddHexStep("Key (32 bytes)", key)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonce := make([]byte, p.nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	v.AddHexStep("Nonce (random, 12 bytes)", nonce)
	if p.aad != "" {
		v.AddTextStep("AAD (authenticated, not encrypted)", p.aad)
	}
	v.AddArrow()

	start := time.Now()
	sealed := aead.Seal(nil, nonce, []byte(text), []byte(p.aad))
	elapsed := time.Since(start)

	ct := sealed[:len(sealed)-p.tagSize]
	tag := sealed[len(sealed)-p.tagSize:]
	v.AddHexStep("Ciphertext (same length as plaintext)", ct)
	v.AddHexStep("Poly1305 tag (16 bytes)", tag)
	v.AddStep(fmt.Sprintf("Encrypted in %s", elapsed.Round(time.Microsecond)))
	v.AddNote("The ciphertext is exactly the plaintext length (stream cipher — no padding, unlike AES-CBC).")
	v.AddArrow()

	// Output is nonce || ciphertext || tag, Base64-encoded.
	result := make([]byte, 0, len(nonce)+len(sealed))
	result = append(result, nonce...)
	result = append(result, sealed...)
	v.AddStep("Package as  nonce ‖ ciphertext ‖ tag  and Base64-encode:")
	v.AddTextStep("Result (Base64)", base64.StdEncoding.EncodeToString(result))
	v.AddTextStep("Result (Hex)", hex.EncodeToString(result))
	v.AddSeparator()

	// Built-in, non-interactive tampering demonstration.
	p.addTamperDemo(v, aead, nonce, sealed)
	p.addSecurityNotes(v)

	return base64.StdEncoding.EncodeToString(result), v.GetSteps(), nil
}

// addTamperDemo flips one ciphertext bit in a copy and shows that Open() then
// refuses to decrypt — the whole point of authenticated encryption.
func (p *ChaCha20Poly1305Processor) addTamperDemo(v *utils.Visualizer, aead cipher.AEAD, nonce, sealed []byte) {
	v.AddStep("🔒 Tamper test (automatic)")
	if len(sealed) <= p.tagSize {
		v.AddStep("(message too short to demonstrate on the ciphertext)")
		v.AddSeparator()
		return
	}
	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[0] ^= 0x01 // flip one bit of the first ciphertext byte
	v.AddStep(fmt.Sprintf("Flip one bit of the ciphertext: first byte %02x → %02x", sealed[0], tampered[0]))
	if _, err := aead.Open(nil, nonce, tampered, []byte(p.aad)); err != nil {
		v.AddStep("Decrypting the tampered data → REJECTED ✅ (Poly1305 tag mismatch)")
		v.AddNote("No plaintext is released. A single flipped bit is caught, so an attacker cannot")
		v.AddNote("silently alter the message — this is what AES-CBC alone (menu 3) cannot do.")
	} else {
		v.AddStep("⚠️ Unexpected: tampered data verified (should never happen)")
	}
	v.AddSeparator()
}

// --- decryption ------------------------------------------------------------

func (p *ChaCha20Poly1305Processor) decrypt(text string, v *utils.Visualizer) (string, []string, error) {
	v.AddStep("📈 Decryption")
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		v.AddStep("❌ Error: input is not valid Base64")
		return "", v.GetSteps(), fmt.Errorf("failed to decode input: %w", err)
	}

	if len(decoded) < p.nonceSize+p.tagSize {
		v.AddStep("❌ Error: input too short to contain nonce + tag")
		return "", v.GetSteps(), fmt.Errorf("input too short")
	}

	nonce := decoded[:p.nonceSize]
	sealed := decoded[p.nonceSize:]
	ct := sealed[:len(sealed)-p.tagSize]
	tag := sealed[len(sealed)-p.tagSize:]

	v.AddStep("Split the input back into its parts:")
	v.AddHexStep("Nonce", nonce)
	v.AddHexStep("Ciphertext", ct)
	v.AddHexStep("Tag", tag)
	if p.aad != "" {
		v.AddTextStep("AAD (must match encryption)", p.aad)
	}
	v.AddArrow()

	key := p.keyManager.GetKey()
	v.AddHexStep("Key (32 bytes)", key)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", v.GetSteps(), fmt.Errorf("failed to create cipher: %w", err)
	}

	v.AddStep("Verify the Poly1305 tag, then decrypt only if it matches:")
	start := time.Now()
	plaintext, err := aead.Open(nil, nonce, sealed, []byte(p.aad))
	elapsed := time.Since(start)
	if err != nil {
		v.AddStep("❌ Authentication failed — tag did not verify.")
		v.AddStep("Possible causes: wrong key, altered ciphertext/tag, wrong nonce, or changed AAD.")
		v.AddStep("No plaintext is returned — that is the AEAD guarantee working as intended.")
		return "", v.GetSteps(), fmt.Errorf("message authentication failed: %w", err)
	}
	v.AddStep(fmt.Sprintf("✅ Tag verified in %s — the data is authentic and untampered.", elapsed.Round(time.Microsecond)))
	v.AddArrow()
	v.AddTextStep("Decrypted Text", string(plaintext))
	v.AddSeparator()

	p.addSecurityNotes(v)
	return string(plaintext), v.GetSteps(), nil
}

// --- shared wrap-up --------------------------------------------------------

func (p *ChaCha20Poly1305Processor) addSecurityNotes(v *utils.Visualizer) {
	v.AddStep("🔒 Security notes")
	v.AddStep("• Never reuse a (key, nonce) pair — it breaks both confidentiality and authenticity.")
	v.AddStep("  A random 96-bit nonce is safe for a moderate number of messages; for very high")
	v.AddStep("  volumes use XChaCha20-Poly1305 (192-bit nonce) or a counter.")
	v.AddStep("• AEAD gives confidentiality AND integrity in one step — prefer it over CBC+separate MAC.")
	v.AddStep("• The tag is checked before any plaintext is released (no padding-oracle class of bugs).")
	v.AddStep("• ChaCha20-Poly1305 and AES-GCM are the two modern AEAD workhorses; ChaCha20 wins")
	v.AddStep("  in software / on mobile, AES-GCM wins where the CPU has AES instructions.")
	v.AddNote("Poly1305 is the same idea as HMAC (menu 6): a keyed tag — but a faster one-time MAC.")
}
