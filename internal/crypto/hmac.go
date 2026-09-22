package crypto

import (
	"crypto/hmac"
	// nolint:gosec // SHA1 is included for educational purposes only, with clear warnings about its insecurity
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/abdorrahmani/cryptolens/internal/utils"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
)

// Available hash algorithms
const (
	HashSHA1       = "sha1"
	HashSHA256     = "sha256"
	HashSHA512     = "sha512"
	HashBLAKE2b256 = "blake2b-256"
	HashBLAKE2b512 = "blake2b-512"
	HashBLAKE3     = "blake3"
)

// HMAC uses two fixed one-byte pads, repeated to the hash's block size.
const (
	hmacIpad = 0x36 // inner pad
	hmacOpad = 0x5c // outer pad
)

type HMACProcessor struct {
	BaseConfigurableProcessor
	keyManager    KeyManager
	hashAlgorithm string
}

func NewHMACProcessor() *HMACProcessor {
	return &HMACProcessor{
		hashAlgorithm: HashSHA256,
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *HMACProcessor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}

	// Configure key file if provided
	keyFile := "keys/hmac_key.bin"
	if kf, ok := config["keyFile"].(string); ok {
		keyFile = kf
	}

	// Initialize key manager
	p.keyManager = NewFileKeyManager(256, keyFile) // HMAC-SHA256 uses 256-bit keys
	if err := p.keyManager.LoadOrGenerateKey(); err != nil {
		return fmt.Errorf("failed to load/generate key: %w", err)
	}

	// Configure hash algorithm if provided
	if hashAlgo, ok := config["hashAlgorithm"].(string); ok {
		if hashAlgo != "" {
			switch hashAlgo {
			case HashSHA1, HashSHA256, HashSHA512, HashBLAKE2b256, HashBLAKE2b512, HashBLAKE3:
				p.hashAlgorithm = hashAlgo
			default:
				return fmt.Errorf("unsupported hash algorithm: %s (must be one of: sha1, sha256, sha512, blake2b-256, blake2b-512, blake3)", hashAlgo)
			}
		}
	}

	return nil
}

// getHashFunction returns the appropriate hash function for the selected algorithm
func (p *HMACProcessor) getHashFunction() (func() hash.Hash, error) {
	switch p.hashAlgorithm {
	case HashSHA1:
		return sha1.New, nil
	case HashSHA256:
		return sha256.New, nil
	case HashSHA512:
		return sha512.New, nil
	case HashBLAKE2b256:
		return func() hash.Hash {
			h, _ := blake2b.New256(nil)
			return h
		}, nil
	case HashBLAKE2b512:
		return func() hash.Hash {
			h, _ := blake2b.New512(nil)
			return h
		}, nil
	case HashBLAKE3:
		return func() hash.Hash {
			return blake3.New()
		}, nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", p.hashAlgorithm)
	}
}

// getBlockSize returns the block size for the selected hash algorithm
func (p *HMACProcessor) getBlockSize() int {
	switch p.hashAlgorithm {
	case HashSHA1:
		return 64
	case HashSHA256:
		return 64
	case HashSHA512:
		return 128
	case HashBLAKE2b256:
		return 128 // BLAKE2b uses a 128-byte block for both digest sizes
	case HashBLAKE2b512:
		return 128
	case HashBLAKE3:
		return 64
	default:
		return 64 // Default to SHA-256 block size
	}
}

// getOutputSize returns the output size in bytes for the selected hash algorithm
func (p *HMACProcessor) getOutputSize() int {
	switch p.hashAlgorithm {
	case HashSHA1:
		return 20 // 160 bits
	case HashSHA256:
		return 32 // 256 bits
	case HashSHA512:
		return 64 // 512 bits
	case HashBLAKE2b256:
		return 32 // 256 bits
	case HashBLAKE2b512:
		return 64 // 512 bits
	case HashBLAKE3:
		return 32 // 256 bits by default
	default:
		return 32 // Default to SHA-256 size
	}
}

func (p *HMACProcessor) Process(text string, operation string) (string, []string, error) {
	// Validate operation type. HMAC computes an authentication tag; it is
	// one-way, so there is no "decrypt".
	if operation != OperationEncrypt {
		return "", nil, fmt.Errorf("invalid operation: %s (HMAC computes a tag; it cannot be reversed)", operation)
	}

	v := utils.NewVisualizer()
	newHash, err := p.getHashFunction()
	if err != nil {
		return "", nil, err
	}
	key := p.keyManager.GetKey()

	p.addIntro(v)
	p.addWhyNested(v)
	p.addConfig(v)

	// Show the inputs.
	v.AddTextStep("Message", text)
	v.AddHexStep("Secret Key", key)
	v.AddArrow()

	// Walk the construction on the real input, computing it by hand.
	tag := p.addConstructionWalkthrough(v, newHash, key, []byte(text))

	// Cross-check the hand computation against Go's crypto/hmac.
	ref := hmac.New(newHash, key)
	ref.Write([]byte(text))
	refTag := ref.Sum(nil)
	if hmac.Equal(tag, refTag) {
		v.AddStep("✅ Hand-computed tag matches Go's crypto/hmac output exactly.")
	} else {
		v.AddStep("⚠️ Hand-computed tag does NOT match the library (unexpected).")
	}
	v.AddSeparator()

	// The core use case: verification.
	p.addVerificationDemo(v, newHash, key, text, tag)

	// Outputs.
	hmacHex := hex.EncodeToString(tag)
	hmacBase64 := base64.StdEncoding.EncodeToString(tag)
	v.AddStep("📈 Output formats")
	v.AddTextStep(fmt.Sprintf("HMAC (Hex, %d bytes)", len(tag)), hmacHex)
	v.AddTextStep("HMAC (Base64)", hmacBase64)

	p.addAlgorithmComparison(v)
	p.addSecurityNotes(v)

	result := fmt.Sprintf("Hex: %s\nBase64: %s", hmacHex, hmacBase64)
	return result, v.GetSteps(), nil
}

// --- explanatory sections --------------------------------------------------

func (p *HMACProcessor) addIntro(v *utils.Visualizer) {
	v.AddStep("📌 What is HMAC?")
	v.AddStep("HMAC (Hash-based Message Authentication Code) turns a hash function plus a")
	v.AddStep("SECRET KEY into an authentication tag. It answers two questions at once:")
	v.AddStep("  • Integrity — was the message altered in transit?")
	v.AddStep("  • Authenticity — did it come from someone who holds the shared key?")
	v.AddNote("A plain hash (menu 4) only gives integrity: anyone can recompute it. HMAC adds a")
	v.AddNote("key, so only holders of the key can produce or check the tag. It is still one-way.")
	v.AddSeparator()

	v.AddStep("🔢 How it is used (the workflow)")
	v.AddStep("1. Sender computes tag = HMAC(key, message) and sends (message, tag).")
	v.AddStep("2. Receiver recomputes HMAC(key, message) and checks it equals the tag.")
	v.AddStep("3. Match → authentic and untampered. Mismatch → reject.")
	v.AddSeparator()
}

func (p *HMACProcessor) addWhyNested(v *utils.Visualizer) {
	v.AddStep("📈 Why the nested construction (not just Hash(key ‖ message))?")
	v.AddStep("The obvious idea — hash the key glued to the message — is INSECURE for hashes")
	v.AddStep("like SHA-256 because of the length-extension attack: knowing Hash(key ‖ msg)")
	v.AddStep("and the length lets an attacker forge a valid tag for msg ‖ extra WITHOUT the key.")
	v.AddStep("HMAC defeats this by hashing TWICE with two key-derived pads:")
	v.AddStep("  HMAC(K, m) = H( (K⊕opad) ‖ H( (K⊕ipad) ‖ m ) )")
	v.AddStep("The outer hash hides the inner hash's internal state, so extension is impossible.")
	v.AddNote("ipad = 0x36 repeated, opad = 0x5c repeated. They differ so the inner and outer")
	v.AddNote("keys are distinct; the specific values are from RFC 2104.")
	v.AddSeparator()
}

func (p *HMACProcessor) addConfig(v *utils.Visualizer) {
	v.AddStep("🔢 This configuration")
	v.AddStep(fmt.Sprintf("Hash function: %s", p.hashAlgorithm))
	v.AddStep(fmt.Sprintf("Block size:    %d bytes (the pad/key block width)", p.getBlockSize()))
	v.AddStep(fmt.Sprintf("Tag size:      %d bytes (%d bits)", p.getOutputSize(), p.getOutputSize()*8))
	v.AddSeparator()
}

// addConstructionWalkthrough computes HMAC by hand on the real message, showing
// each intermediate value. Returns the inner hash, final tag, and block-sized key.
func (p *HMACProcessor) addConstructionWalkthrough(v *utils.Visualizer, newHash func() hash.Hash, key, message []byte) []byte {
	blockSize := p.getBlockSize()

	// Derive the block size from the hash itself so the walkthrough always
	// matches what crypto/hmac uses internally.
	if bs := newHash().BlockSize(); bs > 0 {
		blockSize = bs
	}

	v.AddStep("📈 Step 1 — Normalize the key to one block")
	if len(key) > blockSize {
		h := newHash()
		h.Write(key)
		key = h.Sum(nil)
		v.AddStep(fmt.Sprintf("Key was longer than the %d-byte block, so it is hashed down first.", blockSize))
	} else {
		v.AddStep(fmt.Sprintf("Key is %d bytes ≤ %d-byte block, so it is right-padded with zeros.", len(key), blockSize))
	}
	blockKey := make([]byte, blockSize)
	copy(blockKey, key)
	v.AddHexStep("Block-sized key K'", blockKey)
	v.AddArrow()

	v.AddStep("📈 Step 2 — Derive the inner and outer keys")
	v.AddStep(fmt.Sprintf("ipad = 0x%02X × %d, opad = 0x%02X × %d", hmacIpad, blockSize, hmacOpad, blockSize))
	ipad := createPadding(hmacIpad, blockSize)
	opad := createPadding(hmacOpad, blockSize)
	innerKey := xorBytes(blockKey, ipad)
	outerKey := xorBytes(blockKey, opad)
	v.AddHexStep("K' ⊕ ipad (inner key)", innerKey)
	v.AddHexStep("K' ⊕ opad (outer key)", outerKey)
	v.AddArrow()

	v.AddStep("📈 Step 3 — Inner hash: H(innerKey ‖ message)")
	hi := newHash()
	hi.Write(innerKey)
	hi.Write(message)
	inner := hi.Sum(nil)
	v.AddHexStep("Inner hash", inner)
	v.AddArrow()

	v.AddStep("📈 Step 4 — Outer hash: H(outerKey ‖ innerHash) → the tag")
	ho := newHash()
	ho.Write(outerKey)
	ho.Write(inner)
	tag := ho.Sum(nil)
	v.AddHexStep("HMAC tag", tag)
	v.AddArrow()
	return tag
}

// addVerificationDemo shows the receiver side: a matching message verifies, a
// tampered one does not — and why the comparison must be constant-time.
func (p *HMACProcessor) addVerificationDemo(v *utils.Visualizer, newHash func() hash.Hash, key []byte, message string, tag []byte) {
	v.AddStep("🔒 Verification (the whole point)")

	// Case 1: untampered message recomputes to the same tag.
	ok := hmac.New(newHash, key)
	ok.Write([]byte(message))
	okTag := ok.Sum(nil)
	v.AddStep("Case 1 — receiver gets the original message and recomputes the tag:")
	v.AddStep(fmt.Sprintf("  recomputed == sent tag ? %v → ACCEPT ✅", hmac.Equal(okTag, tag)))

	// Case 2: tamper with one byte and show the tag fully changes.
	tampered := tamperOneByte(message)
	tf := hmac.New(newHash, key)
	tf.Write([]byte(tampered))
	tfTag := tf.Sum(nil)
	diff := countDiffBits(tag, tfTag)
	v.AddStep(fmt.Sprintf("Case 2 — attacker changes the message to %q (no key):", tampered))
	v.AddHexStep("  tag of tampered message", tfTag)
	v.AddStep(fmt.Sprintf("  differs from the real tag in %d of %d bits → REJECT ✅", diff, len(tag)*8))
	v.AddStep(fmt.Sprintf("  hmac.Equal(sent, recomputed) = %v", hmac.Equal(tag, tfTag)))
	v.AddNote("Without the key an attacker cannot compute the right tag for their forged message,")
	v.AddNote("so any change is caught. This is exactly what protects signed cookies, API")
	v.AddNote("requests, and JWT HS256 (menu 10).")

	v.AddStep("Compare tags in CONSTANT TIME (Go's hmac.Equal / subtle.ConstantTimeCompare).")
	v.AddNote("A normal == comparison returns early on the first differing byte; measuring that")
	v.AddNote("timing can leak the tag byte-by-byte — see the Timing Attack simulation (menu 12).")
	v.AddSeparator()
}

func (p *HMACProcessor) addAlgorithmComparison(v *utils.Visualizer) {
	v.AddStep("📚 Choosing the hash")
	v.AddStep("Algorithm      Tag size   Notes")
	v.AddStep("sha1           20 bytes   Legacy; HMAC-SHA1 not yet broken but avoid for new work")
	v.AddStep("sha256         32 bytes   Safe default, ubiquitous")
	v.AddStep("sha512         64 bytes   Larger margin; faster than sha256 on 64-bit CPUs")
	v.AddStep("blake2b-256    32 bytes   Faster than SHA-2, modern")
	v.AddStep("blake2b-512    64 bytes   Faster than SHA-512, modern")
	v.AddStep("blake3         32 bytes   Very fast, parallel/tree hashing")
	v.AddStep(fmt.Sprintf("→ currently selected: %s", p.hashAlgorithm))
	v.AddNote("Run the benchmark (menu 6 → Run Benchmark) to compare their speed on your machine.")
	v.AddSeparator()
}

func (p *HMACProcessor) addSecurityNotes(v *utils.Visualizer) {
	v.AddStep("🔒 Security notes")
	v.AddStep("• HMAC gives integrity AND authenticity, but NOT confidentiality — the message")
	v.AddStep("  is not encrypted. Pair it with encryption (encrypt-then-MAC) when you need both.")
	v.AddStep("• Keep the key secret and use a full-length random key (≥ the hash output size).")
	v.AddStep("• HMAC is provably resistant to length-extension, unlike a bare hash.")
	v.AddStep("• Even with a weakened hash, HMAC stays strong: HMAC-SHA1 is still unbroken,")
	v.AddStep("  though SHA-256+ is preferred for new designs.")
	v.AddStep("• Always verify tags in constant time to avoid timing side channels.")
	v.AddNote("HMAC also underpins HKDF and PBKDF2 (menu 7) and JWT HS256 (menu 10).")
}

// --- helpers ---------------------------------------------------------------

// tamperOneByte returns message with its last byte's low bit flipped, or a
// non-empty stand-in when the message is empty, for the verification demo.
func tamperOneByte(message string) string {
	b := []byte(message)
	if len(b) == 0 {
		return "x"
	}
	b[len(b)-1] ^= 0x01
	return string(b)
}

// Helper function to create padding buffer
func createPadding(value byte, size int) []byte {
	padding := make([]byte, size)
	for i := range padding {
		padding[i] = value
	}
	return padding
}

// Helper function to XOR two byte slices
func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		return nil
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}
