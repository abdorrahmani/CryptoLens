package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// X25519Processor implements the Processor interface for X25519 key exchange
type X25519Processor struct {
	keyManager KeyManager
}

// NewX25519Processor creates a new X25519 processor
func NewX25519Processor() *X25519Processor {
	return &X25519Processor{
		keyManager: NewFileKeyManager(32, "keys/x25519_private.bin"), // 32 bytes for X25519 private key
	}
}

// Configure configures the X25519 processor with the given settings
func (p *X25519Processor) Configure(config map[string]interface{}) error {
	// Ensure keys directory exists
	if err := os.MkdirAll("keys", 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	if privateKeyFile, ok := config["privateKeyFile"].(string); ok {
		p.keyManager = NewFileKeyManager(32, privateKeyFile)
	} else if _, ok := config["privateKeyFile"]; ok {
		return fmt.Errorf("invalid privateKeyFile type: expected string")
	}
	return nil
}

// clampScalar applies the X25519 clamping to a 32-byte private scalar and
// returns a copy, leaving the input untouched.
func clampScalar(priv []byte) []byte {
	c := make([]byte, len(priv))
	copy(c, priv)
	c[0] &= 248  // clear the low 3 bits  → scalar is a multiple of 8 (the cofactor)
	c[31] &= 127 // clear the top bit     → scalar < 2^255
	c[31] |= 64  // set bit 254           → fixes the high bit for a constant-time ladder
	return c
}

// Process implements the Processor interface for X25519
func (p *X25519Processor) Process(_ string, _ string) (string, []string, error) {
	v := utils.NewVisualizer()
	startTime := time.Now()

	addX25519Intro(v)
	addX25519Diagram(v)

	// Step 1: Generate private keys (with clamping explained).
	v.AddStep("Step 1: Private Key Generation")
	v.AddStep("---------------------------")
	v.AddStep("Each private key is just 32 random bytes, then 'clamped' — a few fixed bits are")
	v.AddStep("forced so every key is a safe scalar and the multiplication runs in constant time:")
	v.AddStep("  byte[0]  &= 248  → clear low 3 bits (multiple of the cofactor 8)")
	v.AddStep("  byte[31] &= 127  → clear the top bit (keep scalar below 2^255)")
	v.AddStep("  byte[31] |= 64   → set bit 254 (fixed high bit ⇒ constant-time ladder)")
	rawAlice := make([]byte, 32)
	rawBob := make([]byte, 32)
	if _, err := rand.Read(rawAlice); err != nil {
		return "", nil, fmt.Errorf("failed to generate Alice's private key: %w", err)
	}
	if _, err := rand.Read(rawBob); err != nil {
		return "", nil, fmt.Errorf("failed to generate Bob's private key: %w", err)
	}
	alicePrivate := clampScalar(rawAlice)
	bobPrivate := clampScalar(rawBob)
	v.AddStep(fmt.Sprintf("Alice's clamped private key: %x", alicePrivate))
	v.AddStep(fmt.Sprintf("Bob's   clamped private key: %x", bobPrivate))
	v.AddNote("Clamping is unique to Curve25519 — it removes whole classes of implementation bugs.")
	v.AddArrow()

	// Step 2: Public keys = scalar * basepoint.
	v.AddStep("Step 2: Public Key Calculation")
	v.AddStep("----------------------------")
	v.AddStep("Public key = private_scalar · G, where G is Curve25519's fixed base point (u=9).")
	v.AddStep("This 'scalar multiplication' is the elliptic-curve analogue of g^a mod p in DH.")
	alicePublic, err := curve25519.X25519(alicePrivate, curve25519.Basepoint)
	if err != nil {
		return "", nil, fmt.Errorf("failed to calculate Alice's public key: %w", err)
	}
	bobPublic, err := curve25519.X25519(bobPrivate, curve25519.Basepoint)
	if err != nil {
		return "", nil, fmt.Errorf("failed to calculate Bob's public key: %w", err)
	}
	v.AddStep(fmt.Sprintf("Alice's public key (32 bytes): %x", alicePublic))
	v.AddStep(fmt.Sprintf("Bob's   public key (32 bytes): %x", bobPublic))
	v.AddNote("Reversing this (finding the scalar from the point) is the elliptic-curve discrete")
	v.AddNote("log problem — infeasible. Note keys are 32 bytes vs 256+ bytes for 2048-bit DH.")
	v.AddArrow()

	// Step 3: Shared secret = my_scalar * peer_public.
	v.AddStep("Step 3: Shared Secret Calculation")
	v.AddStep("-------------------------------")
	v.AddStep("Each multiplies their own scalar by the OTHER's public point:")
	v.AddStep("  Alice: a·(b·G)     Bob: b·(a·G)     both equal (a·b)·G")
	aliceShared, err := curve25519.X25519(alicePrivate, bobPublic)
	if err != nil {
		return "", nil, fmt.Errorf("failed to calculate Alice's shared secret: %w", err)
	}
	bobShared, err := curve25519.X25519(bobPrivate, alicePublic)
	if err != nil {
		return "", nil, fmt.Errorf("failed to calculate Bob's shared secret: %w", err)
	}
	v.AddStep(fmt.Sprintf("Alice computes a·B: %x", aliceShared))
	v.AddStep(fmt.Sprintf("Bob   computes b·A: %x", bobShared))
	v.AddArrow()

	// Step 4: Verify.
	v.AddStep("Step 4: Shared Secret Verification")
	v.AddStep("--------------------------------")
	if bytes.Equal(aliceShared, bobShared) {
		v.AddStep("✅ Shared secrets match! Both derived (a·b)·G independently.")
	} else {
		return "", nil, fmt.Errorf("shared secrets do not match")
	}
	v.AddNote("An eavesdropper sees A and B (both public points) but cannot compute (a·b)·G.")
	v.AddSeparator()

	// Step 5: HKDF.
	v.AddStep("Step 5: Key Derivation (HKDF)")
	v.AddStep("---------------------")
	v.AddStep("The raw shared point is not used directly as a key — it is run through HKDF to")
	v.AddStep("produce a uniform, purpose-bound symmetric key.")
	h := hkdf.New(sha256.New, aliceShared, []byte("CryptoLens-X25519-KDF"), []byte("CryptoLens-X25519-Info"))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(h, derivedKey); err != nil {
		return "", nil, fmt.Errorf("failed to derive key: %w", err)
	}
	v.AddStep(fmt.Sprintf("Derived AES key (HKDF-SHA256): %x", derivedKey))
	v.AddNote("HKDF gives key separation and diversification — see PBKDF/KDF concepts in menu 7.")
	v.AddSeparator()

	// Step 6: AES-GCM demo.
	v.AddStep("Step 6: Using the Shared Key for AES-GCM Encryption")
	v.AddStep("-------------------------------------------")
	sampleMessage := "Hello, this is a secret message!"
	v.AddStep(fmt.Sprintf("Original Message: %s", sampleMessage))
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(sampleMessage), nil)
	v.AddStep(fmt.Sprintf("Encrypted (Base64): %s", base64.StdEncoding.EncodeToString(ciphertext)))
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	v.AddStep(fmt.Sprintf("Decrypted Message: %s", string(plaintext)))
	v.AddNote("This is exactly the TLS pattern: X25519 agrees a key, an AEAD cipher protects data.")
	v.AddSeparator()

	addX25519Performance(v, startTime)
	addX25519Security(v)
	addTLS13Flow(v)

	result := "Successfully demonstrated X25519 key exchange and AES-GCM encryption"
	return result, v.GetSteps(), nil
}

// --- explanatory sections --------------------------------------------------

func addX25519Intro(v *utils.Visualizer) {
	v.AddStep("📌 What is X25519?")
	v.AddStep("X25519 is Diffie-Hellman done on the elliptic curve Curve25519 (an ECDH scheme).")
	v.AddStep("Same goal as classic DH (menu 8) — agree a shared secret over an open channel —")
	v.AddStep("but using curve point multiplication instead of modular exponentiation.")
	v.AddNote("It is KEY AGREEMENT, not encryption, and it is the default in TLS 1.3, Signal,")
	v.AddNote("WireGuard, and modern SSH.")
	v.AddSeparator()

	v.AddStep("📈 Why it replaced classic DH")
	v.AddStep("• Smaller: 32-byte keys vs 256+ bytes for 2048-bit DH — same or better security.")
	v.AddStep("• Faster: curve scalar multiplication beats big modular exponentiation.")
	v.AddStep("• Safer by design: one fixed, vetted curve — no prime/parameter choices to get")
	v.AddStep("  wrong, and constant-time by construction so timing attacks don't leak the key.")
	v.AddSeparator()
}

func addX25519Diagram(v *utils.Visualizer) {
	v.AddStep("Key Exchange Flow:")
	v.AddStep("┌─────────┐                    ┌─────────┐")
	v.AddStep("│  Alice  │                    │   Bob   │")
	v.AddStep("└────┬────┘                    └────┬────┘")
	v.AddStep("     │  a (secret)      (secret) b  │")
	v.AddStep("     │  A = a·G  ───────────►  A    │")
	v.AddStep("     │      B    ◄───────────  B = b·G")
	v.AddStep("     │  s = a·B                s = b·A")
	v.AddStep("     │        both equal (a·b)·G    │")
	v.AddStep("     │  HKDF → AES key   HKDF → AES key")
	v.AddStep("┌────┴────┐                    ┌────┴────┐")
	v.AddStep("│  Alice  │                    │   Bob   │")
	v.AddStep("└─────────┘                    └─────────┘")
	v.AddNote("G is the fixed base point; · is curve scalar multiplication (the one-way op).")
	v.AddSeparator()
}

// addX25519Performance times X25519 against a comparable 2048-bit modular
// exponentiation (classic DH's core operation) and reports the rough ratio.
func addX25519Performance(v *utils.Visualizer, startTime time.Time) {
	v.AddStep("⚡ Performance (rough, this machine)")
	x25519Duration := time.Since(startTime)
	v.AddStep(fmt.Sprintf("Full X25519 exchange + HKDF + AES demo: %v", x25519Duration.Round(time.Microsecond)))

	// One 2048-bit modular exponentiation ≈ the core cost of a classic DH op.
	dhStart := time.Now()
	mod := new(big.Int).Lsh(big.NewInt(1), 2048)
	base := big.NewInt(2)
	exp, _ := rand.Int(rand.Reader, mod)
	_ = new(big.Int).Exp(base, exp, mod)
	dhDuration := time.Since(dhStart)
	v.AddStep(fmt.Sprintf("One 2048-bit modular exponentiation (classic DH's core op): %v", dhDuration.Round(time.Microsecond)))
	v.AddNote("Indicative only — a single sample. In practice X25519 is several times faster than")
	v.AddNote("2048-bit DH for equivalent security, which is why modern protocols switched to it.")
	v.AddSeparator()
}

func addX25519Security(v *utils.Visualizer) {
	v.AddStep("🔒 Security considerations")
	v.AddStep("• X25519 gives NO authentication on its own — an active attacker can sit in the")
	v.AddStep("  middle and run a separate exchange with each side (MITM). It MUST be combined")
	v.AddStep("  with authentication: TLS certificates, signatures, or a pre-shared key.")
	v.AddStep("• Use EPHEMERAL keys per session for Perfect Forward Secrecy — a later key")
	v.AddStep("  compromise then cannot decrypt past recorded traffic.")
	v.AddStep("• Never use the raw shared point as a key; always run it through a KDF (HKDF).")
	v.AddStep("• Use a vetted constant-time library (golang.org/x/crypto/curve25519). Never")
	v.AddStep("  hand-roll curve arithmetic.")
	v.AddStep("Curve25519's properties this relies on:")
	v.AddStep("  • constant-time operations by design")
	v.AddStep("  • resistant to side-channel attacks")
	v.AddStep("  • better protection against timing attacks")
	v.AddStep("  • no known practical attacks against Curve25519")
	v.AddStep("  • smaller attack surface due to simpler implementation")
	v.AddSeparator()
}

func addTLS13Flow(v *utils.Visualizer) {
	v.AddStep("📚 How TLS 1.3 uses X25519")
	v.AddStep("1. ClientHello — client offers key-exchange groups (X25519, P-256, …) and sends")
	v.AddStep("   an ephemeral X25519 public key.")
	v.AddStep("2. ServerHello — server picks X25519 and sends its own ephemeral public key.")
	v.AddStep("3. Both sides run X25519 to get the shared secret, then HKDF to derive traffic keys.")
	v.AddStep("4. The server authenticates with a certificate + signature (this is what stops MITM).")
	v.AddStep("5. Finished messages verify the handshake; encrypted application data flows using")
	v.AddStep("   an AEAD cipher (AES-GCM or ChaCha20-Poly1305, menu 11).")
	v.AddNote("Ephemeral X25519 keys give TLS 1.3 forward secrecy by default; static RSA key")
	v.AddNote("exchange was removed in TLS 1.3 for exactly this reason.")
}
