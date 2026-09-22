package crypto

import (
	"crypto/mldsa"
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// MLDSAProcessor demonstrates ML-DSA (FIPS 204), the post-quantum digital
// signature scheme formerly known as Dilithium.
type MLDSAProcessor struct {
	level int // 44, 65 (default), or 87
}

// NewMLDSAProcessor creates a new ML-DSA processor defaulting to ML-DSA-65.
func NewMLDSAProcessor() *MLDSAProcessor {
	return &MLDSAProcessor{level: 65}
}

// Configure accepts an optional "level" (44, 65, or 87).
func (p *MLDSAProcessor) Configure(config map[string]any) error {
	if level, ok := config["level"].(int); ok {
		switch level {
		case 44, 65, 87:
			p.level = level
		default:
			return fmt.Errorf("invalid ML-DSA level: %d (must be 44, 65, or 87)", level)
		}
	}
	return nil
}

func (p *MLDSAProcessor) params() mldsa.Parameters {
	switch p.level {
	case 44:
		return mldsa.MLDSA44()
	case 87:
		return mldsa.MLDSA87()
	default:
		return mldsa.MLDSA65()
	}
}

// Process signs the given message, verifies it, and demonstrates that tampering
// invalidates the signature. The operation argument is ignored.
func (p *MLDSAProcessor) Process(text string, _ string) (string, []string, error) {
	if text == "" {
		text = "Transfer $100 to Alice"
	}

	v := utils.NewVisualizer()
	p.addIntro(v)

	// Step 1: key generation.
	sk, err := mldsa.GenerateKey(p.params())
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate ML-DSA key: %w", err)
	}
	pk := sk.PublicKey()

	v.AddStep("Step 1: Signer generates a key pair")
	v.AddStep("---------------------------------")
	v.AddStep("The private (signing) key stays secret; the public (verification) key is shared.")
	v.AddStep(fmt.Sprintf("Public key:  %d bytes  (first bytes: %s)", len(pk.Bytes()), truncateHex(pk.Bytes(), 16)))
	v.AddStep(fmt.Sprintf("Private key seed: %d bytes — kept secret", len(sk.Bytes())))
	v.AddArrow()

	// Step 2: sign.
	v.AddStep("Step 2: Sign the message with the PRIVATE key")
	v.AddStep("-------------------------------------------")
	v.AddTextStep("Message", text)
	opts := &mldsa.Options{}
	sig, err := sk.Sign(nil, []byte(text), opts)
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign: %w", err)
	}
	v.AddStep(fmt.Sprintf("Signature: %d bytes  (first bytes: %s)", len(sig), truncateHex(sig, 16)))
	v.AddNote("Only the holder of the private key can produce a signature that verifies.")
	v.AddArrow()

	// Step 3: verify.
	v.AddStep("Step 3: Anyone verifies with the PUBLIC key")
	v.AddStep("-----------------------------------------")
	if err := mldsa.Verify(pk, []byte(text), sig, opts); err != nil {
		return "", nil, fmt.Errorf("unexpected: valid signature failed to verify: %w", err)
	}
	v.AddStep("✅ Signature verified — the message is authentic and unmodified.")
	v.AddArrow()

	// Step 4: tamper demonstration.
	p.addTamperDemo(v, pk, []byte(text), sig, opts)

	p.addSizes(v, pk.Bytes(), sig)
	p.addSecurityNotes(v)

	return fmt.Sprintf("ML-DSA-%d signature (%d bytes): %x…", p.level, len(sig), sig[:8]), v.GetSteps(), nil
}

// addTamperDemo shows that changing one byte of the message makes verification fail.
func (p *MLDSAProcessor) addTamperDemo(v *utils.Visualizer, pk *mldsa.PublicKey, message, sig []byte, opts *mldsa.Options) {
	v.AddStep("🔒 Tamper test (automatic)")
	tampered := make([]byte, len(message))
	copy(tampered, message)
	if len(tampered) > 0 {
		tampered[len(tampered)-1] ^= 0x01
	} else {
		tampered = []byte("x")
	}
	v.AddStep("Flip one bit of the message and verify the SAME signature against it:")
	if err := mldsa.Verify(pk, tampered, sig, opts); err != nil {
		v.AddStep("Verification of the tampered message → REJECTED ✅")
		v.AddNote("A signature binds to the exact message. Any change — or a forged signature made")
		v.AddNote("without the private key — fails verification, proving authenticity + integrity.")
	} else {
		v.AddStep("⚠️ Unexpected: tampered message verified (should never happen)")
	}
	v.AddSeparator()
}

// --- explanatory sections --------------------------------------------------

func (p *MLDSAProcessor) addIntro(v *utils.Visualizer) {
	v.AddStep("📌 What is ML-DSA?")
	v.AddStep(fmt.Sprintf("ML-DSA (FIPS 204), formerly Dilithium, is a POST-QUANTUM digital signature scheme. Running ML-DSA-%d here.", p.level))
	v.AddStep("Signatures prove AUTHENTICITY and INTEGRITY: sign with a private key, and anyone")
	v.AddStep("can verify with the public key — the reverse roles of encryption.")
	v.AddNote("Same purpose as RSA/EdDSA signatures (menus 5 and 10), but built to resist quantum attacks.")
	v.AddSeparator()

	v.AddStep("📈 Why post-quantum?")
	v.AddStep("Shor's algorithm on a large quantum computer would forge RSA and ECDSA/EdDSA")
	v.AddStep("signatures by recovering the private key. ML-DSA's security rests on lattice")
	v.AddStep("problems (Module-LWE / Module-SIS) with no known efficient quantum attack.")
	v.AddNote("Signatures need PQ protection for anything verified far in the future — firmware,")
	v.AddNote("software updates, long-lived certificates and documents.")
	v.AddSeparator()
}

func (p *MLDSAProcessor) addSizes(v *utils.Visualizer, pub, sig []byte) {
	v.AddStep("📚 Size is the trade-off")
	v.AddStep(fmt.Sprintf("ML-DSA-%d:  public key %d B, signature %d B", p.level, len(pub), len(sig)))
	v.AddStep("Ed25519 (EdDSA):  public key 32 B, signature 64 B")
	v.AddStep("RSA-2048:  public key ~270 B, signature 256 B")
	v.AddStep("Post-quantum signatures are far larger — kilobytes, not bytes. That growth hits")
	v.AddStep("certificate chains and handshakes, which is why adoption is staged and hybrid.")
	v.AddNote("Levels: ML-DSA-44 ≈ AES-128, ML-DSA-65 ≈ AES-192, ML-DSA-87 ≈ AES-256 security.")
	v.AddSeparator()
}

func (p *MLDSAProcessor) addSecurityNotes(v *utils.Visualizer) {
	v.AddStep("🔒 Security notes")
	v.AddStep("• Signatures give authenticity/integrity, NOT confidentiality — they do not hide")
	v.AddStep("  the message. Combine with a KEM like ML-KEM (menu 12) to also encrypt.")
	v.AddStep("• Keep the private key secret; anyone with it can forge signatures.")
	v.AddStep("• Deployments often use HYBRID signatures (classical + PQ) during the transition.")
	v.AddStep("• Standardized by NIST in 2024 (FIPS 204); pairs with ML-KEM for a full PQ stack.")
	v.AddStep("• A signing 'context' string can bind a signature to a specific purpose/protocol.")
	v.AddNote("ML-KEM (menu 12) agrees keys; ML-DSA authenticates — together they replace the")
	v.AddNote("RSA/ECDH + RSA/ECDSA pairing that quantum computers would break.")
}
