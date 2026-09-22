package crypto

import (
	"bytes"
	"crypto/mlkem"
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// MLKEMProcessor demonstrates ML-KEM (FIPS 203), the post-quantum key
// encapsulation mechanism formerly known as Kyber.
type MLKEMProcessor struct {
	level int // 768 (default) or 1024
}

// NewMLKEMProcessor creates a new ML-KEM processor defaulting to ML-KEM-768.
func NewMLKEMProcessor() *MLKEMProcessor {
	return &MLKEMProcessor{level: 768}
}

// Configure accepts an optional "level" (768 or 1024).
func (p *MLKEMProcessor) Configure(config map[string]any) error {
	if level, ok := config["level"].(int); ok {
		switch level {
		case 768, 1024:
			p.level = level
		default:
			return fmt.Errorf("invalid ML-KEM level: %d (must be 768 or 1024)", level)
		}
	}
	return nil
}

// mlkemRun holds the byte outputs of one encapsulate/decapsulate round so the
// visualization is identical regardless of parameter set.
type mlkemRun struct {
	encapKey   []byte // public key
	decapSeed  []byte // private key seed (64 bytes)
	ciphertext []byte
	sharedBob  []byte // shared key Bob derived when encapsulating
	sharedAli  []byte // shared key Alice derived when decapsulating
}

func (p *MLKEMProcessor) run() (*mlkemRun, error) {
	switch p.level {
	case 1024:
		dk, err := mlkem.GenerateKey1024()
		if err != nil {
			return nil, err
		}
		ek := dk.EncapsulationKey()
		sharedBob, ct := ek.Encapsulate()
		sharedAli, err := dk.Decapsulate(ct)
		if err != nil {
			return nil, err
		}
		return &mlkemRun{ek.Bytes(), dk.Bytes(), ct, sharedBob, sharedAli}, nil
	default: // 768
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, err
		}
		ek := dk.EncapsulationKey()
		sharedBob, ct := ek.Encapsulate()
		sharedAli, err := dk.Decapsulate(ct)
		if err != nil {
			return nil, err
		}
		return &mlkemRun{ek.Bytes(), dk.Bytes(), ct, sharedBob, sharedAli}, nil
	}
}

// Process runs a full ML-KEM key-encapsulation demonstration. The text and
// operation arguments are ignored — like the other key-agreement demos.
func (p *MLKEMProcessor) Process(_ string, _ string) (string, []string, error) {
	v := utils.NewVisualizer()

	p.addIntro(v)

	r, err := p.run()
	if err != nil {
		return "", nil, fmt.Errorf("ML-KEM demonstration failed: %w", err)
	}

	// Step 1: key generation.
	v.AddStep("Step 1: Alice generates a key pair")
	v.AddStep("--------------------------------")
	v.AddStep("Alice keeps the private decapsulation key and publishes the encapsulation key.")
	v.AddStep(fmt.Sprintf("Public encapsulation key: %d bytes  (first bytes: %s)", len(r.encapKey), truncateHex(r.encapKey, 16)))
	v.AddStep(fmt.Sprintf("Private key seed: %d bytes — kept secret", len(r.decapSeed)))
	v.AddArrow()

	// Step 2: encapsulation (Bob).
	v.AddStep("Step 2: Bob encapsulates a shared secret")
	v.AddStep("--------------------------------------")
	v.AddStep("Bob takes Alice's public key and runs Encapsulate(), which outputs TWO things:")
	v.AddStep(fmt.Sprintf("• A shared secret (32 bytes): %s", truncateHex(r.sharedBob, 32)))
	v.AddStep(fmt.Sprintf("• A ciphertext (%d bytes) to send to Alice: %s", len(r.ciphertext), truncateHex(r.ciphertext, 16)))
	v.AddNote("Only the ciphertext is sent. The shared secret never travels over the wire.")
	v.AddArrow()

	// Step 3: decapsulation (Alice).
	v.AddStep("Step 3: Alice decapsulates the shared secret")
	v.AddStep("------------------------------------------")
	v.AddStep("Alice feeds the ciphertext to her private key's Decapsulate() and recovers:")
	v.AddStep(fmt.Sprintf("• The same shared secret (32 bytes): %s", truncateHex(r.sharedAli, 32)))
	v.AddArrow()

	// Step 4: verify.
	v.AddStep("Step 4: Both sides now hold the same secret")
	v.AddStep("-----------------------------------------")
	if bytes.Equal(r.sharedBob, r.sharedAli) {
		v.AddStep("✅ Shared secrets match — Alice and Bob agreed on a key without sending it.")
	} else {
		return "", nil, fmt.Errorf("ML-KEM shared secrets did not match")
	}
	v.AddNote("As with Diffie-Hellman (menu 8) and X25519 (menu 9), the 32-byte shared secret")
	v.AddNote("is then fed to a KDF/AEAD (the 'KEM + DEM' pattern) to actually encrypt data.")
	v.AddSeparator()

	p.addSizes(v, r)
	p.addSecurityNotes(v)

	return fmt.Sprintf("ML-KEM-%d shared secret: %x", p.level, r.sharedBob), v.GetSteps(), nil
}

// --- explanatory sections --------------------------------------------------

func (p *MLKEMProcessor) addIntro(v *utils.Visualizer) {
	v.AddStep("📌 What is ML-KEM?")
	v.AddStep(fmt.Sprintf("ML-KEM (FIPS 203), formerly Kyber, is a POST-QUANTUM key encapsulation mechanism. Running ML-KEM-%d here.", p.level))
	v.AddStep("A KEM is a modern take on key agreement: instead of both sides doing math on a")
	v.AddStep("shared group (like DH), one side ENCAPSULATES a random secret against the other's")
	v.AddStep("public key, producing a ciphertext the owner can DECAPSULATE back to that secret.")
	v.AddNote("Like DH/X25519 this only agrees a shared key — it does not encrypt your data.")
	v.AddSeparator()

	v.AddStep("📈 Why post-quantum?")
	v.AddStep("A large quantum computer running Shor's algorithm would break RSA (menu 5) and")
	v.AddStep("elliptic-curve DH (X25519, menu 9) — the key exchanges securing the internet today.")
	v.AddStep("ML-KEM's security rests instead on the Module Learning-With-Errors (MLWE) lattice")
	v.AddStep("problem, for which no efficient quantum algorithm is known.")
	v.AddNote("'Harvest now, decrypt later': attackers record encrypted traffic today to break it")
	v.AddNote("once quantum computers arrive — which is why PQ key exchange is being deployed now.")
	v.AddSeparator()
}

func (p *MLKEMProcessor) addSizes(v *utils.Visualizer, r *mlkemRun) {
	v.AddStep("📚 Size is the trade-off")
	v.AddStep(fmt.Sprintf("ML-KEM-%d:  public key %d B, ciphertext %d B, shared secret 32 B", p.level, len(r.encapKey), len(r.ciphertext)))
	v.AddStep("X25519 (menu 9):  public key 32 B, shared secret 32 B")
	v.AddStep("Post-quantum keys and ciphertexts are ~30-50× larger. That extra bandwidth per")
	v.AddStep("handshake is the price of quantum resistance.")
	v.AddNote("ML-KEM-768 targets ~AES-192 security; ML-KEM-1024 targets ~AES-256.")
	v.AddSeparator()
}

func (p *MLKEMProcessor) addSecurityNotes(v *utils.Visualizer) {
	v.AddStep("🔒 Security notes")
	v.AddStep("• ML-KEM provides confidentiality of the agreed key, NOT authentication — pair it")
	v.AddStep("  with a signature (e.g. ML-DSA, menu 13) or certificate to stop MITM, exactly")
	v.AddStep("  as X25519 must be authenticated.")
	v.AddStep("• Real deployments use HYBRID key exchange (e.g. X25519 + ML-KEM-768, as in TLS 1.3's")
	v.AddStep("  X25519MLKEM768): the session stays safe if EITHER algorithm holds.")
	v.AddStep("• Use fresh (ephemeral) keys per session for forward secrecy.")
	v.AddStep("• Standardized by NIST in 2024 (FIPS 203); already shipping in Chrome, TLS libraries, and SSH.")
	v.AddNote("The 32-byte shared secret is a drop-in for the one from DH/X25519 — feed it to HKDF then AES/ChaCha20.")
}
