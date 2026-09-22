package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// Supported password-based key derivation functions.
const (
	AlgoPBKDF2   = "pbkdf2"
	AlgoArgon2id = "argon2id"
	AlgoScrypt   = "scrypt"
)

// Fixed scrypt cost parameters (interactive-login strength).
const (
	scryptN = 32768 // CPU/memory cost, must be a power of two
	scryptR = 8     // block size
	scryptP = 1     // parallelization
)

// PBKDFProcessor implements password-based key derivation
type PBKDFProcessor struct {
	BaseConfigurableProcessor
	keyManager KeyManager
	algorithm  string
	iterations int    // PBKDF2 iteration count
	argonTime  uint32 // Argon2id time (pass) parameter
	memory     uint32 // Argon2id memory in KiB
	threads    uint8  // Argon2id parallelism
	keyLength  uint32 // derived key length in bytes
	saltSize   int
}

// NewPBKDFProcessor creates a new PBKDF processor
func NewPBKDFProcessor() *PBKDFProcessor {
	return &PBKDFProcessor{
		algorithm:  AlgoPBKDF2,
		iterations: 100000, // Default PBKDF2 iterations
		argonTime:  3,      // Argon2id passes (kept small; unrelated to PBKDF2 iterations)
		memory:     65536,  // 64 MiB for Argon2id
		threads:    4,
		keyLength:  32, // 256-bit derived key
		saltSize:   16, // Default salt size
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *PBKDFProcessor) Configure(config map[string]interface{}) error {
	if err := p.BaseConfigurableProcessor.Configure(config); err != nil {
		return err
	}

	// Configure algorithm if provided
	if algo, ok := config["algorithm"].(string); ok && algo != "" {
		switch algo {
		case AlgoPBKDF2, AlgoArgon2id, AlgoScrypt:
			p.algorithm = algo
		default:
			return fmt.Errorf("unsupported PBKDF algorithm: %s (must be one of: pbkdf2, argon2id, scrypt)", algo)
		}
	}

	// Configure iterations if provided
	if iter, ok := config["iterations"].(int); ok {
		p.iterations = iter
	}

	// Configure Argon2id memory / threads if provided (accept common numeric types).
	if m, ok := toUint32(config["memory"]); ok {
		p.memory = m
	}
	if t, ok := config["threads"]; ok {
		if tv, ok := toUint32(t); ok && tv > 0 {
			p.threads = uint8(tv)
		}
	}
	if kl, ok := toUint32(config["keyLength"]); ok && kl > 0 {
		p.keyLength = kl
	}

	// Configure salt size if provided
	if size, ok := config["saltSize"].(int); ok {
		p.saltSize = size
	}

	// Configure key file if provided
	keyFile := "keys/pbkdf_key.bin"
	if kf, ok := config["keyFile"].(string); ok {
		keyFile = kf
	}

	// Initialize key manager
	p.keyManager = NewFileKeyManager(256, keyFile)
	if err := p.keyManager.LoadOrGenerateKey(); err != nil {
		return fmt.Errorf("failed to load/generate key: %w", err)
	}

	return nil
}

// toUint32 converts common numeric config types to uint32.
func toUint32(v interface{}) (uint32, bool) {
	switch n := v.(type) {
	case int:
		if n < 0 {
			return 0, false
		}
		return uint32(n), true
	case uint32:
		return n, true
	case uint8:
		return uint32(n), true
	case int64:
		if n < 0 {
			return 0, false
		}
		return uint32(n), true
	default:
		return 0, false
	}
}

// Process handles password-based key derivation
func (p *PBKDFProcessor) Process(text string, _ string) (string, []string, error) {
	v := utils.NewVisualizer()

	p.addIntro(v)
	p.addWhyKDF(v)
	p.addPasswordStrength(v, text)

	// Salt.
	salt := make([]byte, p.saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	v.AddStep("🔢 Step 1 — Generate a random salt")
	v.AddStep(fmt.Sprintf("A fresh %d-byte random salt is created for THIS password.", p.saltSize))
	v.AddHexStep("Salt", salt)
	v.AddNote("The salt is not secret — store it next to the hash. Its job is to make every")
	v.AddNote("password's hash unique, so one precomputed rainbow table cannot crack many users.")
	v.AddArrow()

	// Derive with the selected algorithm.
	v.AddStep(fmt.Sprintf("🔢 Step 2 — Stretch the password with %s", p.algorithm))
	p.addAlgorithmParams(v)

	start := time.Now()
	derivedKey, err := p.derive([]byte(text), salt)
	if err != nil {
		return "", nil, err
	}
	duration := time.Since(start)
	v.AddArrow()

	v.AddStep("📈 Result")
	v.AddHexStep(fmt.Sprintf("Derived key (%d bytes)", len(derivedKey)), derivedKey)
	encoded := base64.StdEncoding.EncodeToString(derivedKey)
	v.AddTextStep("Derived key (Base64)", encoded)
	v.AddStep(fmt.Sprintf("Derivation took %v on this machine.", duration.Round(time.Microsecond)))
	v.AddNote("Aim for ~100–500 ms per derivation: slow enough to punish attackers, fast enough")
	v.AddNote("for a real login. Tune the cost parameters to hit that on your hardware.")
	v.AddSeparator()

	p.addAlgorithmComparison(v)
	p.addSecurityNotes(v)

	return encoded, v.GetSteps(), nil
}

// derive runs the selected KDF.
func (p *PBKDFProcessor) derive(password, salt []byte) ([]byte, error) {
	switch p.algorithm {
	case AlgoArgon2id:
		return argon2.IDKey(password, salt, p.argonTime, p.memory, p.threads, p.keyLength), nil
	case AlgoScrypt:
		key, err := scrypt.Key(password, salt, scryptN, scryptR, scryptP, int(p.keyLength))
		if err != nil {
			return nil, fmt.Errorf("scrypt derivation failed: %w", err)
		}
		return key, nil
	case AlgoPBKDF2:
		fallthrough
	default:
		return pbkdf2.Key(password, salt, p.iterations, int(p.keyLength), sha256.New), nil
	}
}

// --- explanatory sections --------------------------------------------------

func (p *PBKDFProcessor) addIntro(v *utils.Visualizer) {
	v.AddStep("📌 What is a password-based KDF?")
	v.AddStep("A KDF turns a human password into a fixed-length cryptographic key, deliberately")
	v.AddStep("SLOWLY. It is how passwords should be stored and how passphrases become AES keys.")
	v.AddStep(fmt.Sprintf("This run uses: %s", p.algorithm))
	v.AddNote("Like a hash, a KDF is ONE-WAY — you store the derived key, never the password,")
	v.AddNote("and check a login by re-deriving and comparing.")
	v.AddSeparator()
}

func (p *PBKDFProcessor) addWhyKDF(v *utils.Visualizer) {
	v.AddStep("📈 Why not just SHA-256 the password?")
	v.AddStep("A plain hash (menu 4) is built to be FAST — billions of guesses per second on a")
	v.AddStep("GPU. That speed is exactly wrong for passwords. A KDF fixes two things:")
	v.AddStep("  • SALT — a unique random value per password, so identical passwords get")
	v.AddStep("    different hashes and precomputed 'rainbow tables' are useless.")
	v.AddStep("  • WORK FACTOR — a tunable cost (iterations / memory) that makes each guess")
	v.AddStep("    expensive, so brute force (see menu 12) becomes impractical.")
	v.AddNote("Bare SHA-256 has neither: no salt, and far too fast. Never store passwords with it.")
	v.AddSeparator()
}

func (p *PBKDFProcessor) addPasswordStrength(v *utils.Visualizer, text string) {
	warned := false
	if len(text) < 8 {
		v.AddStep("⚠️  Password is very short (< 8 chars) — highly vulnerable to brute force.")
		v.AddStep("    Recommendation: use at least 12–16 characters or a passphrase.")
		warned = true
	} else if len(text) < 12 {
		v.AddStep("⚠️  Password could be stronger — aim for at least 12 characters.")
		warned = true
	}
	if isCommonPassword(text) {
		v.AddStep("⚠️  This looks like a common or trivial password pattern.")
		v.AddStep("    A KDF slows attackers, but a weak password is still guessed first.")
		warned = true
	}
	if warned {
		v.AddNote("A KDF buys time; it cannot rescue a genuinely weak password.")
		v.AddSeparator()
	}
}

func (p *PBKDFProcessor) addAlgorithmParams(v *utils.Visualizer) {
	switch p.algorithm {
	case AlgoArgon2id:
		v.AddStep("Argon2id — memory-hard; winner of the 2015 Password Hashing Competition.")
		v.AddStep(fmt.Sprintf("  time (passes): %d", p.argonTime))
		v.AddStep(fmt.Sprintf("  memory:        %d KiB (~%d MiB)", p.memory, p.memory/1024))
		v.AddStep(fmt.Sprintf("  parallelism:   %d thread(s)", p.threads))
		v.AddStep(fmt.Sprintf("  key length:    %d bytes", p.keyLength))
		v.AddNote("Memory-hardness resists GPU/ASIC cracking: attackers need lots of RAM per guess.")
	case AlgoScrypt:
		v.AddStep("scrypt — memory-hard (2009), widely used (e.g. in cryptocurrencies).")
		v.AddStep(fmt.Sprintf("  N (CPU/mem cost): %d", scryptN))
		v.AddStep(fmt.Sprintf("  r (block size):   %d", scryptR))
		v.AddStep(fmt.Sprintf("  p (parallelism):  %d", scryptP))
		v.AddStep(fmt.Sprintf("  key length:       %d bytes", p.keyLength))
		v.AddNote("Roughly N·r·128 bytes of memory per guess — here about 32 MiB.")
	default:
		v.AddStep("PBKDF2-SHA256 — iteration-based (RFC 8018); just HMAC repeated many times.")
		v.AddStep(fmt.Sprintf("  iterations: %d (each is one HMAC-SHA256, see menu 6)", p.iterations))
		v.AddStep(fmt.Sprintf("  key length: %d bytes", p.keyLength))
		v.AddNote("PBKDF2 is only CPU-hard, not memory-hard, so it is the weakest of the three")
		v.AddNote("against GPU/ASIC attackers — but it is simple and FIPS-approved.")
	}
}

func (p *PBKDFProcessor) addAlgorithmComparison(v *utils.Visualizer) {
	v.AddStep("📚 The three algorithms")
	v.AddStep("Algorithm   Hardness         Cost knobs             Verdict")
	v.AddStep("PBKDF2      CPU only         iterations             OK/legacy; FIPS-approved")
	v.AddStep("scrypt      CPU + memory     N, r, p                Good; memory-hard")
	v.AddStep("Argon2id    CPU + memory     time, memory, threads  Best; modern default")
	v.AddStep(fmt.Sprintf("→ currently selected: %s", p.algorithm))
	v.AddNote("For new systems prefer Argon2id. Run menu 7 → Run Benchmark to compare timings.")
	v.AddSeparator()
}

func (p *PBKDFProcessor) addSecurityNotes(v *utils.Visualizer) {
	v.AddStep("🔒 Security notes")
	v.AddStep("• Store only (algorithm, parameters, salt, derived key) — NEVER the password.")
	v.AddStep("• Use a unique random salt per password (done automatically here).")
	v.AddStep("• Tune cost so derivation takes ~100–500 ms; raise it as hardware improves.")
	v.AddStep("• A KDF also converts a passphrase into a symmetric key for AES (menu 3).")
	v.AddStep("• Verify a login by re-deriving with the stored salt/params and comparing in")
	v.AddStep("  constant time — the same discipline as HMAC (menu 6).")
	v.AddNote("PBKDF2 is literally HMAC repeated, tying this directly back to menu 6.")
}

// isCommonPassword checks if the password matches common patterns
func isCommonPassword(password string) bool {
	// Convert to lowercase for case-insensitive comparison
	lowerPass := strings.ToLower(password)

	// List of common passwords and patterns
	commonPasswords := []string{
		"password", "123456", "qwerty", "admin", "welcome",
		"letmein", "monkey", "dragon", "baseball", "football",
		"abc123", "111111", "123123", "12345678", "123456789",
		"1234567890", "qwerty123", "password123", "admin123",
	}

	// Check against common passwords
	for _, common := range commonPasswords {
		if lowerPass == common {
			return true
		}
	}

	// Check for sequential numbers
	if matched, _ := regexp.MatchString(`^[0-9]+$`, password); matched {
		return true
	}

	// Check for repeated characters
	for i := 0; i < len(password)-2; i++ {
		if password[i] == password[i+1] && password[i] == password[i+2] {
			return true
		}
	}

	return false
}
