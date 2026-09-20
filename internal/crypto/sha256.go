package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/bits"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// sha256InitialHash holds H0..H7, the eight 32-bit initial hash values defined
// in FIPS 180-4. Each is the first 32 bits of the fractional part of the square
// root of one of the first eight primes (2,3,5,7,11,13,17,19) — "nothing up my
// sleeve" numbers chosen to show the constants hide no backdoor.
var sha256InitialHash = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

type SHA256Processor struct {
	BaseConfigurableProcessor
}

func NewSHA256Processor() *SHA256Processor {
	return &SHA256Processor{}
}

// Configure implements the ConfigurableProcessor interface
func (p *SHA256Processor) Configure(config map[string]interface{}) error {
	return p.BaseConfigurableProcessor.Configure(config)
}

func (p *SHA256Processor) Process(text string, _ string) (string, []string, error) {
	v := utils.NewVisualizer()

	addSHA256Intro(v)

	// Input
	v.AddTextStep("Input Text", text)
	v.AddHexStep("Input as Bytes", []byte(text))
	v.AddStep(fmt.Sprintf("Input length: %d byte(s) = %d bits", len(text), len(text)*8))
	v.AddArrow()

	// Padding, computed for this specific input.
	addPaddingWalkthrough(v, len(text))

	// The hash itself.
	hash := sha256.Sum256([]byte(text))
	v.AddStep("📈 Digest")
	v.AddHexStep("SHA-256 (hex, 64 chars)", hash[:])
	encoded := base64.StdEncoding.EncodeToString(hash[:])
	v.AddTextStep("SHA-256 (Base64)", encoded)
	v.AddNote("The digest is always 32 bytes, no matter whether the input is one byte or a gigabyte.")
	v.AddSeparator()

	// The centerpiece: show the avalanche effect on the real input.
	addAvalancheDemo(v, text, hash)

	addInternals(v)
	addSHA256Security(v)
	addSHA256Uses(v)

	return encoded, v.GetSteps(), nil
}

// --- explanatory sections --------------------------------------------------

func addSHA256Intro(v *utils.Visualizer) {
	v.AddStep("📌 What is SHA-256?")
	v.AddStep("SHA-256 is a cryptographic HASH FUNCTION from the SHA-2 family, published by")
	v.AddStep("NIST in FIPS 180-4. It maps any input to a fixed 256-bit (32-byte) 'digest'")
	v.AddStep("that acts as a fingerprint of the data.")
	v.AddNote("Hashing is ONE-WAY: there is no decrypt. This menu only computes a digest —")
	v.AddNote("you cannot recover the input from it. That is the whole point of a hash.")
	v.AddSeparator()

	v.AddStep("🔢 Where it sits in the family")
	v.AddStep("• SHA-1  — 160-bit, BROKEN (practical collisions since 2017). Do not use.")
	v.AddStep("• SHA-2  — SHA-224/256/384/512. SHA-256 is the most common; still secure.")
	v.AddStep("• SHA-3  — a different design (Keccak), a backup family, not a replacement.")
	v.AddSeparator()

	v.AddStep("🔢 The four properties that make a hash cryptographic")
	v.AddStep("1. Deterministic  — same input always gives the same digest")
	v.AddStep("2. Fixed size     — any input maps to exactly 256 bits")
	v.AddStep("3. One-way        — infeasible to find an input for a given digest (pre-image)")
	v.AddStep("4. Collision-safe — infeasible to find two inputs with the same digest")
	v.AddStep("Plus the AVALANCHE effect: a one-bit input change flips about half the output bits.")
	v.AddSeparator()
}

// addPaddingWalkthrough computes and explains SHA-256 preprocessing for a
// message of the given byte length.
func addPaddingWalkthrough(v *utils.Visualizer, nBytes int) {
	msgBits := nBytes * 8
	afterOne := msgBits + 1
	// Zero bits needed so that (afterOne + k) ≡ 448 (mod 512).
	k := ((448 - (afterOne % 512)) + 512) % 512
	total := afterOne + k + 64
	blocks := total / 512

	v.AddStep("🔢 Step 1 — Preprocessing (padding)")
	v.AddStep("SHA-256 works on 512-bit blocks, so the message is padded to a multiple of 512:")
	v.AddStep(fmt.Sprintf("  a. Start with the message: %d bits", msgBits))
	v.AddStep("  b. Append a single '1' bit")
	v.AddStep(fmt.Sprintf("  c. Append %d '0' bits until the length is 448 mod 512", k))
	v.AddStep(fmt.Sprintf("  d. Append the original length (%d) as a 64-bit big-endian integer", msgBits))
	v.AddStep(fmt.Sprintf("  → padded to %d bits = %d block(s) of 512 bits", total, blocks))
	v.AddNote("Encoding the length in the padding is what stops different messages from")
	v.AddNote("colliding just because one is a padded version of another.")
	v.AddArrow()
}

// addAvalancheDemo hashes a one-bit variant of the input and reports how many
// of the 256 output bits changed — the avalanche effect, made concrete.
func addAvalancheDemo(v *utils.Visualizer, text string, hash [32]byte) {
	v.AddStep("📈 The avalanche effect (live)")

	orig := []byte(text)
	modified := make([]byte, len(orig))
	copy(modified, orig)

	var flippedNote string
	if len(modified) == 0 {
		// Nothing to flip; demonstrate on a canonical tiny example instead.
		a := sha256.Sum256([]byte("A"))
		b := sha256.Sum256([]byte("B"))
		diff := countDiffBits(a[:], b[:])
		v.AddStep("Input is empty, so compare two tiny inputs 'A' and 'B':")
		v.AddHexStep("  SHA-256(\"A\")", a[:])
		v.AddHexStep("  SHA-256(\"B\")", b[:])
		v.AddStep(fmt.Sprintf("  Bits changed: %d of 256 (%.1f%%)", diff, float64(diff)/256*100))
		v.AddNote("A minimal input change scrambles roughly half the output bits — no partial hints leak.")
		v.AddSeparator()
		return
	}

	// Flip the least-significant bit of the last byte.
	idx := len(modified) - 1
	before := modified[idx]
	modified[idx] ^= 0x01
	flippedNote = fmt.Sprintf("Flip one bit of the last byte: 0x%02X → 0x%02X", before, modified[idx])

	modHash := sha256.Sum256(modified)
	diff := countDiffBits(hash[:], modHash[:])

	v.AddStep(flippedNote)
	v.AddHexStep("  Original  digest", hash[:])
	v.AddHexStep("  1-bit-off digest", modHash[:])
	v.AddStep(fmt.Sprintf("  Bits changed: %d of 256 (%.1f%%)", diff, float64(diff)/256*100))
	v.AddNote("~50% of bits flip from a single-bit change. The digests are unrelated, so a hash")
	v.AddNote("leaks nothing about how 'close' two inputs are — vital for integrity checks.")
	v.AddSeparator()
}

// addInternals describes the compression that Go's crypto/sha256 performs.
func addInternals(v *utils.Visualizer) {
	v.AddStep("📚 Inside the compression (what crypto/sha256 does)")
	v.AddStep("Step 2 — Message schedule: expand each 512-bit block into 64 32-bit words")
	v.AddStep("         W[0..63] using rotations, shifts and XOR (σ0/σ1 functions).")
	v.AddStep("Step 3 — Compression: load 8 working variables (a..h) from the current hash,")
	v.AddStep("         run 64 rounds mixing them with W[t] and round constants K[t]")
	v.AddStep("         (Ch, Maj, Σ0, Σ1 functions), then add the result back into the hash.")
	v.AddStep("Step 4 — Output: after the last block, concatenate H0..H7 → the 256-bit digest.")
	v.AddStep("Initial hash values H0..H7 (fractional parts of √of the first 8 primes):")
	v.AddStep("  " + formatInitialHash())
	v.AddNote("These 'nothing-up-my-sleeve' constants come from primes so no hidden structure")
	v.AddNote("could have been planted in them.")
	v.AddSeparator()
}

func addSHA256Security(v *utils.Visualizer) {
	v.AddStep("🔒 Security notes")
	v.AddStep("• Collision resistance ≈ 2^128 work; pre-image ≈ 2^256. Both are out of reach.")
	v.AddStep("• Length-extension weakness: given SHA-256(secret‖msg) and the length, an")
	v.AddStep("  attacker can compute SHA-256(secret‖msg‖pad‖extra) WITHOUT the secret. So")
	v.AddStep("  never authenticate by hashing key‖message — use HMAC (menu 6) instead.")
	v.AddStep("• Too fast for passwords: attackers try billions/sec. Use a slow KDF —")
	v.AddStep("  PBKDF2/Argon2id/Scrypt with a salt (menu 7) — not bare SHA-256.")
	v.AddNote("SHA-256 itself is unbroken; the pitfalls above come from using it in the wrong role.")
	v.AddSeparator()
}

func addSHA256Uses(v *utils.Visualizer) {
	v.AddStep("📚 Where SHA-256 is used")
	v.AddStep("• File/download integrity checksums and Git commit identifiers")
	v.AddStep("• Digital signatures (sign the hash, not the whole document)")
	v.AddStep("• Proof-of-work in Bitcoin and other blockchains")
	v.AddStep("• As the building block inside HMAC-SHA256 and many KDFs")
}

// --- helpers ---------------------------------------------------------------

// countDiffBits returns the Hamming distance (number of differing bits) between
// two equal-length byte slices.
func countDiffBits(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	total := 0
	for i := 0; i < n; i++ {
		total += bits.OnesCount8(a[i] ^ b[i])
	}
	return total
}

// formatInitialHash renders H0..H7 as space-separated hex words.
func formatInitialHash() string {
	out := make([]byte, 0, 8*9)
	for i, h := range sha256InitialHash {
		if i > 0 {
			out = append(out, ' ')
		}
		var word [4]byte
		word[0] = byte(h >> 24)
		word[1] = byte(h >> 16)
		word[2] = byte(h >> 8)
		word[3] = byte(h)
		out = append(out, []byte(hex.EncodeToString(word[:]))...)
	}
	return string(out)
}
