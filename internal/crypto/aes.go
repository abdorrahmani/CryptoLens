package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// maxBlocksShown caps how many 16-byte blocks are printed individually so long
// inputs don't flood the view.
const maxBlocksShown = 6

type AESProcessor struct {
	BaseConfigurableProcessor
	keyManager KeyManager
	keySize    int
}

func NewAESProcessor() *AESProcessor {
	return &AESProcessor{
		keySize: 256, // Default to AES-256
	}
}

// Configure implements the ConfigurableProcessor interface
func (p *AESProcessor) Configure(config map[string]interface{}) error {
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
		case 128, 192, 256:
			p.keySize = keySize
		default:
			return fmt.Errorf("invalid key size: %d (must be 128, 192, or 256)", keySize)
		}
	}

	// Configure key file if provided
	keyFile := "keys/aes_key.bin"
	if kf, ok := config["keyFile"].(string); ok {
		keyFile = kf
	}

	// Initialize key manager
	p.keyManager = NewFileKeyManager(p.keySize, keyFile)
	if err := p.keyManager.LoadOrGenerateKey(); err != nil {
		return fmt.Errorf("failed to load/generate key: %w", err)
	}

	return nil
}

// rounds returns the number of AES rounds for the configured key size.
func (p *AESProcessor) rounds() int {
	switch p.keySize {
	case 192:
		return 12
	case 256:
		return 14
	default:
		return 10
	}
}

func (p *AESProcessor) Process(text string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Check for empty input
	if text == "" {
		return "", nil, fmt.Errorf("empty input")
	}

	// Validate operation type
	if operation != OperationEncrypt && operation != OperationDecrypt {
		return "", nil, fmt.Errorf("invalid operation: %s", operation)
	}

	p.addIntro(v)

	if operation == OperationDecrypt {
		return p.decrypt(v, text)
	}
	return p.encrypt(v, text)
}

// --- shared explanation ----------------------------------------------------

func (p *AESProcessor) addIntro(v *utils.Visualizer) {
	v.AddStep("📌 What is AES?")
	v.AddStep("AES (Advanced Encryption Standard), originally the Rijndael cipher, was")
	v.AddStep("standardized by NIST in 2001 (FIPS-197). It is a SYMMETRIC cipher: the same")
	v.AddStep("secret key both encrypts and decrypts. It is the workhorse of modern")
	v.AddStep("encryption — TLS, disk encryption, VPNs, and messaging all rely on it.")
	v.AddSeparator()

	v.AddStep("🔢 Two separate pieces: the block cipher and the mode")
	v.AddStep("• AES itself only transforms one fixed 16-byte (128-bit) BLOCK at a time.")
	v.AddStep("• A MODE OF OPERATION (here CBC) chains those blocks so messages of any")
	v.AddStep("  length can be encrypted. Choosing the mode well is as important as the cipher.")
	v.AddSeparator()

	v.AddStep("🔢 This configuration")
	v.AddStep(fmt.Sprintf("Key size:    %d bits (AES-%d)", p.keySize, p.keySize))
	v.AddStep(fmt.Sprintf("Rounds:      %d transformation rounds", p.rounds()))
	v.AddStep(fmt.Sprintf("Block size:  %d bytes (fixed for all AES variants)", aes.BlockSize))
	v.AddStep("Mode:        CBC (Cipher Block Chaining)")
	v.AddStep("Padding:     PKCS#7")
	v.AddNote("A larger key means more rounds (10/12/14 for 128/192/256), not a bigger block.")
	v.AddSeparator()
}

// addInternals describes what one AES block transformation does. This runs
// inside Go's crypto/aes; it is shown for understanding, not executed here.
func (p *AESProcessor) addInternals(v *utils.Visualizer) {
	v.AddSeparator()
	v.AddStep("📚 Inside one AES block (what crypto/aes does per block)")
	v.AddStep("The 16-byte block is arranged as a 4x4 byte matrix (the 'state') and put")
	v.AddStep(fmt.Sprintf("through %d rounds. Each middle round applies four steps:", p.rounds()))
	v.AddStep("  1. SubBytes   — replace every byte via a fixed non-linear S-box (confusion)")
	v.AddStep("  2. ShiftRows  — rotate the matrix rows by 0,1,2,3 (diffusion across columns)")
	v.AddStep("  3. MixColumns — mix each column with a linear transform (diffusion within)")
	v.AddStep("  4. AddRoundKey— XOR in this round's key from the key schedule")
	v.AddStep("The first round is AddRoundKey only; the final round omits MixColumns.")
	v.AddNote("Confusion + diffusion, repeated over many rounds, is what makes the output")
	v.AddNote("look random and resist analysis. This tool does not need to re-implement it.")
}

// --- encryption ------------------------------------------------------------

func (p *AESProcessor) encrypt(v *utils.Visualizer, text string) (string, []string, error) {
	v.AddStep("📈 Encryption steps")
	v.AddStep("1. Convert the text to bytes")
	v.AddStep("2. Apply PKCS#7 padding to reach a multiple of 16 bytes")
	v.AddStep("3. Generate a fresh random IV (initialization vector)")
	v.AddStep("4. Encrypt block-by-block in CBC mode (each block XORed with the previous)")
	v.AddStep("5. Prepend the IV to the ciphertext and Base64-encode the whole thing")
	v.AddSeparator()

	v.AddTextStep("Input Text", text)
	v.AddHexStep("Input as Bytes", []byte(text))
	v.AddArrow()

	// PKCS#7 padding, explained concretely for this input.
	p.addPaddingExplanation(v, len(text))
	paddedText := p.pad([]byte(text))
	v.AddHexStep("Padded Input", paddedText)
	v.AddStep(fmt.Sprintf("Padded length: %d bytes = %d block(s) of 16", len(paddedText), len(paddedText)/aes.BlockSize))
	v.AddArrow()

	// IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", nil, fmt.Errorf("failed to generate IV: %v", err)
	}
	v.AddHexStep("Generated IV (random, 16 bytes)", iv)
	v.AddNote("The IV is not secret, but it MUST be unpredictable and never reused with the")
	v.AddNote("same key — reusing an IV in CBC leaks whether two messages share a prefix.")
	v.AddArrow()

	block, err := aes.NewCipher(p.keyManager.GetKey())
	if err != nil {
		return "", nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	// CBC chaining, demonstrated on the real first block.
	p.addCBCEncryptExplanation(v, paddedText, iv)

	ciphertext := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedText)
	p.addBlocks(v, "Ciphertext blocks", ciphertext)
	v.AddArrow()

	result := make([]byte, len(iv)+len(ciphertext))
	copy(result, iv)
	copy(result[len(iv):], ciphertext)
	v.AddStep("Prepend IV so the decrypter can recover it:")
	v.AddHexStep("IV || Ciphertext", result)
	v.AddArrow()

	encoded := base64.StdEncoding.EncodeToString(result)
	v.AddTextStep("Base64 Encoded Result", encoded)

	p.addInternals(v)
	p.addSecurityNotes(v)
	return encoded, v.GetSteps(), nil
}

// addPaddingExplanation shows exactly how many PKCS#7 bytes this input needs.
func (p *AESProcessor) addPaddingExplanation(v *utils.Visualizer, n int) {
	pad := aes.BlockSize - (n % aes.BlockSize)
	v.AddStep("🔢 PKCS#7 padding")
	v.AddStep("AES-CBC needs the input length to be a whole number of 16-byte blocks.")
	v.AddStep(fmt.Sprintf("Input is %d byte(s); %d mod 16 = %d, so %d byte(s) of padding are added.",
		n, n, n%aes.BlockSize, pad))
	v.AddStep(fmt.Sprintf("PKCS#7 fills the gap with the pad length itself: %d copies of 0x%02X.", pad, pad))
	v.AddNote("Even when the input is already a multiple of 16, a FULL extra block of 0x10 is")
	v.AddNote("added, so the decrypter can always tell padding apart from real data.")
}

// addCBCEncryptExplanation demonstrates the XOR chaining on the first block.
func (p *AESProcessor) addCBCEncryptExplanation(v *utils.Visualizer, padded, iv []byte) {
	v.AddStep("🔒 CBC mode: chaining the blocks")
	v.AddStep("Each plaintext block is XORed with the previous ciphertext block before")
	v.AddStep("encryption; the very first block uses the IV in place of a previous block:")
	v.AddStep("  C[1] = AES_encrypt(P[1] XOR IV)")
	v.AddStep("  C[i] = AES_encrypt(P[i] XOR C[i-1])   for i > 1")

	first := padded[:aes.BlockSize]
	xored := xorBytes(first, iv)
	v.AddHexStep("  P[1]        ", first)
	v.AddHexStep("  IV          ", iv)
	v.AddHexStep("  P[1] XOR IV ", xored)
	v.AddStep("  → this XOR result is what AES actually encrypts into C[1].")
	v.AddNote("Chaining means identical plaintext blocks encrypt differently, which is why")
	v.AddNote("CBC hides patterns that ECB mode famously leaks (see Attack Simulations).")
	v.AddArrow()
}

// --- decryption ------------------------------------------------------------

func (p *AESProcessor) decrypt(v *utils.Visualizer, text string) (string, []string, error) {
	v.AddStep("📈 Decryption steps (encryption in reverse)")
	v.AddStep("1. Base64-decode the input")
	v.AddStep("2. Split off the first 16 bytes as the IV")
	v.AddStep("3. Decrypt each block in CBC mode, XORing with the previous ciphertext block")
	v.AddStep("4. Strip the PKCS#7 padding")
	v.AddStep("5. Interpret the bytes as text")
	v.AddSeparator()

	v.AddTextStep("Encrypted Input (Base64)", text)
	v.AddArrow()

	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", nil, fmt.Errorf("invalid base64 string: %w", err)
	}
	v.AddHexStep("Decoded Bytes", data)
	v.AddArrow()

	if len(data) < aes.BlockSize {
		return "", nil, fmt.Errorf("ciphertext too short: need at least %d bytes for the IV", aes.BlockSize)
	}
	if (len(data)-aes.BlockSize)%aes.BlockSize != 0 || len(data) == aes.BlockSize {
		return "", nil, fmt.Errorf("ciphertext length is not a whole number of 16-byte blocks")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]
	v.AddHexStep("Extracted IV (first 16 bytes)", iv)
	p.addBlocks(v, "Ciphertext blocks", ciphertext)
	v.AddArrow()

	block, err := aes.NewCipher(p.keyManager.GetKey())
	if err != nil {
		return "", nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	v.AddStep("🔒 CBC decryption formula")
	v.AddStep("  P[1] = AES_decrypt(C[1]) XOR IV")
	v.AddStep("  P[i] = AES_decrypt(C[i]) XOR C[i-1]   for i > 1")
	v.AddNote("The wrong key or a corrupted IV yields random-looking bytes and usually a")
	v.AddNote("padding error — CBC has no built-in way to prove the data is authentic.")
	v.AddArrow()

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	v.AddHexStep("Decrypted Bytes (padding still attached)", plaintext)
	v.AddArrow()

	unpadded, err := p.unpad(plaintext)
	if err != nil {
		return "", nil, fmt.Errorf("failed to unpad: %w", err)
	}
	pad := len(plaintext) - len(unpadded)
	v.AddStep(fmt.Sprintf("PKCS#7: last byte is 0x%02X, so the final %d byte(s) are padding and removed.", pad, pad))
	v.AddHexStep("Unpadded Bytes", unpadded)
	v.AddArrow()
	v.AddTextStep("Decrypted Text", string(unpadded))

	p.addSecurityNotes(v)
	return string(unpadded), v.GetSteps(), nil
}

// --- shared wrap-up --------------------------------------------------------

func (p *AESProcessor) addSecurityNotes(v *utils.Visualizer) {
	v.AddSeparator()
	v.AddStep("📚 Security notes")
	v.AddStep("• Keep the key secret; anyone with it can decrypt. This tool stores it under")
	v.AddStep("  keys/ for the demo only — real systems use a KMS or OS keystore.")
	v.AddStep("• Use a fresh, unpredictable IV per message; never reuse an IV with one key.")
	v.AddStep("• CBC provides CONFIDENTIALITY but NOT authenticity: an attacker can flip")
	v.AddStep("  ciphertext bits, and CBC padding checks enable padding-oracle attacks.")
	v.AddStep("• For real use prefer an AEAD mode — AES-GCM or ChaCha20-Poly1305 (menu 11) —")
	v.AddStep("  which encrypts AND authenticates in one step.")
	v.AddNote("AES the cipher is unbroken; most real-world failures come from misusing the mode.")
}

// --- block/byte helpers ----------------------------------------------------

// addBlocks prints data split into 16-byte blocks, capped for long inputs.
func (p *AESProcessor) addBlocks(v *utils.Visualizer, label string, data []byte) {
	total := len(data) / aes.BlockSize
	v.AddStep(fmt.Sprintf("%s (%d block(s) of 16 bytes):", label, total))
	shown := total
	if shown > maxBlocksShown {
		shown = maxBlocksShown
	}
	for i := 0; i < shown; i++ {
		blk := data[i*aes.BlockSize : (i+1)*aes.BlockSize]
		v.AddHexStep(fmt.Sprintf("  block %d", i+1), blk)
	}
	if total > shown {
		v.AddNote(fmt.Sprintf("… and %d more block(s) not shown.", total-shown))
	}
}

func (p *AESProcessor) pad(data []byte) []byte {
	padding := aes.BlockSize - (len(data) % aes.BlockSize)
	padtext := make([]byte, len(data)+padding)
	copy(padtext, data)
	for i := len(data); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}
	return padtext
}

// unpad removes and validates PKCS#7 padding. It checks every padding byte (not
// just the last) so malformed padding is rejected, and uses a constant-time
// compare to avoid leaking where the mismatch occurred.
func (p *AESProcessor) unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("data length is not a multiple of the block size")
	}
	padding := int(data[len(data)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	expected := make([]byte, padding)
	for i := range expected {
		expected[i] = byte(padding)
	}
	if subtle.ConstantTimeCompare(data[len(data)-padding:], expected) != 1 {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:len(data)-padding], nil
}
