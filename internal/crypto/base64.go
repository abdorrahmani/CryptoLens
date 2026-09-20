package crypto

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// base64Alphabet is the standard Base64 index table (RFC 4648, §4). The value
// of a 6-bit group (0–63) is an INDEX into this string — not an ASCII code.
const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

type Base64Processor struct {
	BaseConfigurableProcessor
}

func NewBase64Processor() *Base64Processor {
	return &Base64Processor{}
}

// Configure implements the ConfigurableProcessor interface
func (p *Base64Processor) Configure(config map[string]interface{}) error {
	return p.BaseConfigurableProcessor.Configure(config)
}

func (p *Base64Processor) Process(text string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Validate operation type
	if operation != OperationEncrypt && operation != OperationDecrypt {
		return "", nil, fmt.Errorf("invalid operation: %s", operation)
	}

	addBase64Intro(v)
	addAlphabetTable(v)

	if operation == OperationDecrypt {
		return decodeBase64(v, text)
	}
	return encodeBase64(v, text)
}

// --- shared explanatory sections -------------------------------------------

func addBase64Intro(v *utils.Visualizer) {
	v.AddStep("📌 What is Base64?")
	v.AddStep("Base64 is a binary-to-text encoding: it represents arbitrary bytes using")
	v.AddStep("64 printable ASCII characters, so binary data can travel through text-only")
	v.AddStep("channels like email headers, URLs, JSON, and JWTs.")
	v.AddNote("Base64 is NOT encryption, hashing, or compression. It hides nothing — anyone")
	v.AddNote("can decode it — and it makes data about 33% larger. Use it for transport, not secrecy.")
	v.AddSeparator()

	v.AddStep("📈 The core idea: 3 bytes ↔ 4 characters")
	v.AddStep("3 bytes = 24 bits, and 24 bits divide evenly into 4 groups of 6 bits.")
	v.AddStep("Each 6-bit group is a number from 0 to 63 that selects one character from")
	v.AddStep("the Base64 alphabet. So every 3 input bytes become exactly 4 output characters.")
	v.AddSeparator()
}

func addAlphabetTable(v *utils.Visualizer) {
	v.AddStep("🔢 The Base64 alphabet (index → character)")
	v.AddStep(" 0-25  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z")
	v.AddStep("26-51  a b c d e f g h i j k l m n o p q r s t u v w x y z")
	v.AddStep("52-61  0 1 2 3 4 5 6 7 8 9")
	v.AddStep("62-63  +  /")
	v.AddStep("pad    =  (marks leftover space in the final block; not a data value)")
	v.AddNote("A 6-bit group picks a character by its INDEX above. This is different from the")
	v.AddNote("character's ASCII code (e.g. index 0 is 'A', whereas 'A' in ASCII is 65).")
	v.AddSeparator()
}

// --- encoding --------------------------------------------------------------

func encodeBase64(v *utils.Visualizer, text string) (string, []string, error) {
	v.AddStep("📈 Encoding steps")
	v.AddStep("1. Read the input as raw bytes")
	v.AddStep("2. Concatenate their 8-bit values into one long bit string")
	v.AddStep("3. Re-slice that bit string into 6-bit groups")
	v.AddStep("4. Map each group's value (0-63) to a Base64 character")
	v.AddStep("5. Pad the final block with '=' so the output length is a multiple of 4")
	v.AddSeparator()

	v.AddTextStep("Input Text", text)
	if len(text) == 0 {
		v.AddNote("Empty input encodes to an empty string.")
		return "", v.GetSteps(), nil
	}
	v.AddBinaryStep("Text as Binary", []byte(text))
	v.AddArrow()

	// Worked example on the first block — the heart of the transformation.
	addEncodeWorkedExample(v, []byte(text))

	// Concrete padding analysis for this specific input.
	addEncodePaddingAnalysis(v, len(text))

	encoded := base64.StdEncoding.EncodeToString([]byte(text))
	v.AddArrow()
	v.AddTextStep("Base64 Encoded Result", encoded)

	addBase64KeyFacts(v)
	return encoded, v.GetSteps(), nil
}

// addEncodeWorkedExample walks the first block (up to 3 bytes) bit by bit so the
// reader can see exactly how bytes become Base64 characters.
func addEncodeWorkedExample(v *utils.Visualizer, data []byte) {
	blk := data
	if len(blk) > 3 {
		blk = blk[:3]
	}

	label := fmt.Sprintf("📈 Worked example — first %d byte(s)", len(blk))
	if len(data) > 3 {
		label = "📈 Worked example — first 3 bytes"
	}
	v.AddStep(label)

	chars := make([]string, len(blk))
	decs := make([]string, len(blk))
	bins := make([]string, len(blk))
	for i, b := range blk {
		chars[i] = printableByte(b)
		decs[i] = strconv.Itoa(int(b))
		bins[i] = fmt.Sprintf("%08b", b)
	}
	v.AddStep(colRow("Character:", chars, 14, 11))
	v.AddStep(colRow("Decimal:", decs, 14, 11))
	v.AddStep(colRow("8-bit byte:", bins, 14, 11))

	allBits := strings.Join(bins, "")
	v.AddStep(fmt.Sprintf("Concatenate into %d bits:", len(allBits)))
	v.AddStep("  " + allBits)

	padZeros := (6 - len(allBits)%6) % 6
	padded := allBits + strings.Repeat("0", padZeros)
	groups := chunkString(padded, 6)
	v.AddStep("Re-slice into 6-bit groups:")
	v.AddStep("  " + strings.Join(groups, " "))
	if padZeros > 0 {
		v.AddNote(fmt.Sprintf("The final group was short, so %d zero bit(s) were appended to complete it.", padZeros))
	}

	idxs := make([]string, len(groups))
	outChars := make([]string, len(groups))
	for i, g := range groups {
		n, _ := strconv.ParseInt(g, 2, 64)
		idxs[i] = strconv.Itoa(int(n))
		outChars[i] = string(base64Alphabet[n])
	}
	v.AddStep(colRow("Group value:", idxs, 22, 5))
	v.AddStep(colRow("Base64 char:", outChars, 22, 5))

	if eq := paddingCount(len(blk)); eq > 0 {
		v.AddNote(fmt.Sprintf("This block holds only %d byte(s) of data, so %d '=' character(s) are appended as padding.", len(blk), eq))
	}
	v.AddSeparator()
}

func addEncodePaddingAnalysis(v *utils.Visualizer, n int) {
	v.AddStep("🔒 Padding for this input")
	r := n % 3
	v.AddStep(fmt.Sprintf("Input length = %d byte(s); %d mod 3 = %d.", n, n, r))
	switch r {
	case 0:
		v.AddStep("Remainder 0 → the data fills whole 3-byte blocks → no '=' padding.")
	case 1:
		v.AddStep("Remainder 1 → final block has 1 byte → 2 Base64 chars + '==' (two padding chars).")
	case 2:
		v.AddStep("Remainder 2 → final block has 2 bytes → 3 Base64 chars + '=' (one padding char).")
	}
	v.AddSeparator()
}

// --- decoding --------------------------------------------------------------

func decodeBase64(v *utils.Visualizer, text string) (string, []string, error) {
	v.AddStep("📈 Decoding steps (encoding in reverse)")
	v.AddStep("1. Drop the '=' padding markers")
	v.AddStep("2. Map each character back to its 6-bit index value")
	v.AddStep("3. Concatenate those 6-bit values into one bit string")
	v.AddStep("4. Re-slice the bits into 8-bit bytes (leftover padding bits are discarded)")
	v.AddStep("5. Interpret the bytes as text")
	v.AddSeparator()

	v.AddTextStep("Base64 Input", text)

	// Decode first so invalid input fails cleanly before the walkthrough.
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", nil, fmt.Errorf("invalid base64 string: %w", err)
	}

	if pad := strings.Count(text, "="); pad > 0 {
		v.AddNote(fmt.Sprintf("Input ends with %d '=' padding marker(s); these carry no data and are removed first.", pad))
	}
	v.AddArrow()

	if len(data) == 0 {
		v.AddNote("Empty (or padding-only) input decodes to an empty string.")
		v.AddTextStep("Decoded Text", "")
		return "", v.GetSteps(), nil
	}

	addDecodeWorkedExample(v, text)

	v.AddBinaryStep("Decoded Binary", data)
	v.AddArrow()
	v.AddTextStep("Decoded Text", string(data))

	addBase64KeyFacts(v)
	return string(data), v.GetSteps(), nil
}

// addDecodeWorkedExample walks the first block (up to 4 characters) back into bytes.
func addDecodeWorkedExample(v *utils.Visualizer, text string) {
	clean := strings.ReplaceAll(text, "=", "")
	block := clean
	if len(block) > 4 {
		block = block[:4]
	}
	if len(block) == 0 {
		return
	}

	v.AddStep(fmt.Sprintf("📈 Worked example — first %d character(s)", len(block)))

	chars := make([]string, len(block))
	idxs := make([]string, len(block))
	sixBits := make([]string, len(block))
	for i := 0; i < len(block); i++ {
		idx := strings.IndexByte(base64Alphabet, block[i])
		chars[i] = string(block[i])
		idxs[i] = strconv.Itoa(idx)
		sixBits[i] = fmt.Sprintf("%06b", idx)
	}
	v.AddStep(colRow("Character:", chars, 16, 9))
	v.AddStep(colRow("Index (0-63):", idxs, 16, 9))
	v.AddStep(colRow("6-bit value:", sixBits, 16, 9))

	allBits := strings.Join(sixBits, "")
	v.AddStep(fmt.Sprintf("Concatenate into %d bits:", len(allBits)))
	v.AddStep("  " + allBits)

	fullBytes := len(allBits) / 8
	byteGroups := chunkString(allBits, 8)
	kept := byteGroups
	leftover := 0
	if len(byteGroups) > fullBytes {
		kept = byteGroups[:fullBytes]
		leftover = len(byteGroups[fullBytes])
	}
	v.AddStep("Re-slice into 8-bit bytes:")
	v.AddStep("  " + strings.Join(kept, " "))
	if leftover > 0 {
		v.AddNote(fmt.Sprintf("%d leftover bit(s) remain; these are discarded padding bits, not data.", leftover))
	}

	byteChars := make([]string, len(kept))
	byteVals := make([]string, len(kept))
	for i, g := range kept {
		n, _ := strconv.ParseInt(g, 2, 64)
		byteVals[i] = strconv.Itoa(int(n))
		byteChars[i] = printableByte(byte(n))
	}
	v.AddStep(colRow("Byte value:", byteVals, 16, 9))
	v.AddStep(colRow("Character:", byteChars, 16, 9))
	v.AddSeparator()
}

// --- shared wrap-up --------------------------------------------------------

func addBase64KeyFacts(v *utils.Visualizer) {
	v.AddSeparator()
	v.AddStep("📚 Key facts")
	v.AddStep("• Each character carries 6 bits; 4 characters reconstruct 3 bytes.")
	v.AddStep("• Output length is always a multiple of 4; '=' pads the final block.")
	v.AddStep("• Size overhead is about 33% (4 output chars per 3 input bytes).")
	v.AddStep("• Base64URL swaps '+' and '/' for '-' and '_' (and often drops padding) so")
	v.AddStep("  the text is safe inside URLs — that is the variant JWTs use.")
	v.AddNote("Because decoding is trivial, never rely on Base64 to protect sensitive data.")
}

// --- small helpers ---------------------------------------------------------

// paddingCount returns how many '=' characters a final block of the given byte
// count produces (3 bytes → 0, 2 → 1, 1 → 2).
func paddingCount(blockBytes int) int {
	switch blockBytes {
	case 1:
		return 2
	case 2:
		return 1
	default:
		return 0
	}
}

// printableByte renders a byte as its character when printable, else as \xNN.
func printableByte(b byte) string {
	if b >= 0x20 && b < 0x7f {
		return string(b)
	}
	return fmt.Sprintf("\\x%02X", b)
}

// chunkString splits s into consecutive substrings of at most size runes.
func chunkString(s string, size int) []string {
	var out []string
	for i := 0; i < len(s); i += size {
		end := i + size
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}

// colRow renders a labeled row of aligned columns for the worked examples.
func colRow(label string, vals []string, labelWidth, valWidth int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-*s", labelWidth, label)
	for _, s := range vals {
		fmt.Fprintf(&b, "%-*s", valWidth, s)
	}
	return strings.TrimRight(b.String(), " ")
}
