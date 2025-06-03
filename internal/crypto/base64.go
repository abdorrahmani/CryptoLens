package crypto

import (
	"encoding/base64"
	"fmt"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

type Base64Processor struct {
	BaseConfigurableProcessor
	paddingChar string
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

	// Add introduction
	v.AddStep("Base64 Encoding/Decoding Process")
	v.AddStep("=============================")
	v.AddNote("Base64 is a binary-to-text encoding scheme")
	v.AddNote("It represents binary data in an ASCII string format")
	v.AddSeparator()

	// Show Base64 alphabet with ASCII values
	v.AddStep("Base64 Alphabet (with ASCII values):")
	v.AddStep("A-Z (65-90):  A(65) B(66) C(67) D(68) E(69) F(70) G(71) H(72) I(73) J(74) K(75) L(76) M(77)")
	v.AddStep("              N(78) O(79) P(80) Q(81) R(82) S(83) T(84) U(85) V(86) W(87) X(88) Y(89) Z(90)")
	v.AddStep("a-z (97-122): a(97) b(98) c(99) d(100) e(101) f(102) g(103) h(104) i(105) j(106) k(107) l(108) m(109)")
	v.AddStep("              n(110) o(111) p(112) q(113) r(114) s(115) t(116) u(117) v(118) w(119) x(120) y(121) z(122)")
	v.AddStep("0-9 (48-57):  0(48) 1(49) 2(50) 3(51) 4(52) 5(53) 6(54) 7(55) 8(56) 9(57)")
	v.AddStep("Special:      +(43) /(47) =(61)")
	v.AddSeparator()

	if operation == OperationDecrypt {
		// Add decoding steps
		v.AddStep("Decoding Process:")
		v.AddStep("1. Remove padding characters (=)")
		v.AddStep("2. Convert Base64 characters to 6-bit values")
		v.AddStep("3. Group 6-bit values into 8-bit bytes")
		v.AddStep("4. Convert bytes to text")
		v.AddSeparator()

		// Show input
		v.AddTextStep("Base64 Input", text)
		v.AddArrow()

		// Show ASCII values of input
		v.AddStep("ASCII Values of Input:")
		for _, char := range text {
			v.AddStep(fmt.Sprintf("'%c' = %d", char, int(char)))
		}
		v.AddArrow()

		// Decode from base64
		data, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return "", nil, fmt.Errorf("invalid base64 string: %w", err)
		}

		// Show binary representation
		v.AddBinaryStep("Decoded Binary", data)
		v.AddArrow()

		// Show ASCII values of decoded data
		v.AddStep("ASCII Values of Decoded Data:")
		for _, b := range data {
			v.AddStep(fmt.Sprintf("'%c' = %d", b, b))
		}
		v.AddArrow()

		// Show final result
		v.AddTextStep("Decoded Text", string(data))

		// Add how it works
		v.AddSeparator()
		v.AddStep("How Base64 Decoding Works:")
		v.AddStep("1. Each Base64 character represents 6 bits")
		v.AddStep("2. Four Base64 characters = 24 bits = 3 bytes")
		v.AddStep("3. Padding (=) is used when input length is not divisible by 3")
		v.AddStep("4. The last group may have 1 or 2 padding characters")
		v.AddNote("Base64 encoding is reversible - the original data can be recovered")

		return string(data), v.GetSteps(), nil
	}

	// Add encoding steps
	v.AddStep("Encoding Process:")
	v.AddStep("1. Convert text to bytes")
	v.AddStep("2. Group bytes into 6-bit chunks")
	v.AddStep("3. Convert 6-bit chunks to Base64 characters")
	v.AddStep("4. Add padding if needed")
	v.AddSeparator()

	// Show input
	v.AddTextStep("Input Text", text)
	v.AddArrow()

	// Show ASCII values of input
	v.AddStep("ASCII Values of Input:")
	for _, char := range text {
		v.AddStep(fmt.Sprintf("'%c' = %d", char, int(char)))
	}
	v.AddArrow()

	// Show binary representation
	v.AddBinaryStep("Text as Binary", []byte(text))
	v.AddArrow()

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString([]byte(text))
	v.AddTextStep("Base64 Encoded Result", encoded)

	// Show ASCII values of encoded result
	v.AddStep("ASCII Values of Encoded Result:")
	for _, char := range encoded {
		v.AddStep(fmt.Sprintf("'%c' = %d", char, int(char)))
	}

	// Add how it works
	v.AddSeparator()
	v.AddStep("How Base64 Encoding Works:")
	v.AddStep("1. Take 3 bytes (24 bits) of input")
	v.AddStep("2. Split into 4 groups of 6 bits")
	v.AddStep("3. Convert each 6-bit group to a Base64 character")
	v.AddStep("4. If input length is not divisible by 3:")
	v.AddStep("   - Add one padding character (=) if 2 bytes remain")
	v.AddStep("   - Add two padding characters (==) if 1 byte remains")
	v.AddNote("Base64 encoding increases data size by approximately 33%")

	return encoded, v.GetSteps(), nil
}
