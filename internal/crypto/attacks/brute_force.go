package attacks

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/abdorrahmani/cryptolens/internal/utils"
)

// BruteForceProcessor implements the brute force attack simulation
type BruteForceProcessor struct {
	iterations int
	salt       []byte
}

// NewBruteForceProcessor creates a new brute force attack processor
func NewBruteForceProcessor() *BruteForceProcessor {
	return &BruteForceProcessor{
		iterations: 100, // Weak iteration count for demonstration
	}
}

// Configure configures the brute force processor
func (p *BruteForceProcessor) Configure(config map[string]interface{}) error {
	// Generate a random salt
	p.salt = make([]byte, 16)
	if _, err := rand.Read(p.salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	return nil
}

// Process demonstrates the brute force attack on a weak PBKDF key
func (p *BruteForceProcessor) Process(text string, operation string) (string, []string, error) {
	v := utils.NewVisualizer()

	// Add introduction
	v.AddStep("🔒 Brute Force Attack on Weak PBKDF")
	v.AddStep("================================")
	v.AddNote("This simulation demonstrates how weak key derivation parameters")
	v.AddNote("can make passwords vulnerable to brute force attacks")
	v.AddNote("")
	v.AddNote("⚠️ Important Note: This attack is NOT directly breaking the cipher")
	v.AddNote("Instead, it's comparing derived keys from PBKDF2 with weak parameters")
	v.AddNote("The attacker is trying to find a password that generates the same derived key")
	v.AddNote("This is why strong key derivation parameters are crucial for security")
	v.AddSeparator()

	// Generate the target key using PBKDF2 with weak parameters
	targetKey := pbkdf2.Key([]byte(text), p.salt, p.iterations, 32, sha256.New)
	targetKeyBase64 := base64.StdEncoding.EncodeToString(targetKey)

	v.AddTextStep("Target Password", text)
	v.AddStep(fmt.Sprintf("Using PBKDF2 with only %d iterations", p.iterations))
	v.AddHexStep("Salt", p.salt)
	v.AddTextStep("Target Key (Base64)", targetKeyBase64)
	v.AddArrow()

	// Common passwords to try
	commonPasswords := []string{
		// Basic passwords
		"password", "123456", "qwerty", "admin", "welcome",
		"letmein", "monkey", "dragon", "baseball", "football",
		"abc123", "111111", "123123", "12345678", "123456789",
		"1234567890", "qwerty123", "password123", "admin123",
		"superman", "trustno1", "sunshine", "master", "hello123",
		"shadow", "ashley", "freedom", "whatever", "qazwsx",
		"michael", "football", "baseball", "welcome", "jennifer",
		"hunter", "joshua", "maggie", "starwars", "silver",
		"william", "dallas", "yankees", "justin", "lovely",
		"jordan", "matthew", "daniel", "oliver", "andrew", "root",

		// Common patterns
		"1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
		"qwerty", "qwerty123", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbnm",
		"password", "password123", "password1", "password1234", "password12345",
		"admin", "admin123", "admin1234", "admin12345", "administrator",

		// Years
		"1990", "1991", "1992", "1993", "1994", "1995", "1996", "1997", "1998", "1999",
		"2000", "2001", "2002", "2003", "2004", "2005", "2006", "2007", "2008", "2009",
		"2010", "2011", "2012", "2013", "2014", "2015", "2016", "2017", "2018", "2019",
		"2020", "2021", "2022", "2023", "2024", "2025",

		// Months
		"january", "february", "march", "april", "may", "june",
		"july", "august", "september", "october", "november", "december",

		// Days
		"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",

		// Common names
		"james", "john", "robert", "michael", "william", "david", "richard", "joseph", "thomas", "charles",
		"mary", "patricia", "jennifer", "linda", "elizabeth", "barbara", "susan", "jessica", "sarah", "margaret",
		"mike", "bob", "joe", "tom", "dave", "jim", "steve", "chris", "dan", "paul",
		"lisa", "sarah", "jennifer", "michelle", "laura", "amy", "angela", "kimberly", "melissa", "emily",

		// Sports teams
		"lakers", "celtics", "bulls", "warriors", "heat", "knicks", "nets", "rockets", "spurs", "mavericks",
		"yankees", "redsox", "dodgers", "cubs", "giants", "cardinals", "braves", "mets", "phillies", "angels",
		"cowboys", "patriots", "packers", "steelers", "49ers", "chiefs", "ravens", "saints", "broncos", "seahawks",

		// Movies and TV shows
		"starwars", "startrek", "harrypotter", "lordoftherings", "matrix", "terminator", "alien", "predator",
		"friends", "seinfeld", "simpsons", "familyguy", "southpark", "breakingbad", "gameofthrones", "strangerthings",

		// Common words
		"love", "hate", "happy", "sad", "angry", "smile", "laugh", "cry", "dream", "hope",
		"peace", "war", "life", "death", "time", "space", "earth", "world", "universe", "heaven",
		"hell", "god", "devil", "angel", "demon", "soul", "spirit", "mind", "heart", "soul",

		// Keyboard patterns
		"qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "asdfghjkl", "zxcvbnm", "qwerty123", "asdfgh123", "zxcvbn123",
		"1q2w3e4r", "2w3e4r5t", "3e4r5t6y", "4r5t6y7u", "5t6y7u8i", "6y7u8i9o", "7u8i9o0p",

		// Common phrases
		"iloveyou", "ihateyou", "fuckyou", "fuckoff", "fuckme", "fuckit", "fuckthis", "fuckthat",
		"hello123", "welcome123", "password123", "admin123", "user123", "login123", "signin123",

		// Common combinations
		"pass123", "pass1234", "pass12345", "pass123456", "pass1234567", "pass12345678",
		"admin123", "admin1234", "admin12345", "admin123456", "admin1234567", "admin12345678",
		"user123", "user1234", "user12345", "user123456", "user1234567", "user12345678",

		// Common words with numbers
		"password1", "password12", "password123", "password1234", "password12345",
		"admin1", "admin12", "admin123", "admin1234", "admin12345",
		"user1", "user12", "user123", "user1234", "user12345",

		// Common words with special characters
		"password!", "password@", "password#", "password$", "password%",
		"admin!", "admin@", "admin#", "admin$", "admin%",
		"user!", "user@", "user#", "user$", "user%",

		// Common words with uppercase
		"Password", "Admin", "User", "Login", "Welcome", "Hello", "Goodbye", "Thankyou",

		// Common words with mixed case
		"PaSsWoRd", "AdMiN", "UsEr", "LoGiN", "WeLcOmE", "HeLlO", "GoOdByE", "ThAnKyOu",

		// Common words with numbers and special characters
		"password123!", "password123@", "password123#", "password123$", "password123%",
		"admin123!", "admin123@", "admin123#", "admin123$", "admin123%",
		"user123!", "user123@", "user123#", "user123$", "user123%",

		// Common words with uppercase and numbers
		"Password123", "Admin123", "User123", "Login123", "Welcome123", "Hello123", "Goodbye123", "Thankyou123",

		// Common words with mixed case and numbers
		"PaSsWoRd123", "AdMiN123", "UsEr123", "LoGiN123", "WeLcOmE123", "HeLlO123", "GoOdByE123", "ThAnKyOu123",

		// Common words with uppercase, numbers and special characters
		"Password123!", "Admin123@", "User123#", "Login123$", "Welcome123%", "Hello123!", "Goodbye123@", "Thankyou123#",

		// Common words with mixed case, numbers and special characters
		"PaSsWoRd123!", "AdMiN123@", "UsEr123#", "LoGiN123$", "WeLcOmE123%", "HeLlO123!", "GoOdByE123@", "ThAnKyOu123#",

		// Common words with uppercase and special characters
		"Password!", "Admin@", "User#", "Login$", "Welcome%", "Hello!", "Goodbye@", "Thankyou#",

		// Common words with mixed case and special characters
		"PaSsWoRd!", "AdMiN@", "UsEr#", "LoGiN$", "WeLcOmE%", "HeLlO!", "GoOdByE@", "ThAnKyOu#",

		// Common words with numbers and uppercase
		"PASSWORD123", "ADMIN123", "USER123", "LOGIN123", "WELCOME123", "HELLO123", "GOODBYE123", "THANKYOU123",

		// Common words with numbers and mixed case
		"PaSsWoRd123", "AdMiN123", "UsEr123", "LoGiN123", "WeLcOmE123", "HeLlO123", "GoOdByE123", "ThAnKyOu123",

		// Common words with numbers, uppercase and special characters
		"PASSWORD123!", "ADMIN123@", "USER123#", "LOGIN123$", "WELCOME123%", "HELLO123!", "GOODBYE123@", "THANKYOU123#",

		// Common words with numbers, mixed case and special characters
		"PaSsWoRd123!", "AdMiN123@", "UsEr123#", "LoGiN123$", "WeLcOmE123%", "HeLlO123!", "GoOdByE123@", "ThAnKyOu123#",

		// Common words with uppercase and special characters
		"PASSWORD!", "ADMIN@", "USER#", "LOGIN$", "WELCOME%", "HELLO!", "GOODBYE@", "THANKYOU#",

		// Common words with mixed case and special characters
		"PaSsWoRd!", "AdMiN@", "UsEr#", "LoGiN$", "WeLcOmE%", "HeLlO!", "GoOdByE@", "ThAnKyOu#",

		// Common words with numbers and uppercase
		"PASSWORD123", "ADMIN123", "USER123", "LOGIN123", "WELCOME123", "HELLO123", "GOODBYE123", "THANKYOU123",

		// Common words with numbers and mixed case
		"PaSsWoRd123", "AdMiN123", "UsEr123", "LoGiN123", "WeLcOmE123", "HeLlO123", "GoOdByE123", "ThAnKyOu123",

		// Common words with numbers, uppercase and special characters
		"PASSWORD123!", "ADMIN123@", "USER123#", "LOGIN123$", "WELCOME123%", "HELLO123!", "GOODBYE123@", "THANKYOU123#",

		// Common words with numbers, mixed case and special characters
		"PaSsWoRd123!", "AdMiN123@", "UsEr123#", "LoGiN123$", "WeLcOmE123%", "HeLlO123!", "GoOdByE123@", "ThAnKyOu123#",
	}

	// Add attack details
	v.AddStep("Attack Details:")
	v.AddStep("1. Using a dictionary of common passwords")
	v.AddStep("2. Testing each password with the same salt")
	v.AddStep("3. Comparing derived keys")
	v.AddStep(fmt.Sprintf("4. Only %d iterations makes this very fast", p.iterations))
	v.AddArrow()

	// Start the attack
	v.AddStep("Starting Brute Force Attack...")
	startTime := time.Now()

	// Track statistics
	var attempts int
	var found bool
	var foundPassword string
	var foundKey string

	// Try each password
	for _, password := range commonPasswords {
		attempts++
		derivedKey := pbkdf2.Key([]byte(password), p.salt, p.iterations, 32, sha256.New)
		derivedKeyBase64 := base64.StdEncoding.EncodeToString(derivedKey)

		// Show progress
		if attempts%5 == 0 {
			v.AddStep(fmt.Sprintf("Trying password %d/%d: %s", attempts, len(commonPasswords), password))
		}

		// Check if we found a match
		if derivedKeyBase64 == targetKeyBase64 {
			found = true
			foundPassword = password
			foundKey = derivedKeyBase64
			break
		}
	}

	// Calculate attack duration
	duration := time.Since(startTime)

	// Show results
	v.AddSeparator()
	v.AddStep("Attack Results:")
	v.AddStep(fmt.Sprintf("Total attempts: %d", attempts))
	v.AddStep(fmt.Sprintf("Attack duration: %.2f seconds", duration.Seconds()))
	v.AddStep(fmt.Sprintf("Attempts per second: %.0f", float64(attempts)/duration.Seconds()))

	if found {
		v.AddStep("✅ Password found!")
		v.AddTextStep("Found Password", foundPassword)
		v.AddTextStep("Derived Key", foundKey)
	} else {
		v.AddStep("❌ Password not found in dictionary")
	}

	// Add security implications
	v.AddSeparator()
	v.AddStep("🔒 Security Implications:")
	v.AddStep("1. Weak key derivation parameters make brute force attacks feasible")
	v.AddStep("2. Common passwords are easily cracked")
	v.AddStep("3. Low iteration counts allow for rapid password testing")
	v.AddStep("4. Dictionary attacks can be very effective")

	v.AddStep("✅ Best Practices:")
	v.AddStep("1. Use strong key derivation functions (Argon2, scrypt, bcrypt)")
	v.AddStep("2. Use high iteration counts (100,000+ for PBKDF2)")
	v.AddStep("3. Use unique salts for each password")
	v.AddStep("4. Enforce strong password policies")
	v.AddStep("5. Consider using memory-hard functions")

	// Show comparison with secure parameters
	v.AddSeparator()
	v.AddStep("Comparison with Secure Parameters:")
	v.AddStep("Current (Weak):")
	v.AddStep(fmt.Sprintf("• PBKDF2 with %d iterations", p.iterations))
	v.AddStep(fmt.Sprintf("• Attack time: %.2f seconds", duration.Seconds()))
	v.AddStep("Secure Configuration:")
	v.AddStep("• PBKDF2 with 310,000 iterations")
	v.AddStep("• Estimated attack time: ~5.2 hours")
	v.AddStep("• Argon2id with 1GB memory cost")
	v.AddStep("• Estimated attack time: ~2.3 days")

	return fmt.Sprintf("Attack completed in %.2f seconds", duration.Seconds()), v.GetSteps(), nil
}
