package attacks

import (
	"testing"
	"time"
)

func TestBruteForceProcessor_Configure(t *testing.T) {
	tests := []struct {
		name       string
		config     map[string]interface{}
		wantErr    bool
		iterations int
	}{
		{
			name: "valid configuration",
			config: map[string]interface{}{
				"iterations": 1000,
			},
			wantErr:    false,
			iterations: 1000,
		},
		{
			name: "invalid iterations type",
			config: map[string]interface{}{
				"iterations": "1000",
			},
			wantErr:    false, // Should not error, just use default
			iterations: 100,   // Default value
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewBruteForceProcessor()
			err := p.Configure(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("BruteForceProcessor.Configure() error = %v, wantErr %v", err, tt.wantErr)
			}
			if p.config.Iterations != tt.iterations {
				t.Errorf("BruteForceProcessor.Configure() iterations = %v, want %v", p.config.Iterations, tt.iterations)
			}
			if len(p.config.Salt) != 16 {
				t.Errorf("BruteForceProcessor.Configure() salt length = %v, want %v", len(p.config.Salt), 16)
			}
		})
	}
}

func TestBruteForceProcessor_Process(t *testing.T) {
	tests := []struct {
		name       string
		text       string
		operation  string
		wantResult bool
	}{
		{
			name:       "find common password",
			text:       "password123",
			operation:  "attack",
			wantResult: true,
		},
		{
			name:       "find another common password",
			text:       "admin123",
			operation:  "attack",
			wantResult: true,
		},
		{
			name:       "random text should not be found",
			text:       "xK9#mP2$vL5",
			operation:  "attack",
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewBruteForceProcessor()
			err := p.Configure(map[string]interface{}{
				"iterations": 100, // Use low iterations for faster tests
			})
			if err != nil {
				t.Fatalf("Failed to configure processor: %v", err)
			}

			result, steps, err := p.Process(tt.text, tt.operation)
			if err != nil {
				t.Errorf("BruteForceProcessor.Process() error = %v", err)
			}
			if result == "" {
				t.Error("BruteForceProcessor.Process() returned empty result")
			}
			if len(steps) == 0 {
				t.Error("BruteForceProcessor.Process() returned no steps")
			}

			// Check if the result contains "Password found!" or "Password not found"
			found := false
			for _, step := range steps {
				if step == "✅ Password found!" {
					found = true
					break
				}
			}
			if found != tt.wantResult {
				t.Errorf("Password found = %v, want %v", found, tt.wantResult)
			}
		})
	}
}

func TestBruteForceProcessor_Performance(t *testing.T) {
	p := NewBruteForceProcessor()
	err := p.Configure(map[string]interface{}{
		"iterations": 100, // Use low iterations for faster tests
	})
	if err != nil {
		t.Fatalf("Failed to configure processor: %v", err)
	}

	start := time.Now()
	_, _, err = p.Process("password123", "attack")
	duration := time.Since(start)

	if err != nil {
		t.Errorf("BruteForceProcessor.Process() error = %v", err)
	}

	// Test should complete within 5 seconds
	if duration > 5*time.Second {
		t.Errorf("Attack took too long: %v", duration)
	}
}
