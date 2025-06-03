package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "cryptolens-test")
	if err != nil {
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	// Set up test environment
	os.Setenv("HOME", tmpDir)
	os.Setenv("USERPROFILE", tmpDir) // For Windows

	// Run tests
	code := m.Run()

	// Clean up
	os.Exit(code)
}

func TestMainInitialization(t *testing.T) {
	// Test with invalid config path
	os.Setenv("CRYPTOLENS_CONFIG", "nonexistent/path/config.yaml")

	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "cryptolens-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test config file
	configDir := filepath.Join(tmpDir, ".cryptolens")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}

	// Test with valid config path
	os.Setenv("CRYPTOLENS_CONFIG", filepath.Join(configDir, "config.yaml"))
}
