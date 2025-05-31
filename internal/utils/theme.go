package utils

// Theme defines the interface for color themes
type Theme interface {
	// GetColor returns the ANSI color code for the given color name
	GetColor(name string) string
	// Format formats text with the given style
	Format(text string, style string) string
}

// ColorTheme implements the Theme interface
type ColorTheme struct {
	colors map[string]string
}

// NewColorTheme creates a new color theme with default colors
func NewColorTheme() *ColorTheme {
	return &ColorTheme{
		colors: map[string]string{
			"reset":        "\033[0m",
			"red":          "\033[31m",
			"green":        "\033[32m",
			"yellow":       "\033[33m",
			"blue":         "\033[34m",
			"purple":       "\033[35m",
			"cyan":         "\033[36m",
			"white":        "\033[37m",
			"bold":         "\033[1m",
			"dim":          "\033[2m",
			"italic":       "\033[3m",
			"underline":    "\033[4m",
			"brightRed":    "\033[91m",
			"brightGreen":  "\033[92m",
			"brightYellow": "\033[93m",
			"brightBlue":   "\033[94m",
			"brightPurple": "\033[95m",
			"brightCyan":   "\033[96m",
		},
	}
}

// GetColor returns the ANSI color code for the given color name
func (t *ColorTheme) GetColor(name string) string {
	if color, exists := t.colors[name]; exists {
		return color
	}
	return t.colors["reset"]
}

// Format formats text with the given style
func (t *ColorTheme) Format(text string, style string) string {
	return t.GetColor(style) + text + t.GetColor("reset")
}

// DefaultTheme is the default color theme instance
var DefaultTheme Theme = NewColorTheme()
