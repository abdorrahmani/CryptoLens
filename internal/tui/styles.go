package tui

import "github.com/charmbracelet/lipgloss"

// Color palette, mapped to the ANSI colors the old console theme used so the
// TUI keeps CryptoLens' familiar look.
var (
	colTitle   = lipgloss.Color("14") // bright cyan
	colAccent  = lipgloss.Color("11") // bright yellow
	colDim     = lipgloss.Color("240")
	colDanger  = lipgloss.Color("9")  // bright red
	colSuccess = lipgloss.Color("10") // bright green
	colArrow   = lipgloss.Color("11") // bright yellow
	colDiagram = lipgloss.Color("12") // bright blue
	colWhite   = lipgloss.Color("15")
	colSelBg   = lipgloss.Color("57") // purple
)

var (
	titleStyle = lipgloss.NewStyle().
			Foreground(colTitle).
			Bold(true)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(colDim)

	bannerStyle = lipgloss.NewStyle().
			Foreground(colDiagram)

	sepStyle = lipgloss.NewStyle().
			Foreground(colDim)

	itemStyle = lipgloss.NewStyle().
			Foreground(colAccent).
			PaddingLeft(2)

	selectedItemStyle = lipgloss.NewStyle().
				Foreground(colWhite).
				Background(colSelBg).
				Bold(true).
				PaddingLeft(1)

	dangerItemStyle = lipgloss.NewStyle().
			Foreground(colDanger).
			PaddingLeft(2)

	itemDescStyle = lipgloss.NewStyle().
			Foreground(colDim)

	helpStyle = lipgloss.NewStyle().
			Foreground(colDim).
			MarginTop(1)

	errStyle = lipgloss.NewStyle().
			Foreground(colDanger).
			Bold(true)

	promptStyle = lipgloss.NewStyle().
			Foreground(colSuccess).
			Bold(true)

	resultTitleStyle = lipgloss.NewStyle().
				Foreground(colSuccess).
				Bold(true)

	// Step rendering styles (mirror the old display.ShowResult formatting).
	stepHeaderStyle  = lipgloss.NewStyle().Foreground(colWhite).Bold(true)
	stepArrowStyle   = lipgloss.NewStyle().Foreground(colArrow).Bold(true)
	stepSuccessStyle = lipgloss.NewStyle().Foreground(colSuccess)
	stepWarnStyle    = lipgloss.NewStyle().Foreground(colDanger)
	stepNumberStyle  = lipgloss.NewStyle().Foreground(colTitle).Bold(true)
	stepBulletStyle  = lipgloss.NewStyle().Foreground(colAccent)
	stepDiagramStyle = lipgloss.NewStyle().Foreground(colDiagram)
	stepLabelStyle   = lipgloss.NewStyle().Foreground(colWhite).Bold(true)
	stepPlainStyle   = lipgloss.NewStyle().Foreground(colWhite)
)
