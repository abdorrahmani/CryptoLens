package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderSteps turns the processor's step slice into a styled block for the
// result viewport. The styling mirrors the old console display so output reads
// the same, section headers, arrows, success/warning markers and all.
func renderSteps(steps []string) string {
	var b strings.Builder
	for i, step := range steps {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(formatStep(step))
	}
	return b.String()
}

func formatStep(step string) string {
	// Steps that already carry raw ANSI escapes (e.g. the benchmark bar charts)
	// are passed through untouched so we don't clobber their coloring.
	if strings.Contains(step, "\x1b[") {
		return step
	}

	switch {
	case hasAnyPrefix(step, "📌", "🔢", "📈", "🔒", "📚"):
		underline := sepStyle.Render(strings.Repeat("=", lipgloss.Width(step)))
		return stepHeaderStyle.Render(step) + "\n" + underline
	case strings.HasPrefix(step, "----------------------------------------"):
		return sepStyle.Render(step)
	case strings.Contains(step, "↓"):
		return stepArrowStyle.Render(step)
	case strings.Contains(step, "✅"):
		return stepSuccessStyle.Render(step)
	case strings.Contains(step, "⚠️"):
		return stepWarnStyle.Render(step)
	case strings.HasPrefix(step, "Step"):
		return stepNumberStyle.Render(step)
	case strings.HasPrefix(step, "•"):
		return stepBulletStyle.Render(step)
	case containsAny(step, "┌", "│", "└", "─"):
		return stepDiagramStyle.Render(step)
	case strings.Contains(step, ":"):
		parts := strings.SplitN(step, ":", 2)
		if len(parts) == 2 {
			return stepLabelStyle.Render(parts[0]+":") + stepPlainStyle.Render(parts[1])
		}
		return stepPlainStyle.Render(step)
	default:
		return stepPlainStyle.Render(step)
	}
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
