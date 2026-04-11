package reporter

import (
	"fmt"
	"os"
	"strings"

	"github.com/velzepooz/skill-detector/internal/model"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

// Theme controls color and formatting options for the TextReporter.
type Theme struct {
	NoColor bool
}

// NewTheme creates a Theme with color auto-detection.
// noColor=true forces no-color mode. Also checks NO_COLOR env var.
func NewTheme(noColor bool) Theme {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return Theme{NoColor: true}
	}
	return Theme{NoColor: false}
}

// Colorize wraps text with ANSI escape codes when color is enabled.
func (t Theme) Colorize(text string, codes ...string) string {
	if t.NoColor {
		return text
	}
	prefix := strings.Join(codes, "")
	return prefix + text + ansiReset
}

// VerdictIcon returns the appropriate verdict icon with color.
func (t Theme) VerdictIcon(clean bool, findingCount int) string {
	if clean {
		return t.Colorize("✓ No concerns", ansiGreen, ansiBold)
	}
	return t.Colorize(fmt.Sprintf("⚠ %d behaviors detected", findingCount), ansiYellow, ansiBold)
}

// ConfidenceIcon returns the Unicode icon for a confidence level.
func (t Theme) ConfidenceIcon(conf model.Confidence) string {
	switch conf {
	case model.ConfidenceHigh:
		return "●"
	case model.ConfidenceMedium:
		return "◐"
	default:
		return "○"
	}
}

// ConfidenceStyle returns ANSI codes for styling a finding row by confidence.
func (t Theme) ConfidenceStyle(conf model.Confidence) []string {
	switch conf {
	case model.ConfidenceHigh:
		return []string{ansiBold}
	case model.ConfidenceLow:
		return []string{ansiDim}
	default:
		return []string{}
	}
}
