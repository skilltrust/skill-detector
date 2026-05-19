package reporter

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

const maxWidth = 80
const maxFindings = 5

// TextReporter writes scan results as human-readable text.
type TextReporter struct {
	Theme          Theme
	Verbose        bool
	OmitTrustScore bool
}

// Report writes the scan result in text format.
func (t *TextReporter) Report(result model.ScanResult, w io.Writer) error {
	findings := slices.Clone(result.Findings)

	// Build set of expected rule IDs from config overrides.
	expectedRules := map[string]bool{}
	for _, co := range result.ConfigOverrides {
		if co.Field == "context" && co.Override == "expected" {
			expectedRules[co.RuleID] = true
		}
	}

	// Sort findings: category, then expected (non-expected first), then confidence (high first), then file path.
	slices.SortStableFunc(findings, func(a, b model.Finding) int {
		if a.Category != b.Category {
			return strings.Compare(a.Category, b.Category)
		}
		aExp, bExp := expectedRules[a.RuleID], expectedRules[b.RuleID]
		if aExp != bExp {
			if aExp {
				return 1
			}
			return -1
		}
		if a.Confidence != b.Confidence {
			return int(a.Confidence) - int(b.Confidence)
		}
		return strings.Compare(a.FilePath, b.FilePath)
	})

	clean := len(findings) == 0
	findingCount := len(findings)
	hasPerms := len(result.Permissions) > 0

	// Verdict line (with inline permissions for clean scans).
	if clean && hasPerms {
		fmt.Fprintln(w, t.Theme.VerdictIcon(clean, findingCount)+" · "+formatInlinePermissions(result.Permissions))
	} else {
		fmt.Fprintln(w, t.Theme.VerdictIcon(clean, findingCount))
	}

	// Trust Score block: 4-axis grid above findings list.
	if !t.OmitTrustScore {
		t.writeTrustScoreBlock(w, result)
	}

	// Finding rows.
	if !clean {
		fmt.Fprintln(w)

		if t.Verbose {
			t.writeVerboseFindings(w, findings, expectedRules)
		} else {
			t.writeDefaultFindings(w, findings, expectedRules)
		}

		fmt.Fprintln(w)

		// Permission summary line (for all findings with permissions).
		if hasPerms {
			summary := formatPermissionSummary(result.Permissions)
			fmt.Fprintln(w, t.Theme.Colorize("  Permissions: "+truncate(summary, maxWidth-16), ansiDim))
		}

		// Metadata line.
		t.writeMetadataLine(w, result, !t.Verbose && len(findings) > maxFindings)
	} else {
		// Clean scan: blank line + metadata.
		fmt.Fprintln(w)
		t.writeMetadataLine(w, result, false)
	}

	return nil
}

// writeTrustScoreBlock writes the four-axis Trust Score grid to w.
// Shared by Report (when OmitTrustScore is false) and WriteTrustScoreBlock.
func (t *TextReporter) writeTrustScoreBlock(w io.Writer, result model.ScanResult) {
	if len(result.Axes) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, t.Theme.Colorize("Trust Score", ansiBold))
	for _, a := range axes.Order {
		ar := result.Axes[a]
		label := axisLabel(a)
		grade := string(ar.Grade)
		if !t.Theme.NoColor {
			grade = t.colorizeGrade(grade)
		}
		rationale := ar.Rationale
		if rationale == "" {
			rationale = "no findings on this axis"
		}
		fmt.Fprintf(w, "  %-20s %s   %s\n", label, grade, rationale)
	}
}

// WriteTrustScoreBlock writes only the four-axis Trust Score grid to w.
// Used by the --axes-only CLI flag.
func WriteTrustScoreBlock(w io.Writer, result model.ScanResult, noColor bool) {
	t := &TextReporter{Theme: NewTheme(noColor)}
	t.writeTrustScoreBlock(w, result)
}

func (t *TextReporter) writeFindingRow(w io.Writer, f model.Finding, expected bool) {
	t.writeFindingRowWithDiagnosis(w, f, true, expected)
}

func (t *TextReporter) writeFindingRowWithDiagnosis(w io.Writer, f model.Finding, includeDiagnosis bool, expected bool) {
	const indent = 2
	const minGap = 2

	icon := t.Theme.ConfidenceIcon(f.Confidence)
	catTag := f.Category
	if expected {
		catTag += " (expected)"
	}
	// icon + space prefix = 2 rune positions for the icon + 1 space
	iconPrefix := icon + " "
	iconLen := utf8.RuneCountInString(iconPrefix)
	maxDescLen := maxWidth - indent - iconLen - minGap - utf8.RuneCountInString(catTag)

	desc := truncate(f.Description, maxDescLen)

	totalUsed := indent + iconLen + utf8.RuneCountInString(desc) + utf8.RuneCountInString(catTag)
	padding := maxWidth - totalUsed
	if padding < minGap {
		padding = minGap
	}

	style := t.Theme.ConfidenceStyle(f.Confidence)

	styledRow := t.Theme.Colorize(
		fmt.Sprintf("%s%s%s%s%s",
			strings.Repeat(" ", indent),
			iconPrefix,
			desc,
			strings.Repeat(" ", padding),
			catTag,
		),
		style...,
	)
	// In color mode, replace the plain category tag with the colored one
	if !t.Theme.NoColor {
		catStyle := ansiCyan
		if expected {
			catStyle = ansiDim + ansiCyan
		}
		styledRow = fmt.Sprintf("%s%s%s%s%s%s%s",
			strings.Join(style, ""),
			strings.Repeat(" ", indent),
			iconPrefix,
			desc,
			strings.Repeat(" ", padding),
			ansiReset+catStyle+catTag+ansiReset,
			"",
		)
	}

	fmt.Fprintln(w, styledRow)

	// Diagnosis line below the finding row.
	if includeDiagnosis && f.Diagnosis != "" {
		diagLine := truncate("    "+f.Diagnosis, maxWidth)
		fmt.Fprintln(w, t.Theme.Colorize(diagLine, ansiDim))
	}
}

func (t *TextReporter) writeDefaultFindings(w io.Writer, findings []model.Finding, expectedRules map[string]bool) {
	displayed := 0
	currentCategory := ""
	for _, f := range findings {
		if displayed >= maxFindings {
			break
		}
		if f.Category != currentCategory {
			if displayed > 0 {
				fmt.Fprintln(w)
			}
			currentCategory = f.Category
			t.writeCategoryHeader(w, currentCategory)
		}
		t.writeFindingRow(w, f, expectedRules[f.RuleID])
		displayed++
	}
}

func (t *TextReporter) writeVerboseFindings(w io.Writer, findings []model.Finding, expectedRules map[string]bool) {
	currentCategory := ""
	for i, f := range findings {
		if f.Category != currentCategory {
			currentCategory = f.Category
			t.writeCategoryHeader(w, currentCategory)
			if currentCategory != "" {
				fmt.Fprintln(w)
			}
		}
		t.writeVerboseFinding(w, f, expectedRules[f.RuleID])
		if i < len(findings)-1 {
			fmt.Fprintln(w)
		}
	}
}

func (t *TextReporter) writeCategoryHeader(w io.Writer, category string) {
	if category == "" {
		return
	}
	fmt.Fprintf(w, "  %s\n", t.Theme.Colorize(category, ansiBold))
}

func (t *TextReporter) writeVerboseFinding(w io.Writer, f model.Finding, expected bool) {
	t.writeFindingRowWithDiagnosis(w, f, false, expected)

	fileLine := f.FilePath
	if f.Line > 0 {
		fileLine = fmt.Sprintf("%s:%d", f.FilePath, f.Line)
	}

	confidence := strings.ToLower(f.Confidence.String())
	if f.Diagnosis != "" {
		confidence += " · " + f.Diagnosis
	}

	details := []string{
		fmt.Sprintf("    Rule: %s (%s)", f.RuleID, f.Category),
		fmt.Sprintf("    File: %s", fileLine),
		fmt.Sprintf("    Confidence: %s", confidence),
		fmt.Sprintf("    Your check: %s", f.Remediation),
	}
	for _, d := range details {
		fmt.Fprintln(w, t.Theme.Colorize(truncate(d, maxWidth), ansiDim))
	}
}

func (t *TextReporter) writeMetadataLine(w io.Writer, result model.ScanResult, overflow bool) {
	var meta string
	if overflow {
		hidden := len(result.Findings) - maxFindings
		meta = fmt.Sprintf("  ...and %d more · --verbose for details · %d files scanned · %d rules", hidden, result.FileCount, result.RuleCount)
	} else {
		meta = fmt.Sprintf("  %d files scanned · %d rules", result.FileCount, result.RuleCount)
	}
	fmt.Fprintln(w, t.Theme.Colorize(meta, ansiDim))
}

// canonicalPermTypes defines the deterministic output order for permission types.
var canonicalPermTypes = []string{"filesystem", "network", "shell_execution", "env_var_access"}

var permInlineLabels = map[string]string{
	"filesystem":      "reads local files",
	"network":         "network",
	"shell_execution": "shell",
	"env_var_access":  "env var access",
}

var permNegativeLabels = map[string]string{
	"network":         "no network",
	"shell_execution": "no shell",
	"env_var_access":  "no env var access",
}

var permSummaryLabels = map[string]string{
	"filesystem":      "reads filesystem",
	"network":         "network",
	"shell_execution": "shell",
	"env_var_access":  "env var access",
}

// formatInlinePermissions formats permissions for the clean-scan verdict line.
// Shows positive labels for present types and negative labels for absent types.
func formatInlinePermissions(perms []model.Permission) string {
	present := make(map[string]model.Permission, len(perms))
	for _, p := range perms {
		present[p.Type] = p
	}

	var parts []string
	for _, typ := range canonicalPermTypes {
		if _, ok := present[typ]; ok {
			parts = append(parts, permInlineLabels[typ])
		} else if neg, ok := permNegativeLabels[typ]; ok {
			parts = append(parts, neg)
		}
	}
	return strings.Join(parts, " · ")
}

// formatPermissionSummary formats permissions for the findings-mode summary line.
// Only shows present permissions (no negatives).
func formatPermissionSummary(perms []model.Permission) string {
	present := make(map[string]model.Permission, len(perms))
	for _, p := range perms {
		present[p.Type] = p
	}

	var parts []string
	for _, typ := range canonicalPermTypes {
		p, ok := present[typ]
		if !ok {
			continue
		}
		if typ == "filesystem" {
			hasCredentials := false
			for _, d := range p.Details {
				if strings.Contains(d, "credentials") {
					hasCredentials = true
					break
				}
			}
			if hasCredentials {
				parts = append(parts, "reads filesystem (incl. credentials)")
			} else {
				parts = append(parts, permSummaryLabels[typ])
			}
		} else {
			parts = append(parts, permSummaryLabels[typ])
		}
	}
	return strings.Join(parts, " · ")
}

// buildExplanation constructs a one-sentence plain-language explanation from permissions.
// Returns empty string if no interesting (non-benign) capabilities are present.
func buildExplanation(perms []model.Permission) string {
	present := make(map[string]model.Permission, len(perms))
	for _, p := range perms {
		present[p.Type] = p
	}

	var phrases []string
	for _, typ := range canonicalPermTypes {
		p, ok := present[typ]
		if !ok {
			continue
		}
		switch typ {
		case "filesystem":
			// Only include if credentials are present (benign filesystem is omitted)
			credPath := extractCredentialPath(p.Details)
			if credPath != "" {
				phrases = append(phrases, "reads "+credPath)
			}
		case "network":
			if len(p.Details) > 0 && p.Details[0] != "" {
				phrases = append(phrases, "makes network calls to "+p.Details[0])
			} else {
				phrases = append(phrases, "makes outbound network calls")
			}
		case "shell_execution":
			phrases = append(phrases, "executes shell commands")
		case "env_var_access":
			if len(p.Details) > 0 && p.Details[0] != "" {
				phrases = append(phrases, "accesses environment variables ("+p.Details[0]+")")
			} else {
				phrases = append(phrases, "accesses environment variables")
			}
		}
	}

	if len(phrases) == 0 {
		return ""
	}

	var joined string
	switch len(phrases) {
	case 1:
		joined = phrases[0]
	case 2:
		joined = phrases[0] + " and " + phrases[1]
	default:
		joined = strings.Join(phrases[:len(phrases)-1], ", ") + ", and " + phrases[len(phrases)-1]
	}

	sentence := "This skill " + joined
	if len([]rune(sentence)) > 78 {
		sentence = truncate(sentence, 78)
	}
	return sentence
}

// extractCredentialPath extracts a credential file path from permission details.
func extractCredentialPath(details []string) string {
	for _, d := range details {
		if strings.Contains(d, "credentials") {
			if idx := strings.Index(d, ": "); idx != -1 {
				return d[idx+2:]
			}
		}
	}
	return ""
}

// axisLabel returns the human-readable display label for an axis.
func axisLabel(a axes.Axis) string {
	switch a {
	case axes.Security:
		return "Security"
	case axes.PermissionHygiene:
		return "Permission hygiene"
	case axes.Transparency:
		return "Transparency"
	case axes.Quality:
		return "Quality"
	}
	return string(a)
}

// colorizeGrade applies ANSI color to a grade letter.
func (t *TextReporter) colorizeGrade(g string) string {
	switch g {
	case "A", "B":
		return t.Theme.Colorize(g, ansiGreen)
	case "C":
		return t.Theme.Colorize(g, ansiYellow)
	default:
		return t.Theme.Colorize(g, ansiRed)
	}
}

func truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-3]) + "..."
}
