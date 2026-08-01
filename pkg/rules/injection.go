package rules

import (
	"bytes"
	"regexp"
	"unicode/utf8"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// Package-level compiled regex — compile ONCE, not per Match() call.
var (
	reEvalVar     = regexp.MustCompile(`eval\s+.*\$`)
	reBacktickVar = regexp.MustCompile("`[^`]*\\$\\{?\\w+[^`]*`")

	reHiddenInstruction = regexp.MustCompile(`(?i)(ignore\s+(previous|above|all)\s+instructions|disregard\s+(above|previous)|new\s+instructions\s+follow)`)
	reInstructionMarker = regexp.MustCompile(`\[/?INST\]|<</?SYS>>`)
	reHTMLComment       = regexp.MustCompile(`<!--[\s\S]*?-->`)
)

// Zero-width Unicode runes to detect.
var zeroWidthRunes = []rune{
	'\u200B', '\u200C', '\u200D', '\uFEFF', '\u2060', '\u200E', '\u200F',
}

type shellInjectionRule struct {
	baseRule
}

func (r *shellInjectionRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsAgentFile(ctx.Path) && !isInAgentConfigDir(ctx.Path) {
		return nil
	}
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1
		if reEvalVar.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"shell injection via eval with variable input",
				"Avoid using eval with unsanitized variables; use explicit commands instead"))
		}
		if reBacktickVar.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"shell injection via backtick execution with variable",
				"Avoid backtick command substitution with unsanitized variables; use explicit commands instead"))
		}
	}
	return findings
}

type promptInjectionRule struct {
	baseRule
}

func (r *promptInjectionRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsSkillManifest(ctx.Path) && !IsInstructionFile(ctx.Path) && !isInAgentConfigDir(ctx.Path) {
		return nil
	}
	var findings []model.Finding

	// Pre-pass: detect directives inside multi-line HTML comments.
	// The per-line loop only catches single-line comments; multi-line ones
	// span across split boundaries and need full-content matching.
	for _, loc := range reHTMLComment.FindAllIndex(content, -1) {
		comment := content[loc[0]:loc[1]]
		if !bytes.Contains(comment, []byte("\n")) {
			continue // single-line comments are handled in the per-line loop
		}
		if reHiddenInstruction.Match(comment) ||
			bytes.Contains(comment, []byte("SYSTEM:")) ||
			bytes.Contains(comment, []byte("system:")) {
			lineNum := 1 + bytes.Count(content[:loc[0]], []byte("\n"))
			findings = append(findings, r.newFinding(ctx, lineNum,
				"multi-line HTML comment with hidden directive",
				"Remove hidden directives from HTML comments"))
		}
	}

	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1
		lineStr := string(line)

		// Detect zero-width Unicode characters.
		j := 0
		for _, ru := range lineStr {
			for _, zw := range zeroWidthRunes {
				if ru == zw {
					// Skip BOM (U+FEFF) at position 0 of the first line.
					if ru == '\uFEFF' && lineNum == 1 && j == 0 {
						continue
					}
					findings = append(findings, r.newFinding(ctx, lineNum,
						"zero-width Unicode character detected in prompt template",
						"Remove invisible Unicode characters that could hide malicious instructions"))
				}
			}
			j += utf8.RuneLen(ru)
		}

		// Detect hidden instruction patterns.
		if reHiddenInstruction.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"hidden instruction pattern detected in prompt template",
				"Remove prompt injection directives; ensure prompts contain only intended instructions"))
		}

		// Detect instruction markers like [INST], [/INST], <<SYS>>, <</SYS>>.
		if reInstructionMarker.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"instruction marker detected that could manipulate AI behavior",
				"Remove instruction markers; use the AI platform's proper API for system instructions"))
		}

		// Detect directives in HTML comments.
		if reHTMLComment.Match(line) && reHiddenInstruction.Match(line) {
			// Already caught by reHiddenInstruction above — no duplicate needed.
		} else if reHTMLComment.Match(line) {
			// HTML comment without known instruction pattern — check for SYSTEM directive.
			if bytes.Contains(line, []byte("SYSTEM:")) || bytes.Contains(line, []byte("system:")) {
				findings = append(findings, r.newFinding(ctx, lineNum,
					"HTML comment with system directive detected in prompt template",
					"Remove hidden directives from HTML comments"))
			}
		}
	}
	return findings
}

// RegisterInjectionRules registers all injection detection rules.
func RegisterInjectionRules(registry *RuleRegistry) {
	registry.Register(&shellInjectionRule{
		baseRule: baseRule{
			id:       "SD-001",
			name:     "Shell Injection",
			severity: model.SeverityCritical,
			category: "Injection",
			types:    []string{".sh", ".bash"},
			axis:     axes.Security,
		},
	})

	registry.Register(&promptInjectionRule{
		baseRule: baseRule{
			id:       "SD-002",
			name:     "Prompt Injection",
			severity: model.SeverityCritical,
			category: "Injection",
			types:    []string{".md", ".mdc", ".txt", ".yaml", ".yml", ".json", ".toml", ".cursorrules", ".windsurfrules"},
			axis:     axes.Security,
		},
	})
}
