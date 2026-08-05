package rules

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
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

// isInvisibleRune reports whether r can hide instructions from a human
// reader: zero-width chars, bidi embedding/override controls, or the
// Unicode Tags block (the standard invisible-payload channel for LLMs).
func isInvisibleRune(r rune) bool {
	switch r {
	case '\u200B', '\u200C', '\u200D', '\uFEFF', '\u2060', '\u200E', '\u200F':
		return true
	}
	if r >= 0x202A && r <= 0x202E {
		return true
	}
	return r >= 0xE0000 && r <= 0xE007F
}

// shellFenceLangs are the ``` fence info-string languages SD-001 treats as
// shell content, plus the empty string — untagged fences commonly contain
// shell too. Any other tag (js, jsx, ts, tsx, python, go, json, yaml, ...)
// is skipped: those fences hold non-shell code where backtick-delimited
// `${var}` is template-literal syntax, not shell command substitution.
var shellFenceLangs = map[string]bool{
	"":         true,
	"bash":     true,
	"sh":       true,
	"zsh":      true,
	"shell":    true,
	"console":  true,
	"terminal": true,
}

// shellFencedLines returns the 1-based line numbers inside ``` fenced code
// blocks whose opening fence is tagged as shell (or untagged). Lines inside
// fences tagged with a non-shell language (```js, ```python, ...) are
// excluded.
func shellFencedLines(content []byte) map[int]bool {
	out := make(map[int]bool)
	inFence := false
	shellFence := false
	for i, line := range bytes.Split(content, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("```")) {
			if !inFence {
				lang := ""
				if fields := strings.Fields(string(trimmed[3:])); len(fields) > 0 {
					lang = strings.ToLower(fields[0])
				}
				shellFence = shellFenceLangs[lang]
				inFence = true
			} else {
				inFence = false
				shellFence = false
			}
			continue
		}
		if inFence && shellFence {
			out[i+1] = true
		}
	}
	return out
}

type shellInjectionRule struct {
	baseRule
}

func (r *shellInjectionRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsAgentFile(ctx.Path) && !isInAgentConfigDir(ctx.Path) {
		return nil
	}
	var fenced map[int]bool
	if strings.HasSuffix(ctx.Path, ".md") {
		fenced = shellFencedLines(content)
	}
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1
		if fenced != nil && !fenced[lineNum] {
			continue
		}
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

		// Detect invisible Unicode characters (zero-width, bidi overrides, Unicode Tags block).
		invisible := 0
		byteOff := 0
		for _, ru := range lineStr {
			if isInvisibleRune(ru) {
				// BOM at the very start of the file is legitimate.
				if ru != '\uFEFF' || lineNum != 1 || byteOff != 0 {
					invisible++
				}
			}
			byteOff += utf8.RuneLen(ru)
		}
		if invisible > 0 {
			findings = append(findings, r.newFinding(ctx, lineNum,
				fmt.Sprintf("%d invisible Unicode character(s) detected in prompt template", invisible),
				"Remove invisible Unicode characters that could hide malicious instructions"))
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
			types:    []string{".sh", ".bash", ".zsh", ".md", ""},
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
