package rules

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

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

// emojiZWJModifiers is the explicit set of Miscellaneous-Symbols-block
// codepoints that Unicode's recommended ZWJ sequences (RGI
// emoji-zwj-sequences: gender/role modifiers combined with a profession or
// activity pictograph, e.g. mage+ZWJ+MALE-SIGN) actually pair with a
// pictograph. Review round found the first version of this carve-out used
// the *whole* U+2600-U+27BF block instead, which also contains ordinary
// prose furniture — check marks (U+2713), scissors, arrows up through
// U+27BF — so a ZWJ between two check marks would have been exempt too.
// This explicit set is the corrected, auditable boundary: exactly the
// codepoints observed to appear in RGI role/profession ZWJ sequences,
// nothing wider.
var emojiZWJModifiers = map[rune]bool{
	0x2640: true, // FEMALE SIGN
	0x2642: true, // MALE SIGN
	0x2695: true, // STAFF OF AESCULAPIUS (medical)
	0x2696: true, // SCALES (judge)
	0x26A7: true, // MALE WITH STROKE AND MALE AND FEMALE SIGN (transgender)
	0x2602: true, // UMBRELLA
	0x2620: true, // SKULL AND CROSSBONES
	0x26D1: true, // HELMET WITH WHITE CROSS
	0x2708: true, // AIRPLANE
	0x2764: true, // HEAVY BLACK HEART
}

// isEmojiRune reports whether r is a pictograph emoji codepoint
// (U+1F300-U+1FAFF, Miscellaneous Symbols and Pictographs through Symbols
// and Pictographs Extended-A — covers the person/cook/mage/rocket glyphs
// observed in the bench corpus, Task 5b predicate_lift.py SD-002) or one
// of the explicit symbol-emoji modifiers in emojiZWJModifiers above. This
// deliberately does NOT cover regional-indicator flag pairs
// (U+1F1E6-U+1F1FF) or skin-tone modifiers (U+1F3FB-U+1F3FF): no sample in
// the corpus exercises either, so widening the definition to include them
// would be unmeasured. Used only to narrow the ZWJ carve-out below — it is
// not a general-purpose emoji detector.
func isEmojiRune(r rune) bool {
	if r >= 0x1F300 && r <= 0x1FAFF {
		return true
	}
	return emojiZWJModifiers[r]
}

// maxExemptZWJPerLine bounds how many ZWJ-between-emoji occurrences a
// single line may have exempted from the invisible-rune count. Every one
// of the 9 benign findings this carve-out targets (Task 5b,
// predicate_lift.py SD-002, results-task5.tsv) has exactly 1 qualifying
// ZWJ on its line — this cap keeps a wide safety margin above that
// observed maximum (legitimate multi-join sequences like a family or
// couple emoji commonly use 2-4 ZWJs) while still being orders of
// magnitude below the malicious corpus's steganographic runs (17-34
// invisible runes on one line). Review round flagged the unbounded
// version of this carve-out as a covert channel: encode one bit per
// adjacent emoji pair by choosing whether a ZWJ sits between them
// (unsupported ZWJ sequences render as the two emoji side by side, so
// 😀‍😀 and 😀😀 look identical to a human) — with no cap, every present
// ZWJ was exempt and the line stayed silent regardless of how many bits
// it carried. Beyond this cap, none of the line's qualifying ZWJs are
// exempted — the whole line is treated as untrusted, not just the
// excess.
const maxExemptZWJPerLine = 4

// zwjExemptIndices returns the indices within runes of every ZWJ character
// that sits strictly between two emoji codepoints (isEmojiRune on both
// neighbors) — the standard compound-emoji spelling, not a hidden payload.
// If more than maxExemptZWJPerLine qualify, none are exempted: past that
// cap the whole line is treated as untrusted rather than as an unusually
// long legitimate emoji sequence, closing the covert channel described on
// maxExemptZWJPerLine.
func zwjExemptIndices(runes []rune) map[int]bool {
	qualifying := make(map[int]bool)
	for idx, ru := range runes {
		if ru != '‍' {
			continue
		}
		if idx == 0 || idx == len(runes)-1 {
			continue
		}
		if isEmojiRune(runes[idx-1]) && isEmojiRune(runes[idx+1]) {
			qualifying[idx] = true
		}
	}
	if len(qualifying) > maxExemptZWJPerLine {
		return nil
	}
	return qualifying
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
		runes := []rune(lineStr)
		exemptZWJ := zwjExemptIndices(runes)
		for idx, ru := range runes {
			if !isInvisibleRune(ru) {
				continue
			}
			switch {
			case ru == '\uFEFF' && lineNum == 1 && idx == 0:
				// BOM at the very start of the file is legitimate.
			case exemptZWJ[idx]:
				// A ZWJ strictly between two emoji codepoints is the
				// standard Unicode ZWJ-sequence mechanism that composes
				// e.g. person+occupation into one glyph -- how the
				// character is spelled, not a hidden payload. Measured
				// (predicate_lift.py, SD-002, Task 5b, results-task5.tsv):
				// this shape is 9 of 10 benign SD-002 findings in the bench
				// corpus (ben%/mal% = 90%/0%, clearing the >=10 bar since
				// mal=0) and 0 of 29 malicious SD-002 findings -- the
				// corpus's real zero-width smuggling (a steganographic run
				// of ZWSP/ZWNJ/ZWJ, literal ZWJ padding after an injection
				// marker, ZWSP between plain words) never has a ZWJ with an
				// emoji codepoint on both sides. See zwjExemptIndices and
				// maxExemptZWJPerLine for the codepoint set and the cap
				// that keep this exemption from becoming an unbounded
				// covert channel.
			default:
				invisible++
			}
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
