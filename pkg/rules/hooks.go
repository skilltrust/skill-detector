package rules

import (
	"regexp"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// reUnquotedVar captures $VAR / ${VAR} not preceded by a double quote.
// Heuristic: variable preceded by anything other than ". CLAUDE_*-prefixed
// variables are harness-provided (e.g. $CLAUDE_PROJECT_DIR) and are exempted
// at the call site — they're not attacker-controlled input.
var reUnquotedVar = regexp.MustCompile(`(^|[^"])\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)

type hookInterpolationRule struct {
	baseRule
}

func (r *hookInterpolationRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsClaudeSettings(ctx.Path) {
		return nil
	}
	s, err := parseClaudeSettings(content)
	if err != nil {
		return nil
	}
	var findings []model.Finding
	for hookName, raw := range s.Hooks {
		for _, cmd := range hookCommands(raw) {
			flagged := false
			for _, m := range reUnquotedVar.FindAllStringSubmatch(cmd, -1) {
				if !strings.HasPrefix(m[2], "CLAUDE_") {
					flagged = true
					break
				}
			}
			if flagged {
				findings = append(findings, r.newFinding(ctx, 1,
					"hook "+hookName+" interpolates unquoted shell variable: "+cmd,
					"Quote all variable expansions: use \"${VAR}\" not $VAR; sanitize untrusted input before interpolation"))
			}
		}
	}
	return findings
}

// RegisterHooksRules registers all hook-class rules.
func RegisterHooksRules(registry *RuleRegistry) {
	registry.Register(&hookInterpolationRule{
		baseRule: baseRule{
			id:       "SD-020",
			name:     "Hook Shell Metacharacter Interpolation",
			severity: model.SeverityCritical,
			category: "Hooks",
			types:    []string{".json"},
			axis:     axes.Security,
		},
	})
}
