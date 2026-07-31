package rules

import (
	"regexp"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// reUnquotedVar matches $VAR or ${VAR} that is NOT inside a double-quoted
// string. Heuristic: variable preceded by anything other than ".
var reUnquotedVar = regexp.MustCompile(`(^|[^"])\$\{?[A-Za-z_][A-Za-z0-9_]*\}?`)

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
			if reUnquotedVar.MatchString(cmd) {
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
