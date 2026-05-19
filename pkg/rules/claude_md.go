package rules

import (
	"bytes"
	"regexp"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

var (
	// reRawSQLConcat — a SQL keyword followed by string concatenation with
	// what looks like a variable.
	reRawSQLConcat = regexp.MustCompile(
		`(?i)(SELECT|INSERT|UPDATE|DELETE)\s.+(["'])\s*\+\s*\w+`)
	// reSQLInstruction — instruction phrasing directing AI to build raw SQL.
	reSQLInstruction = regexp.MustCompile(
		`(?i)construct\s+(the\s+)?SQL\s+like|build\s+(the\s+)?query\s+as`)
)

type claudeMDSQLInjectionRule struct {
	baseRule
}

func (r *claudeMDSQLInjectionRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsClaudeMD(ctx.Path) {
		return nil
	}
	var findings []model.Finding
	hitInstruction := reSQLInstruction.Match(content)
	for i, line := range bytes.Split(content, []byte("\n")) {
		if reRawSQLConcat.Match(line) && hitInstruction {
			findings = append(findings, r.newFinding(ctx, i+1,
				"CLAUDE.md instructs raw SQL construction with string concatenation",
				"Direct the AI to use parameterized queries or an ORM; never instruct string-concatenation SQL"))
		}
	}
	return findings
}

// RegisterClaudeMDRules registers all CLAUDE.md-class rules.
func RegisterClaudeMDRules(registry *RuleRegistry) {
	registry.Register(&claudeMDSQLInjectionRule{
		baseRule: baseRule{
			id:       "SD-015",
			name:     "CLAUDE.md SQL Injection By Instruction",
			severity: model.SeverityHigh,
			category: "ClaudeMD",
			types:    []string{".md"},
			axis:     axes.Security,
		},
	})
}
