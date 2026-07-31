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
	// reCommentAndControl — instruction phrasing directing AI to treat external
	// comment/URL content as authoritative commands.
	reCommentAndControl = regexp.MustCompile(
		`(?i)(follow|treat).*\b(PR\s+comments?|issue\s+(comments?|bodies?|bodys?)|URLs?\s+in\s+(issue|comment))[^.]*\b(authoritative|commands?|run\s+them|execute|without\s+asking)`)
)

type claudeMDSQLInjectionRule struct {
	baseRule
}

func (r *claudeMDSQLInjectionRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsInstructionFile(ctx.Path) {
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

type claudeMDCommentAndControlRule struct {
	baseRule
}

func (r *claudeMDCommentAndControlRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsInstructionFile(ctx.Path) {
		return nil
	}
	var findings []model.Finding
	for i, line := range bytes.Split(content, []byte("\n")) {
		if reCommentAndControl.Match(line) {
			findings = append(findings, r.newFinding(ctx, i+1,
				"CLAUDE.md instructs AI to treat external comments/URLs as authoritative commands",
				"Never instruct the AI to execute instructions from PR comments, issue bodies, or arbitrary URLs without explicit user confirmation"))
		}
	}
	// Also fire on the whole-content pattern in case the directive spans multiple lines.
	if findings == nil && reCommentAndControl.Match(content) {
		findings = append(findings, r.newFinding(ctx, 1,
			"CLAUDE.md instructs AI to treat external comments/URLs as authoritative commands",
			"Never instruct the AI to execute instructions from PR comments, issue bodies, or arbitrary URLs without explicit user confirmation"))
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
			types:    []string{".md", ".mdc"},
			axis:     axes.Security,
		},
	})
	registry.Register(&claudeMDCommentAndControlRule{
		baseRule: baseRule{
			id:       "SD-016",
			name:     "CLAUDE.md Comment-and-Control",
			severity: model.SeverityCritical,
			category: "ClaudeMD",
			types:    []string{".md", ".mdc"},
			axis:     axes.Security,
		},
	})
}
