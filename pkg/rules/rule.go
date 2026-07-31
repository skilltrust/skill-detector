package rules

import (
	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// Rule is the interface that all detection rules must implement.
type Rule interface {
	ID() string
	Name() string
	Severity() model.Severity
	Category() string
	FileTypes() []string
	Match(content []byte, ctx model.FileContext) []model.Finding
	Axis() axes.Axis
}

// ContentScanTypes is the extension set for line-oriented content rules:
// every scannable config/doc extension plus script languages and the empty
// extension (extensionless hook scripts inside agent config dirs).
var ContentScanTypes = []string{
	".sh", ".bash", ".zsh", ".md", ".yaml", ".yml", ".txt", ".json", ".toml",
	".env", ".cfg", ".conf", ".ini", ".xml",
	".py", ".js", ".ts", ".mjs", ".rb", ".pl", ".ps1", "",
}

// baseRule embeds common fields shared by all rules.
type baseRule struct {
	id       string
	name     string
	severity model.Severity
	category string
	types    []string
	axis     axes.Axis
}

func (b *baseRule) ID() string               { return b.id }
func (b *baseRule) Name() string             { return b.name }
func (b *baseRule) Severity() model.Severity { return b.severity }
func (b *baseRule) Category() string         { return b.category }
func (b *baseRule) FileTypes() []string      { return b.types }
func (b *baseRule) Axis() axes.Axis          { return b.axis }

// newFinding constructs a Finding pre-filled with the rule's metadata,
// including the axis assignment so rule code cannot forget it.
func (b *baseRule) newFinding(ctx model.FileContext, line int, desc, remediation string) model.Finding {
	return model.Finding{
		RuleID:      b.id,
		RuleName:    b.name,
		Severity:    b.severity,
		EffSeverity: b.severity,
		Category:    b.category,
		Description: desc,
		FilePath:    ctx.Path,
		Line:        line,
		Confidence:  model.ConfidenceMedium,
		Remediation: remediation,
		Axis:        b.axis,
	}
}
