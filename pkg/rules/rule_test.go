package rules

import (
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

func TestBaseRuleAxisStamping(t *testing.T) {
	b := baseRule{
		id:       "TEST-001",
		name:     "Test",
		severity: model.SeverityHigh,
		category: "Test",
		types:    []string{".md"},
		axis:     axes.Security,
	}
	f := b.newFinding(model.FileContext{Path: "x.md", Ext: ".md"}, 1, "desc", "remed")
	if f.Axis != axes.Security {
		t.Errorf("Axis = %q, want %q", f.Axis, axes.Security)
	}
	if b.Axis() != axes.Security {
		t.Errorf("Axis() = %q, want %q", b.Axis(), axes.Security)
	}
}
