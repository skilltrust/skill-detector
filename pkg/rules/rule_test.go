package rules

import (
	"strings"
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

func TestExistingRulesHaveAxisAssigned(t *testing.T) {
	r := DefaultRegistry()
	for _, rule := range r.All() {
		if rule.Axis() == "" {
			t.Errorf("rule %s has no axis assigned", rule.ID())
		}
	}
}

func TestRuleAxisMappings(t *testing.T) {
	r := DefaultRegistry()
	expected := map[string]axes.Axis{
		"injection":                 axes.Security,
		"supply chain":              axes.Security,
		"supply_chain":              axes.Security,
		"supplychain":               axes.Security,
		"exfiltration":              axes.Security,
		"ssrf / data exfiltration":  axes.Security,
		"integrity":                 axes.Security,
		"security misconfiguration": axes.PermissionHygiene,
		"misconfiguration":          axes.PermissionHygiene,
		"broken access control":     axes.PermissionHygiene,
		"access control":            axes.PermissionHygiene,
		"access_control":            axes.PermissionHygiene,
		"accesscontrol":             axes.PermissionHygiene,
		"claudemd":                  axes.Security,
		"settingsjson":              axes.PermissionHygiene,
		"hooks":                     axes.Security,
		"mcp":                       axes.PermissionHygiene,
	}
	for _, rule := range r.All() {
		cat := strings.ToLower(rule.Category())
		wanted, ok := expected[cat]
		if !ok {
			t.Errorf("rule %s has uncategorized Category() %q (test needs updating)", rule.ID(), rule.Category())
			continue
		}
		if rule.Axis() != wanted {
			t.Errorf("rule %s (category %q) has axis %q, want %q",
				rule.ID(), rule.Category(), rule.Axis(), wanted)
		}
	}
}

func TestDefaultRegistryIncludesNewPacks(t *testing.T) {
	r := DefaultRegistry()
	want := []string{"SD-015", "SD-016", "SD-017", "SD-018", "SD-019", "SD-020", "SD-021"}
	got := make(map[string]bool)
	for _, rule := range r.All() {
		got[rule.ID()] = true
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("DefaultRegistry missing rule %s", id)
		}
	}
}
