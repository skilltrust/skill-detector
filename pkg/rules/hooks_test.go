package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

func TestHooks_ShellMetacharInterpolation_Malicious(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "malicious", "hooks-interp", ".claude", "settings.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	registry := NewRegistry()
	RegisterHooksRules(registry)
	ctx := model.FileContext{Path: ".claude/settings.json", Ext: ".json", Content: content}
	var findings []model.Finding
	for _, rule := range registry.RulesFor(".json") {
		findings = append(findings, rule.Match(content, ctx)...)
	}
	var count int
	for _, f := range findings {
		if f.RuleID == "SD-020" {
			count++
			if f.Axis != axes.Security {
				t.Errorf("axis = %q, want security", f.Axis)
			}
			if f.Severity != model.SeverityCritical {
				t.Errorf("severity = %v, want Critical", f.Severity)
			}
		}
	}
	if count < 2 {
		t.Errorf("expected >= 2 SD-020 findings, got %d", count)
	}
}

func TestHooks_ShellMetacharInterpolation_Clean(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "clean", "hooks-interp", ".claude", "settings.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	registry := NewRegistry()
	RegisterHooksRules(registry)
	ctx := model.FileContext{Path: ".claude/settings.json", Ext: ".json", Content: content}
	var findings []model.Finding
	for _, rule := range registry.RulesFor(".json") {
		findings = append(findings, rule.Match(content, ctx)...)
	}
	for _, f := range findings {
		if f.RuleID == "SD-020" {
			t.Errorf("clean fixture produced SD-020 finding: %+v", f)
		}
	}
}
