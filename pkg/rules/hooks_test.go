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

func TestSD020_NestedHookSchema(t *testing.T) {
	content := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo $UNSANITIZED | sh"}]}]}}`)
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
		}
	}
	if count == 0 {
		t.Fatal("SD-020 must fire on nested hook schema with unquoted variable")
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

func TestSD020_ClaudeProvidedVarsExempt(t *testing.T) {
	content := []byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"./lint.sh $CLAUDE_PROJECT_DIR"}]}]}}`)
	r := findRule(t, "SD-020")
	if len(r.Match(content, model.FileContext{Path: ".claude/settings.json", Ext: ".json"})) != 0 {
		t.Fatal("harness-provided CLAUDE_* variables must not trigger SD-020")
	}
}

func TestSD020_OtherVarsStillFlagged(t *testing.T) {
	content := []byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"sh -c \"echo $UNTRUSTED\""}]}]}}`)
	r := findRule(t, "SD-020")
	if len(r.Match(content, model.FileContext{Path: ".claude/settings.json", Ext: ".json"})) == 0 {
		t.Fatal("non-CLAUDE_ unquoted variables must still trigger SD-020")
	}
}
