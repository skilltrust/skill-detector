package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

func runSettingsRule(t *testing.T, fixturePath string) []model.Finding {
	t.Helper()
	content, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	registry := NewRegistry()
	RegisterSettingsJSONRules(registry)
	ctx := model.FileContext{Path: ".claude/settings.json", Ext: ".json", Content: content}
	var findings []model.Finding
	for _, rule := range registry.RulesFor(".json") {
		findings = append(findings, rule.Match(content, ctx)...)
	}
	return findings
}

func TestSettingsJSON_BashCurlWildcard_Malicious(t *testing.T) {
	findings := runSettingsRule(t, filepath.Join("..", "..", "testdata", "malicious", "settings-bash-curl", ".claude", "settings.json"))
	var sd017 []model.Finding
	for _, f := range findings {
		if f.RuleID == "SD-017" {
			sd017 = append(sd017, f)
		}
	}
	if len(sd017) < 3 {
		t.Fatalf("got %d SD-017 findings, want >= 3 (curl, wget, *)", len(sd017))
	}
	for _, f := range sd017 {
		if f.Axis != axes.PermissionHygiene {
			t.Errorf("finding %q axis = %q, want permission_hygiene", f.RuleID, f.Axis)
		}
		if f.Severity != model.SeverityHigh {
			t.Errorf("finding %q severity = %v, want High", f.RuleID, f.Severity)
		}
	}
}

func TestSettingsJSON_BashCurlWildcard_Clean(t *testing.T) {
	findings := runSettingsRule(t, filepath.Join("..", "..", "testdata", "clean", "settings-bash-curl", ".claude", "settings.json"))
	for _, f := range findings {
		if f.RuleID == "SD-017" {
			t.Errorf("clean fixture produced SD-017 finding: %+v", f)
		}
	}
}

func TestSettingsJSON_SubcommandLimitBypass_Malicious(t *testing.T) {
	findings := runSettingsRule(t, filepath.Join("..", "..", "testdata", "malicious", "settings-bypass", ".claude", "settings.json"))
	var got bool
	for _, f := range findings {
		if f.RuleID == "SD-018" {
			got = true
			if f.Severity != model.SeverityHigh {
				t.Errorf("severity = %v, want High", f.Severity)
			}
			if f.Axis != axes.PermissionHygiene {
				t.Errorf("axis = %q, want permission_hygiene", f.Axis)
			}
		}
	}
	if !got {
		t.Errorf("expected SD-018 finding, got: %+v", findings)
	}
}

func TestSettingsJSON_SubcommandLimitBypass_Clean(t *testing.T) {
	findings := runSettingsRule(t, filepath.Join("..", "..", "testdata", "clean", "settings-bypass", ".claude", "settings.json"))
	for _, f := range findings {
		if f.RuleID == "SD-018" {
			t.Errorf("clean fixture produced SD-018 finding: %+v", f)
		}
	}
}

func TestSettingsJSON_RuleIgnoresOtherJSON(t *testing.T) {
	registry := NewRegistry()
	RegisterSettingsJSONRules(registry)
	ctx := model.FileContext{
		Path:    "package.json",
		Ext:     ".json",
		Content: []byte(`{"permissions":{"allow":["Bash(curl *)"]}}`),
	}
	var findings []model.Finding
	for _, rule := range registry.RulesFor(".json") {
		findings = append(findings, rule.Match(ctx.Content, ctx)...)
	}
	if len(findings) != 0 {
		t.Errorf("package.json should not be inspected, got %d findings", len(findings))
	}
}
