package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

func TestClaudeMD_SQLInjection_Malicious(t *testing.T) {
	registry := NewRegistry()
	RegisterClaudeMDRules(registry)

	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "malicious", "claude-md-sql", "CLAUDE.md"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	ctx := model.FileContext{Path: "CLAUDE.md", Ext: ".md", Content: content}
	var findings []model.Finding
	for _, rule := range registry.RulesFor(".md") {
		findings = append(findings, rule.Match(content, ctx)...)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one SD-015 finding, got 0")
	}
	if findings[0].RuleID != "SD-015" {
		t.Errorf("RuleID = %q, want SD-015", findings[0].RuleID)
	}
	if findings[0].Axis != axes.Security {
		t.Errorf("Axis = %q, want security", findings[0].Axis)
	}
}

func TestClaudeMD_SQLInjection_Clean(t *testing.T) {
	registry := NewRegistry()
	RegisterClaudeMDRules(registry)

	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "clean", "claude-md-sql", "CLAUDE.md"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	ctx := model.FileContext{Path: "CLAUDE.md", Ext: ".md", Content: content}
	var findings []model.Finding
	for _, rule := range registry.RulesFor(".md") {
		findings = append(findings, rule.Match(content, ctx)...)
	}
	if len(findings) != 0 {
		t.Fatalf("clean fixture: got %d findings, want 0", len(findings))
	}
}

func TestClaudeMD_RuleIgnoresOtherMDFiles(t *testing.T) {
	registry := NewRegistry()
	RegisterClaudeMDRules(registry)

	content := []byte("SELECT * FROM users WHERE name = '\" + user_input + \"'")
	ctx := model.FileContext{Path: "README.md", Ext: ".md", Content: content}
	var findings []model.Finding
	for _, rule := range registry.RulesFor(".md") {
		findings = append(findings, rule.Match(content, ctx)...)
	}
	if len(findings) != 0 {
		t.Errorf("README.md should not be inspected by claude_md rules, got %d findings", len(findings))
	}
}
