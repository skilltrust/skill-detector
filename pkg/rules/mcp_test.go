package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

func TestMCP_ExternalDomainReach_Malicious(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "malicious", "mcp-domain", ".mcp.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	registry := NewRegistry()
	RegisterMCPRules(registry)
	ctx := model.FileContext{Path: ".mcp.json", Ext: ".json", Content: content}
	var findings []model.Finding
	for _, rule := range registry.RulesFor(".json") {
		findings = append(findings, rule.Match(content, ctx)...)
	}
	var got bool
	for _, f := range findings {
		if f.RuleID == "SD-021" {
			got = true
			if f.Axis != axes.PermissionHygiene {
				t.Errorf("axis = %q, want permission_hygiene", f.Axis)
			}
			if f.Severity != model.SeverityMedium {
				t.Errorf("severity = %v, want Medium (use --strict-mcp to raise)", f.Severity)
			}
		}
	}
	if !got {
		t.Errorf("expected SD-021 finding, got: %+v", findings)
	}
}

func TestMCP_ExternalDomainReach_Clean(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "clean", "mcp-domain", ".mcp.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	registry := NewRegistry()
	RegisterMCPRules(registry)
	ctx := model.FileContext{Path: ".mcp.json", Ext: ".json", Content: content}
	var findings []model.Finding
	for _, rule := range registry.RulesFor(".json") {
		findings = append(findings, rule.Match(content, ctx)...)
	}
	for _, f := range findings {
		if f.RuleID == "SD-021" {
			t.Errorf("clean fixture produced SD-021 finding: %+v", f)
		}
	}
}
