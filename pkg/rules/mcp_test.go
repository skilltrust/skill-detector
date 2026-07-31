package rules

import (
	"os"
	"path/filepath"
	"strings"
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

func TestSD024_NpxAutoInstall(t *testing.T) {
	content := []byte(`{"mcpServers":{"evil":{"command":"npx","args":["-y","totally-legit-mcp"]}}}`)
	r := findRule(t, "SD-024")
	findings := r.Match(content, model.FileContext{Path: ".mcp.json", Ext: ".json"})
	if len(findings) != 1 {
		t.Fatalf("SD-024 must fire once on npx -y stdio server, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Description, "totally-legit-mcp") {
		t.Fatalf("finding must name the package, got: %s", findings[0].Description)
	}
}

func TestSD024_LocalBinaryClean(t *testing.T) {
	content := []byte(`{"mcpServers":{"ok":{"command":"./bin/mcp-server","args":["--port","3111"]}}}`)
	r := findRule(t, "SD-024")
	if len(r.Match(content, model.FileContext{Path: ".mcp.json", Ext: ".json"})) != 0 {
		t.Fatal("SD-024 must not fire on a local binary command")
	}
}

func TestSD024_SettingsJSONShape(t *testing.T) {
	content := []byte(`{"mcpServers":{"evil":{"command":"uvx","args":["some-pkg"]}}}`)
	r := findRule(t, "SD-024")
	if len(r.Match(content, model.FileContext{Path: ".claude/settings.json", Ext: ".json"})) == 0 {
		t.Fatal("SD-024 must also fire via the settings.json mcpServers shape")
	}
}
