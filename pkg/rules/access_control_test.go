package rules

import (
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
)

func TestCredentialAccessRule(t *testing.T) {
	registry := NewRegistry()
	RegisterAccessControlRules(registry)

	tests := []struct {
		name        string
		content     string
		ext         string
		wantCount   int
		wantRuleID  string
		wantLine    int
		wantDescSub string // substring that must appear in description
	}{
		{
			name:        "aws credentials access",
			content:     "#!/bin/bash\ncat ~/.aws/credentials",
			ext:         ".sh",
			wantCount:   1,
			wantRuleID:  "SD-004",
			wantLine:    2,
			wantDescSub: "~/.aws/",
		},
		{
			name:        "ssh key access",
			content:     "cat ~/.ssh/id_rsa",
			ext:         ".sh",
			wantCount:   1,
			wantRuleID:  "SD-004",
			wantLine:    1,
			wantDescSub: "~/.ssh/",
		},
		{
			name:        "etc shadow access",
			content:     "cat /etc/shadow",
			ext:         ".sh",
			wantCount:   1,
			wantRuleID:  "SD-004",
			wantLine:    1,
			wantDescSub: "/etc/shadow",
		},
		{
			name:      "clean script produces no findings",
			content:   "#!/bin/bash\necho hello\nmkdir -p ./data",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:      "multiple credential paths on separate lines",
			content:   "#!/bin/bash\ncat ~/.aws/credentials\ncat /etc/shadow",
			ext:       ".sh",
			wantCount: 2,
		},
		{
			name:        "credentials in markdown file",
			content:     "Read ~/.aws/credentials for config",
			ext:         ".md",
			wantCount:   1,
			wantRuleID:  "SD-004",
			wantLine:    1,
			wantDescSub: "~/.aws/",
		},
		{
			name:        "gnupg access",
			content:     "cp ~/.gnupg/secring.gpg /tmp/",
			ext:         ".sh",
			wantCount:   1,
			wantRuleID:  "SD-004",
			wantDescSub: "~/.gnupg/",
		},
		{
			name:        "dotenv access",
			content:     "cat ~/.env",
			ext:         ".sh",
			wantCount:   1,
			wantRuleID:  "SD-004",
			wantDescSub: "~/.env",
		},
		{
			name:        "etc passwd access",
			content:     "cat /etc/passwd",
			ext:         ".sh",
			wantCount:   1,
			wantRuleID:  "SD-004",
			wantDescSub: "/etc/passwd",
		},
		{
			name:        "generic credentials file",
			content:     "cat .credentials",
			ext:         ".sh",
			wantCount:   1,
			wantRuleID:  "SD-004",
			wantDescSub: ".credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := model.FileContext{Path: "skill.yaml", Ext: tt.ext, Content: []byte(tt.content)}
			rules := registry.RulesFor(tt.ext)
			var findings []model.Finding
			for _, rule := range rules {
				if rule.ID() == "SD-004" {
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
			if tt.wantDescSub != "" && tt.wantCount > 0 {
				if !strings.Contains(findings[0].Description, tt.wantDescSub) {
					t.Errorf("Description = %q, want substring %q", findings[0].Description, tt.wantDescSub)
				}
			}
		})
	}
}

func TestPathTraversalRule(t *testing.T) {
	registry := NewRegistry()
	RegisterAccessControlRules(registry)

	tests := []struct {
		name        string
		content     string
		ext         string
		wantCount   int
		wantRuleID  string
		wantDescSub string // substring that must appear in description
	}{
		{
			name:       "path traversal with ../",
			content:    "cat ../../etc/passwd",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-003",
		},
		{
			name:        "absolute path /etc/",
			content:     "read /etc/hosts",
			ext:         ".sh",
			wantCount:   1,
			wantRuleID:  "SD-003",
			wantDescSub: "/etc/hosts",
		},
		{
			name:        "absolute path /home/",
			content:     "ls /home/user/",
			ext:         ".sh",
			wantCount:   1,
			wantRuleID:  "SD-003",
			wantDescSub: "/home/user/",
		},
		{
			name:      "safe relative path",
			content:   "cat ./data/input.txt",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:      "URL with ../ is not traversal",
			content:   "curl https://example.com/../api",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:       "windows absolute path",
			content:    "read C:\\Users\\secrets",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-003",
		},
		{
			name:      "clean script no paths",
			content:   "echo hello",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:       "traversal in markdown",
			content:    "source: ../../etc/shadow",
			ext:        ".md",
			wantCount:  1,
			wantRuleID: "SD-003",
		},
		{
			name:        "absolute /root/ path",
			content:     "cp /root/.bashrc .",
			ext:         ".sh",
			wantCount:   1,
			wantRuleID:  "SD-003",
			wantDescSub: "/root/.bashrc",
		},
		{
			name:        "absolute /tmp/ path",
			content:     "write /tmp/output",
			ext:         ".yaml",
			wantCount:   1,
			wantRuleID:  "SD-003",
			wantDescSub: "/tmp/output",
		},
		{
			name:        "absolute path on line with URL is still detected",
			content:     "cat /etc/shadow # see https://example.com",
			ext:         ".sh",
			wantCount:   1,
			wantRuleID:  "SD-003",
			wantDescSub: "/etc/shadow",
		},
		{
			name:        "traversal suppressed but absolute path still detected",
			content:     "curl https://example.com/../api /etc/hosts",
			ext:         ".sh",
			wantCount:   1, // ../ suppressed by URL, but /etc/ detected independently
			wantRuleID:  "SD-003",
			wantDescSub: "/etc/hosts",
		},
		{
			name:        "shell metacharacters not captured in path",
			content:     "cat /etc/passwd;rm -rf /",
			ext:         ".sh",
			wantCount:   1,
			wantRuleID:  "SD-003",
			wantDescSub: "/etc/passwd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := model.FileContext{Path: "skill.yaml", Ext: tt.ext, Content: []byte(tt.content)}
			rules := registry.RulesFor(tt.ext)
			var findings []model.Finding
			for _, rule := range rules {
				if rule.ID() == "SD-003" {
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
			if tt.wantDescSub != "" && tt.wantCount > 0 {
				if !strings.Contains(findings[0].Description, tt.wantDescSub) {
					t.Errorf("Description = %q, want substring %q", findings[0].Description, tt.wantDescSub)
				}
			}
		})
	}
}

func TestPathTraversalFindingFields(t *testing.T) {
	registry := NewRegistry()
	RegisterAccessControlRules(registry)

	ctx := model.FileContext{Path: "skill.yaml", Ext: ".yaml", Content: []byte("source: ../../etc/passwd")}
	rules := registry.RulesFor(".yaml")
	var findings []model.Finding
	for _, rule := range rules {
		if rule.ID() == "SD-003" {
			findings = append(findings, rule.Match(ctx.Content, ctx)...)
		}
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.RuleID != "SD-003" {
		t.Errorf("RuleID = %q, want %q", f.RuleID, "SD-003")
	}
	if f.Category != "Broken Access Control" {
		t.Errorf("Category = %q, want %q", f.Category, "Broken Access Control")
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("Severity = %v, want High", f.Severity)
	}
	if f.RuleName != "Path Traversal" {
		t.Errorf("RuleName = %q, want %q", f.RuleName, "Path Traversal")
	}
	if f.Confidence != model.ConfidenceMedium {
		t.Errorf("Confidence = %v, want Medium", f.Confidence)
	}
	if f.Remediation == "" {
		t.Error("Remediation should not be empty")
	}
}

func TestCredentialAccessFindingFields(t *testing.T) {
	registry := NewRegistry()
	RegisterAccessControlRules(registry)

	ctx := model.FileContext{Path: "skill.yaml", Ext: ".sh", Content: []byte("cat ~/.aws/credentials")}
	rules := registry.RulesFor(".sh")
	var findings []model.Finding
	for _, rule := range rules {
		if rule.ID() == "SD-004" {
			findings = append(findings, rule.Match(ctx.Content, ctx)...)
		}
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.RuleID != "SD-004" {
		t.Errorf("RuleID = %q, want %q", f.RuleID, "SD-004")
	}
	if f.Category != "Broken Access Control" {
		t.Errorf("Category = %q, want %q", f.Category, "Broken Access Control")
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("Severity = %v, want Critical", f.Severity)
	}
	if f.RuleName != "Credential Access" {
		t.Errorf("RuleName = %q, want %q", f.RuleName, "Credential Access")
	}
	if f.FilePath != "skill.yaml" {
		t.Errorf("FilePath = %q, want %q", f.FilePath, "skill.yaml")
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

func TestSD003_GatesNonAgentFile(t *testing.T) {
	content := []byte("source: ../../etc/passwd")
	ctx := model.FileContext{Path: "node_modules/foo/README.md", Ext: ".md", Content: content}
	registry := NewRegistry()
	RegisterAccessControlRules(registry)
	var findings []model.Finding
	for _, r := range registry.RulesFor(".md") {
		findings = append(findings, r.Match(content, ctx)...)
	}
	for _, f := range findings {
		if f.RuleID == "SD-003" {
			t.Errorf("SD-003 should not fire on non-agent file, got: %+v", f)
		}
	}
}

func TestSD004_GatesNonAgentFile(t *testing.T) {
	content := []byte("Read ~/.aws/credentials for config")
	ctx := model.FileContext{Path: "node_modules/foo/README.md", Ext: ".md", Content: content}
	registry := NewRegistry()
	RegisterAccessControlRules(registry)
	var findings []model.Finding
	for _, r := range registry.RulesFor(".md") {
		findings = append(findings, r.Match(content, ctx)...)
	}
	for _, f := range findings {
		if f.RuleID == "SD-004" {
			t.Errorf("SD-004 should not fire on non-agent file, got: %+v", f)
		}
	}
}

func TestRegistryFileTypeDispatch(t *testing.T) {
	registry := NewRegistry()
	RegisterInjectionRules(registry)
	RegisterAccessControlRules(registry)

	// .md file should NOT get SD-001 (shell injection) rules
	mdRules := registry.RulesFor(".md")
	for _, r := range mdRules {
		if r.ID() == "SD-001" {
			t.Error("SD-001 should not apply to .md files")
		}
	}

	// .md file SHOULD get SD-002 (prompt injection), SD-003 (path traversal), SD-004 (credential access)
	mdIDs := map[string]bool{}
	for _, r := range mdRules {
		mdIDs[r.ID()] = true
	}
	if !mdIDs["SD-002"] {
		t.Error("SD-002 should apply to .md files")
	}
	if !mdIDs["SD-003"] {
		t.Error("SD-003 should apply to .md files")
	}
	if !mdIDs["SD-004"] {
		t.Error("SD-004 should apply to .md files")
	}

	// .sh file should get SD-001, SD-003, SD-004 (but NOT SD-002)
	shRules := registry.RulesFor(".sh")
	shIDs := map[string]bool{}
	for _, r := range shRules {
		shIDs[r.ID()] = true
	}
	if !shIDs["SD-001"] {
		t.Error("SD-001 should apply to .sh files")
	}
	if shIDs["SD-002"] {
		t.Error("SD-002 should NOT apply to .sh files")
	}
	if !shIDs["SD-003"] {
		t.Error("SD-003 should apply to .sh files")
	}
	if !shIDs["SD-004"] {
		t.Error("SD-004 should apply to .sh files")
	}
}
