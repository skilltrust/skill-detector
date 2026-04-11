package rules

import (
	"testing"

	"github.com/velzepooz/skill-detector/internal/model"
)

func TestWorldWritableRule(t *testing.T) {
	registry := NewRegistry()
	RegisterMisconfigurationRules(registry)

	tests := []struct {
		name       string
		content    string
		ext        string
		wantCount  int
		wantRuleID string
		wantLine   int
	}{
		{
			name:       "chmod 777",
			content:    "chmod 777 /tmp/data",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-005",
			wantLine:   1,
		},
		{
			name:       "chmod 666",
			content:    "chmod 666 somefile",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-005",
			wantLine:   1,
		},
		{
			name:       "chmod a+w",
			content:    "chmod a+w somefile",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-005",
			wantLine:   1,
		},
		{
			name:       "chmod o+w",
			content:    "chmod o+w somefile",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-005",
			wantLine:   1,
		},
		{
			name:       "chmod +w",
			content:    "chmod +w somefile",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-005",
			wantLine:   1,
		},
		{
			name:       "chmod 777 on second line",
			content:    "#!/bin/bash\nchmod 777 /var/data",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-005",
			wantLine:   2,
		},
		{
			name:      "chmod u+w is safe",
			content:   "chmod u+w myfile",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:      "safe chmod 700",
			content:   "chmod 700 myfile",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:      "safe chmod 600",
			content:   "chmod 600 myfile",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:      "clean script no chmod",
			content:   "echo hello",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:       "chmod in yaml file",
			content:    "run: chmod 777 /data",
			ext:        ".yaml",
			wantCount:  1,
			wantRuleID: "SD-005",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := model.FileContext{Path: "test" + tt.ext, Ext: tt.ext, Content: []byte(tt.content)}
			rules := registry.RulesFor(tt.ext)
			var findings []model.Finding
			for _, rule := range rules {
				if rule.ID() == "SD-005" {
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

func TestHardcodedSecretRule(t *testing.T) {
	registry := NewRegistry()
	RegisterMisconfigurationRules(registry)

	tests := []struct {
		name       string
		content    string
		ext        string
		wantCount  int
		wantRuleID string
		wantLine   int
	}{
		{
			name:       "AWS access key",
			content:    "key=AKIAIOSFODNN7EXAMPLE",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-006",
			wantLine:   1,
		},
		{
			name:       "OpenAI API key",
			content:    "sk-proj-abc123def456ghi789jkl012mno",
			ext:        ".yaml",
			wantCount:  1,
			wantRuleID: "SD-006",
		},
		{
			name:       "GitHub PAT",
			content:    "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			ext:        ".yaml",
			wantCount:  1,
			wantRuleID: "SD-006",
		},
		{
			name:       "Slack token",
			content:    "SLACK_TOKEN=xoxb-123456-abcdefgh",
			ext:        ".env",
			wantCount:  1,
			wantRuleID: "SD-006",
		},
		{
			name:       "generic secret assignment",
			content:    `api_key="aVeryLongSecretValue1234567890abcdef"`,
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-006",
		},
		{
			name:      "clean file no secrets",
			content:   "echo hello world",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:      "short value not a secret",
			content:   `key="short"`,
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:       "GitHub gho_ token",
			content:    "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-006",
		},
		{
			name:       "xoxp Slack token",
			content:    "xoxp-123456789-abcdefghijk",
			ext:        ".yaml",
			wantCount:  1,
			wantRuleID: "SD-006",
		},
		{
			name:       "generic password assignment",
			content:    `password="SuperSecretPassword1234567890"`,
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-006",
		},
		{
			name:       "multiple secrets",
			content:    "AKIAIOSFODNN7EXAMPLE\nsk-proj-abc123def456ghi789jkl012mno",
			ext:        ".sh",
			wantCount:  2,
			wantRuleID: "SD-006",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := model.FileContext{Path: "test" + tt.ext, Ext: tt.ext, Content: []byte(tt.content)}
			rules := registry.RulesFor(tt.ext)
			var findings []model.Finding
			for _, rule := range rules {
				if rule.ID() == "SD-006" {
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

func TestWorldWritableFindingFields(t *testing.T) {
	registry := NewRegistry()
	RegisterMisconfigurationRules(registry)

	ctx := model.FileContext{Path: "setup.sh", Ext: ".sh", Content: []byte("chmod 777 /tmp/data")}
	rules := registry.RulesFor(".sh")
	var findings []model.Finding
	for _, rule := range rules {
		if rule.ID() == "SD-005" {
			findings = append(findings, rule.Match(ctx.Content, ctx)...)
		}
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.RuleID != "SD-005" {
		t.Errorf("RuleID = %q, want %q", f.RuleID, "SD-005")
	}
	if f.Category != "Security Misconfiguration" {
		t.Errorf("Category = %q, want %q", f.Category, "Security Misconfiguration")
	}
	if f.Severity != model.SeverityMedium {
		t.Errorf("Severity = %v, want Medium", f.Severity)
	}
	if f.RuleName != "World-Writable Permissions" {
		t.Errorf("RuleName = %q, want %q", f.RuleName, "World-Writable Permissions")
	}
	if f.FilePath != "setup.sh" {
		t.Errorf("FilePath = %q, want %q", f.FilePath, "setup.sh")
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

func TestHardcodedSecretFindingFields(t *testing.T) {
	registry := NewRegistry()
	RegisterMisconfigurationRules(registry)

	ctx := model.FileContext{Path: "config.yaml", Ext: ".yaml", Content: []byte("key: AKIAIOSFODNN7EXAMPLE")}
	rules := registry.RulesFor(".yaml")
	var findings []model.Finding
	for _, rule := range rules {
		if rule.ID() == "SD-006" {
			findings = append(findings, rule.Match(ctx.Content, ctx)...)
		}
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.RuleID != "SD-006" {
		t.Errorf("RuleID = %q, want %q", f.RuleID, "SD-006")
	}
	if f.Category != "Security Misconfiguration" {
		t.Errorf("Category = %q, want %q", f.Category, "Security Misconfiguration")
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("Severity = %v, want Critical", f.Severity)
	}
	if f.RuleName != "Hardcoded Secret" {
		t.Errorf("RuleName = %q, want %q", f.RuleName, "Hardcoded Secret")
	}
	if f.FilePath != "config.yaml" {
		t.Errorf("FilePath = %q, want %q", f.FilePath, "config.yaml")
	}
	if f.Confidence != model.ConfidenceMedium {
		t.Errorf("Confidence = %v, want Medium", f.Confidence)
	}
	if f.Remediation == "" {
		t.Error("Remediation should not be empty")
	}
}
