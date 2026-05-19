package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
)

func TestPostInstallRule(t *testing.T) {
	registry := NewRegistry()
	RegisterIntegrityRules(registry)

	tests := []struct {
		name       string
		content    string
		ext        string
		wantCount  int
		wantRuleID string
		wantLine   int
	}{
		{
			name:       "postinstall function",
			content:    "postinstall() { echo done; }",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-012",
			wantLine:   1,
		},
		{
			name:       "pre_install reference",
			content:    "run pre_install step",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-012",
			wantLine:   1,
		},
		{
			name:       "post-install hyphenated",
			content:    "echo post-install hook",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-012",
			wantLine:   1,
		},
		{
			name:       "after_install reference",
			content:    "after_install()",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-012",
			wantLine:   1,
		},
		{
			name:       "before_install reference",
			content:    "before_install steps:",
			ext:        ".md",
			wantCount:  1,
			wantRuleID: "SD-012",
			wantLine:   1,
		},
		{
			name:       "on_install reference",
			content:    "on_install callback",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-012",
			wantLine:   1,
		},
		{
			name:       "npm postinstall script",
			content:    "\"postinstall\": \"node setup.js\"",
			ext:        ".json",
			wantCount:  1,
			wantRuleID: "SD-012",
			wantLine:   1,
		},
		{
			name:       "npm prepare script",
			content:    "\"prepare\": \"husky install\"",
			ext:        ".json",
			wantCount:  1,
			wantRuleID: "SD-012",
			wantLine:   1,
		},
		{
			name:       "npm prepublish script",
			content:    "\"prepublish\": \"npm run build\"",
			ext:        ".json",
			wantCount:  1,
			wantRuleID: "SD-012",
			wantLine:   1,
		},
		{
			name:      "empty content",
			content:   "",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:      "clean script no post-install",
			content:   "echo hello world\nmkdir -p ./data",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:      "case insensitive PostInstall",
			content:   "PostInstall hook runs",
			ext:       ".md",
			wantCount: 1,
		},
		{
			name:       "multiline with install on line 3",
			content:    "line1\nline2\npost_install() {",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-012",
			wantLine:   3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := model.FileContext{Path: "test" + tt.ext, Ext: tt.ext, Content: []byte(tt.content)}
			rr := registry.RulesFor(tt.ext)
			var findings []model.Finding
			for _, rule := range rr {
				if rule.ID() == "SD-012" {
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

func TestPersistenceRule(t *testing.T) {
	registry := NewRegistry()
	RegisterIntegrityRules(registry)

	tests := []struct {
		name       string
		content    string
		ext        string
		wantCount  int
		wantRuleID string
		wantLine   int
	}{
		{
			name:       "crontab command",
			content:    "crontab -e",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "cron directory ref",
			content:    "cp job /etc/cron.d/evil",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "cron daily directory",
			content:    "cp job /etc/cron.daily/evil",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "cron hourly directory",
			content:    "cp job /etc/cron.hourly/evil",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "var spool cron",
			content:    "ls /var/spool/cron/root",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "launch agent keyword",
			content:    "launchctl load agent.plist",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "LaunchAgent reference",
			content:    "Install the LaunchAgent plist",
			ext:        ".md",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "LaunchDaemon reference",
			content:    "cp plist /Library/LaunchDaemons/evil.plist",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "LaunchAgents path",
			content:    "cp x ~/Library/LaunchAgents/evil.plist",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "systemctl enable",
			content:    "systemctl enable evil.service",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "systemctl start",
			content:    "systemctl start evil.service",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "etc systemd path",
			content:    "cp evil.service /etc/systemd/system/",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "bashrc modification",
			content:    "echo 'evil' >> ~/.bashrc",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "zshrc modification",
			content:    "echo 'evil' >> ~/.zshrc",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "bash_profile modification",
			content:    "echo 'evil' >> ~/.bash_profile",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "profile modification",
			content:    "echo 'evil' >> ~/.profile",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "windows schtasks",
			content:    "schtasks /create /tn evil",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:       "windows Register-ScheduledTask",
			content:    "Register-ScheduledTask -Action $action",
			ext:        ".txt",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   1,
		},
		{
			name:      "empty content",
			content:   "",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:      "clean script no persistence",
			content:   "echo hello world\nmkdir -p ./data",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:       "multiline crontab on line 2",
			content:    "#!/bin/bash\ncrontab -l",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-013",
			wantLine:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := model.FileContext{Path: "test" + tt.ext, Ext: tt.ext, Content: []byte(tt.content)}
			rr := registry.RulesFor(tt.ext)
			var findings []model.Finding
			for _, rule := range rr {
				if rule.ID() == "SD-013" {
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

func TestGitHookRule(t *testing.T) {
	registry := NewRegistry()
	RegisterIntegrityRules(registry)

	tests := []struct {
		name       string
		content    string
		ext        string
		wantCount  int
		wantRuleID string
		wantLine   int
	}{
		{
			name:       "git hooks path reference",
			content:    "cp payload.sh .git/hooks/pre-commit",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-014",
			wantLine:   1,
		},
		{
			name:       "git config hooksPath",
			content:    "git config core.hooksPath /tmp/evil-hooks",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-014",
			wantLine:   1,
		},
		{
			name:       "core.hooksPath assignment",
			content:    "core.hooksPath = /tmp/hooks",
			ext:        ".cfg",
			wantCount:  1,
			wantRuleID: "SD-014",
			wantLine:   1,
		},
		{
			name:       "git hooks post-commit",
			content:    "echo evil > .git/hooks/post-commit",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-014",
			wantLine:   1,
		},
		{
			name:      "empty content",
			content:   "",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:      "clean script no git hooks",
			content:   "echo hello world\ngit commit -m test",
			ext:       ".sh",
			wantCount: 0,
		},
		{
			name:       "both patterns on same line produces one finding",
			content:    "git config core.hooksPath .git/hooks/",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-014",
			wantLine:   1,
		},
		{
			name:       "multiline git hooks on line 3",
			content:    "line1\nline2\ncp evil .git/hooks/pre-push",
			ext:        ".sh",
			wantCount:  1,
			wantRuleID: "SD-014",
			wantLine:   3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := model.FileContext{Path: "test" + tt.ext, Ext: tt.ext, Content: []byte(tt.content)}
			rr := registry.RulesFor(tt.ext)
			var findings []model.Finding
			for _, rule := range rr {
				if rule.ID() == "SD-014" {
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

func TestIntegrityFindingFields(t *testing.T) {
	registry := NewRegistry()
	RegisterIntegrityRules(registry)

	tests := []struct {
		name         string
		content      string
		ext          string
		wantRuleID   string
		wantCategory string
		wantSeverity model.Severity
		wantRuleName string
	}{
		{
			name:         "SD-012 fields",
			content:      "postinstall() { echo done; }",
			ext:          ".sh",
			wantRuleID:   "SD-012",
			wantCategory: "Integrity",
			wantSeverity: model.SeverityMedium,
			wantRuleName: "Post-Install Hook",
		},
		{
			name:         "SD-013 fields",
			content:      "crontab -e",
			ext:          ".sh",
			wantRuleID:   "SD-013",
			wantCategory: "Integrity",
			wantSeverity: model.SeverityCritical,
			wantRuleName: "Persistence Mechanism",
		},
		{
			name:         "SD-014 fields",
			content:      "cp evil .git/hooks/pre-commit",
			ext:          ".sh",
			wantRuleID:   "SD-014",
			wantCategory: "Integrity",
			wantSeverity: model.SeverityHigh,
			wantRuleName: "Git Hook Modification",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := model.FileContext{Path: "test" + tt.ext, Ext: tt.ext, Content: []byte(tt.content)}
			rr := registry.RulesFor(tt.ext)
			var findings []model.Finding
			for _, rule := range rr {
				if rule.ID() == tt.wantRuleID {
					findings = append(findings, rule.Match(ctx.Content, ctx)...)
				}
			}
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			f := findings[0]
			if f.RuleID != tt.wantRuleID {
				t.Errorf("RuleID = %q, want %q", f.RuleID, tt.wantRuleID)
			}
			if f.Category != tt.wantCategory {
				t.Errorf("Category = %q, want %q", f.Category, tt.wantCategory)
			}
			if f.Severity != tt.wantSeverity {
				t.Errorf("Severity = %v, want %v", f.Severity, tt.wantSeverity)
			}
			if f.RuleName != tt.wantRuleName {
				t.Errorf("RuleName = %q, want %q", f.RuleName, tt.wantRuleName)
			}
			if f.FilePath != "test"+tt.ext {
				t.Errorf("FilePath = %q, want %q", f.FilePath, "test"+tt.ext)
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
		})
	}
}

func TestIntegrityFixture(t *testing.T) {
	registry := NewRegistry()
	RegisterIntegrityRules(registry)

	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "malicious", "persistence", ".claude", "scripts", "persist.sh"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	ctx := model.FileContext{Path: "persist.sh", Ext: ".sh", Content: content}
	rr := registry.RulesFor(".sh")
	var findings []model.Finding
	for _, rule := range rr {
		if rule.ID() == "SD-012" || rule.ID() == "SD-013" || rule.ID() == "SD-014" {
			findings = append(findings, rule.Match(ctx.Content, ctx)...)
		}
	}

	// Expected: SD-012 line 5 (postinstall), SD-012 line 6 (post-install in echo),
	// SD-013 line 10 (crontab), SD-013 line 13 (LaunchAgents),
	// SD-013 line 14 (launchctl), SD-013 line 17 (.bashrc),
	// SD-014 line 20 (.git/hooks/), SD-014 line 21 (git config core.hooksPath)
	if len(findings) < 8 {
		t.Fatalf("got %d findings, want at least 8; findings: %v", len(findings), findings)
	}

	// Verify we have findings from all three rules.
	ruleIDs := make(map[string]bool)
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
	}
	for _, id := range []string{"SD-012", "SD-013", "SD-014"} {
		if !ruleIDs[id] {
			t.Errorf("expected findings from %s", id)
		}
	}
}

func TestIntegrityCleanFile(t *testing.T) {
	registry := NewRegistry()
	RegisterIntegrityRules(registry)

	tests := []struct {
		name    string
		content string
		ext     string
	}{
		{
			name:    "clean shell script",
			content: "#!/bin/bash\necho hello\nmkdir -p ./data\necho done",
			ext:     ".sh",
		},
		{
			name:    "clean markdown",
			content: "# Title\n\nSome documentation about the project.",
			ext:     ".md",
		},
		{
			name:    "clean yaml",
			content: "name: my-skill\nversion: 1.0.0\ndescription: A simple skill",
			ext:     ".yaml",
		},
		{
			name:    "clean json",
			content: "{\"name\": \"my-skill\", \"version\": \"1.0.0\"}",
			ext:     ".json",
		},
		{
			name:    "clean txt prompt",
			content: "You are a helpful assistant.\nPlease help with code.",
			ext:     ".txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := model.FileContext{Path: "test" + tt.ext, Ext: tt.ext, Content: []byte(tt.content)}
			rr := registry.RulesFor(tt.ext)
			var findings []model.Finding
			for _, rule := range rr {
				if rule.ID() == "SD-012" || rule.ID() == "SD-013" || rule.ID() == "SD-014" {
					findings = append(findings, rule.Match(ctx.Content, ctx)...)
				}
			}
			if len(findings) != 0 {
				t.Errorf("expected 0 findings on clean content, got %d", len(findings))
				for _, f := range findings {
					t.Logf("  finding: %s line %d: %s", f.RuleID, f.Line, f.Description)
				}
			}
		})
	}
}
