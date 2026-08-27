package rules

import (
	"bytes"
	"regexp"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// SD-005: World-writable file permission patterns.
var (
	reChmod777      = regexp.MustCompile(`chmod\s+[0-7]*[67][67][67]\b`)
	reChmodAllWrite = regexp.MustCompile(`chmod\s+[ao]?\+[rwx]*w`)
)

// SD-006: Hardcoded secret / API key patterns.
var (
	reAWSKey        = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reSKKey         = regexp.MustCompile(`sk-[a-zA-Z0-9-]{30,}`)
	reGitHubPAT     = regexp.MustCompile(`gh[pousr]_[a-zA-Z0-9]{36}`)
	reSlackToken    = regexp.MustCompile(`xox[bpsa]-[a-zA-Z0-9-]{10,}`)
	reGenericSecret = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*["']?[a-zA-Z0-9/+=]{16,}`)
)

type worldWritableRule struct {
	baseRule
}

func (r *worldWritableRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !InScope(ctx) {
		return nil
	}
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1
		if reChmod777.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"world-writable file permission detected",
				"Use restrictive permissions (e.g., chmod 700 or chmod 600) instead of world-writable modes"))
		} else if reChmodAllWrite.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"overly permissive chmod granting write to all/others",
				"Use restrictive permissions; avoid granting write access to all users"))
		}
	}
	return findings
}

type hardcodedSecretRule struct {
	baseRule
}

func (r *hardcodedSecretRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !InScope(ctx) {
		return nil
	}
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1

		// Check specific patterns first; most specific wins.
		if reAWSKey.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"hardcoded AWS access key detected",
				"Remove hardcoded AWS keys; use environment variables or a secrets manager"))
			continue
		}
		if reGitHubPAT.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"hardcoded GitHub personal access token detected",
				"Remove hardcoded GitHub tokens; use environment variables or a secrets manager"))
			continue
		}
		if reSlackToken.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"hardcoded Slack token detected",
				"Remove hardcoded Slack tokens; use environment variables or a secrets manager"))
			continue
		}
		if reSKKey.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"hardcoded API key detected (sk- prefix)",
				"Remove hardcoded API keys; use environment variables or a secrets manager"))
			continue
		}
		// Generic secret pattern — only if no specific pattern matched.
		if reGenericSecret.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"potential hardcoded secret or API key in variable assignment",
				"Remove hardcoded secrets; use environment variables or a secrets manager"))
		}
	}
	return findings
}

// RegisterMisconfigurationRules registers all security misconfiguration detection rules.
func RegisterMisconfigurationRules(registry *RuleRegistry) {
	registry.Register(&worldWritableRule{
		baseRule: baseRule{
			id:       "SD-005",
			name:     "World-Writable Permissions",
			severity: model.SeverityMedium,
			category: "Security Misconfiguration",
			types:    ContentScanTypes,
			axis:     axes.PermissionHygiene,
		},
	})
	registry.Register(&hardcodedSecretRule{
		baseRule: baseRule{
			id:       "SD-006",
			name:     "Hardcoded Secret",
			severity: model.SeverityCritical,
			category: "Security Misconfiguration",
			types:    ContentScanTypes,
			axis:     axes.PermissionHygiene,
		},
	})
}
