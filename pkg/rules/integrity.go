package rules

import (
	"bytes"
	"regexp"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// SD-012: Post-install scripts / lifecycle hooks.
var (
	rePostInstall  = regexp.MustCompile(`(?i)\b(post[_-]?install|pre[_-]?install|after[_-]?install|before[_-]?install|on[_-]?install)\b`)
	reNpmLifecycle = regexp.MustCompile(`(?i)"(postinstall|preinstall|prepare|prepublish)"\s*:`)
)

// SD-013: Persistence mechanisms.
var (
	reCrontab      = regexp.MustCompile(`\bcrontab\b`)
	reCronDir      = regexp.MustCompile(`/etc/cron\.(d|daily|hourly|weekly|monthly)/|/var/spool/cron/`)
	reLaunchAgent  = regexp.MustCompile(`(?i)(LaunchAgent|LaunchDaemon|launchctl)`)
	reLaunchPath   = regexp.MustCompile(`(~/Library/LaunchAgents/|/Library/LaunchDaemons/|/Library/LaunchAgents/)`)
	reSystemd      = regexp.MustCompile(`\bsystemctl\s+(enable|start)\b|/etc/systemd/`)
	reShellProfile = regexp.MustCompile(`(\.bashrc|\.bash_profile|\.zshrc|\.profile|\.zprofile)\b`)
	reWinScheduler = regexp.MustCompile(`(?i)\b(schtasks|Register-ScheduledTask)\b`)
)

// SD-014: Git hook modifications.
var (
	reGitHooksPath  = regexp.MustCompile(`\.git/hooks/`)
	reGitHookConfig = regexp.MustCompile(`(?i)(git\s+config\s+.*core\.hooksPath|core\.hooksPath\s*=)`)
)

type postInstallRule struct {
	baseRule
}

func (r *postInstallRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsAgentFile(ctx.Path) && !isInAgentConfigDir(ctx.Path) {
		return nil
	}
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1
		if rePostInstall.Match(line) || reNpmLifecycle.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"post-install or lifecycle hook detected",
				"Review and remove post-install hooks; use explicit setup steps instead"))
		}
	}
	return findings
}

type persistenceRule struct {
	baseRule
}

func (r *persistenceRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsAgentFile(ctx.Path) && !isInAgentConfigDir(ctx.Path) {
		return nil
	}
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1
		switch {
		case reCrontab.Match(line):
			findings = append(findings, r.newFinding(ctx, lineNum,
				"crontab manipulation detected — persistence mechanism",
				"Remove crontab commands; skills should not schedule recurring tasks"))
		case reCronDir.Match(line):
			findings = append(findings, r.newFinding(ctx, lineNum,
				"cron directory reference detected — persistence mechanism",
				"Remove cron directory references; skills should not install cron jobs"))
		case reLaunchAgent.Match(line):
			findings = append(findings, r.newFinding(ctx, lineNum,
				"macOS launch agent/daemon detected — persistence mechanism",
				"Remove launch agent/daemon references; skills should not install persistent services"))
		case reLaunchPath.Match(line):
			findings = append(findings, r.newFinding(ctx, lineNum,
				"macOS LaunchAgents path detected — persistence mechanism",
				"Remove LaunchAgents path references; skills should not install persistent services"))
		case reSystemd.Match(line):
			findings = append(findings, r.newFinding(ctx, lineNum,
				"systemd service manipulation detected — persistence mechanism",
				"Remove systemd references; skills should not install system services"))
		case reShellProfile.Match(line):
			findings = append(findings, r.newFinding(ctx, lineNum,
				"shell profile modification detected — persistence mechanism",
				"Remove shell profile modifications; skills should not alter user shell configuration"))
		case reWinScheduler.Match(line):
			findings = append(findings, r.newFinding(ctx, lineNum,
				"Windows task scheduler detected — persistence mechanism",
				"Remove scheduled task commands; skills should not schedule recurring tasks"))
		}
	}
	return findings
}

type gitHookRule struct {
	baseRule
}

func (r *gitHookRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsAgentFile(ctx.Path) && !isInAgentConfigDir(ctx.Path) {
		return nil
	}
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1
		if reGitHooksPath.Match(line) || reGitHookConfig.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"git hook modification detected — integrity violation",
				"Remove git hook modifications; skills should not alter repository hooks"))
		}
	}
	return findings
}

// RegisterIntegrityRules registers all integrity detection rules.
func RegisterIntegrityRules(registry *RuleRegistry) {
	registry.Register(&postInstallRule{
		baseRule: baseRule{
			id:       "SD-012",
			name:     "Post-Install Hook",
			severity: model.SeverityMedium,
			category: "Integrity",
			types:    ContentScanTypes,
			axis:     axes.Security,
		},
	})
	registry.Register(&persistenceRule{
		baseRule: baseRule{
			id:       "SD-013",
			name:     "Persistence Mechanism",
			severity: model.SeverityCritical,
			category: "Integrity",
			types:    ContentScanTypes,
			axis:     axes.Security,
		},
	})
	registry.Register(&gitHookRule{
		baseRule: baseRule{
			id:       "SD-014",
			name:     "Git Hook Modification",
			severity: model.SeverityHigh,
			category: "Integrity",
			types:    ContentScanTypes,
			axis:     axes.Security,
		},
	})
}
