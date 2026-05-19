package rules

import (
	"encoding/json"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// claudeSettings is a minimal decoder for the .claude/settings.json schema.
// Only fields used by SP-1 rules are populated.
type claudeSettings struct {
	Permissions struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	} `json:"permissions"`
	Hooks      map[string]json.RawMessage `json:"hooks"`
	MCPServers map[string]struct {
		URL     string            `json:"url"`
		Command string            `json:"command"`
		Env     map[string]string `json:"env"`
	} `json:"mcpServers"`
}

func parseClaudeSettings(content []byte) (claudeSettings, error) {
	var s claudeSettings
	err := json.Unmarshal(content, &s)
	return s, err
}

// broadShellPatterns are wildcard or whole-shell permission grants flagged
// as broad-permission risks.
var broadShellPatterns = []string{
	"Bash(curl *)",
	"Bash(wget *)",
	"Bash(*)",
	"Bash(sh *)",
	"Bash(bash *)",
	"Bash(eval *)",
}

type bashCurlWildcardRule struct {
	baseRule
}

func (r *bashCurlWildcardRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsClaudeSettings(ctx.Path) {
		return nil
	}
	s, err := parseClaudeSettings(content)
	if err != nil {
		return nil
	}
	var findings []model.Finding
	for _, entry := range s.Permissions.Allow {
		for _, pat := range broadShellPatterns {
			if strings.EqualFold(strings.TrimSpace(entry), pat) {
				findings = append(findings, r.newFinding(ctx, 1,
					"broad shell permission granted: "+entry,
					"Replace with specific subcommand patterns; never grant Bash(curl *), Bash(wget *), or Bash(*)"))
			}
		}
	}
	return findings
}

type subcommandLimitBypassRule struct {
	baseRule
}

func (r *subcommandLimitBypassRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsClaudeSettings(ctx.Path) {
		return nil
	}
	s, err := parseClaudeSettings(content)
	if err != nil {
		return nil
	}
	var findings []model.Finding

	// Pattern: a deny entry for a specific Bash subcommand is undermined by
	// an allow entry that is broader.
	for _, deny := range s.Permissions.Deny {
		denyCmd := bashCommand(deny)
		if denyCmd == "" {
			continue
		}
		for _, allow := range s.Permissions.Allow {
			allowCmd := bashCommand(allow)
			if allowCmd == "" {
				continue
			}
			// If allow is broader than deny (allow = "rm *" but deny = "rm -rf *",
			// or allow = "*" with any specific deny).
			if (allowCmd == "*" || strings.HasSuffix(allowCmd, " *")) &&
				strings.HasPrefix(strings.TrimSuffix(denyCmd, " *"), strings.TrimSuffix(allowCmd, " *")) {
				findings = append(findings, r.newFinding(ctx, 1,
					"deny "+deny+" is bypassed by broader allow "+allow,
					"Tighten the allow entry so it does not subsume the denied subcommand"))
			}
		}
	}
	return findings
}

// bashCommand extracts the inner string of a Bash(...) permission entry.
// Returns empty string if entry is not a Bash(...) grant.
func bashCommand(entry string) string {
	const prefix = "Bash("
	if !strings.HasPrefix(entry, prefix) || !strings.HasSuffix(entry, ")") {
		return ""
	}
	return entry[len(prefix) : len(entry)-1]
}

// RegisterSettingsJSONRules registers all .claude/settings.json-class rules.
func RegisterSettingsJSONRules(registry *RuleRegistry) {
	registry.Register(&bashCurlWildcardRule{
		baseRule: baseRule{
			id:       "SD-017",
			name:     "settings.json Bash Wildcard Grant",
			severity: model.SeverityHigh,
			category: "SettingsJSON",
			types:    []string{".json"},
			axis:     axes.PermissionHygiene,
		},
	})
	registry.Register(&subcommandLimitBypassRule{
		baseRule: baseRule{
			id:       "SD-018",
			name:     "settings.json Subcommand Limit Bypass",
			severity: model.SeverityHigh,
			category: "SettingsJSON",
			types:    []string{".json"},
			axis:     axes.PermissionHygiene,
		},
	})
}
