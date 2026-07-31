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

type unsanctionedHookRule struct {
	baseRule
}

type hookEntry struct {
	Command string `json:"command"`
}

// nestedHookMatcher is one element of the real Claude Code hooks schema:
// {"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"..."}]}]}}
type nestedHookMatcher struct {
	Matcher string      `json:"matcher"`
	Hooks   []hookEntry `json:"hooks"`
}

// hookCommands extracts command strings from a hooks entry, accepting both
// the real nested shape and the flat shape ([{"command":"..."}]) used by
// this repo's older fixtures.
func hookCommands(raw json.RawMessage) []string {
	var cmds []string
	var nested []nestedHookMatcher
	if err := json.Unmarshal(raw, &nested); err == nil {
		for _, m := range nested {
			for _, h := range m.Hooks {
				if strings.TrimSpace(h.Command) != "" {
					cmds = append(cmds, h.Command)
				}
			}
		}
	}
	var flat []hookEntry
	if err := json.Unmarshal(raw, &flat); err == nil {
		for _, e := range flat {
			if strings.TrimSpace(e.Command) != "" {
				cmds = append(cmds, e.Command)
			}
		}
	}
	return cmds
}

func (r *unsanctionedHookRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsClaudeSettings(ctx.Path) {
		return nil
	}
	s, err := parseClaudeSettings(content)
	if err != nil {
		return nil
	}
	var findings []model.Finding
	for hookName, raw := range s.Hooks {
		for _, cmd := range hookCommands(raw) {
			cmd = strings.TrimSpace(cmd)
			if cmd == "" {
				continue
			}
			firstField := strings.Fields(cmd)
			if len(firstField) == 0 {
				continue
			}
			head := firstField[0]
			isInRepo := strings.HasPrefix(cmd, "./") || strings.HasPrefix(cmd, "../") ||
				(!strings.HasPrefix(head, "/") && !strings.Contains(head, "/"))
			// Even an in-repo-looking command fails if it pipes to a shell.
			if isInRepo && (strings.Contains(cmd, "| sh") || strings.Contains(cmd, "|sh") ||
				strings.Contains(cmd, "| bash") || strings.Contains(cmd, "|bash")) {
				isInRepo = false
			}
			if !isInRepo {
				findings = append(findings, r.newFinding(ctx, 1,
					"hook "+hookName+" runs unsanctioned command: "+cmd,
					"Restrict hook commands to in-repo scripts (./scripts/...) or maintain an explicit allowlist"))
			}
		}
	}
	return findings
}

// unrestrictedGrantRule flags a bare "*" in permissions.allow — a grant of
// every tool and command, the broadest possible permission. The Bash-wildcard
// rule (SD-017) only catches specific Bash(...) patterns, so "*" slipped through.
type unrestrictedGrantRule struct {
	baseRule
}

func (r *unrestrictedGrantRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsClaudeSettings(ctx.Path) {
		return nil
	}
	s, err := parseClaudeSettings(content)
	if err != nil {
		return nil
	}
	var findings []model.Finding
	for _, entry := range s.Permissions.Allow {
		if strings.TrimSpace(entry) == "*" {
			findings = append(findings, r.newFinding(ctx, 1,
				`unrestricted permission grant: allow contains "*" (every tool and command permitted)`,
				`Replace the "*" wildcard with an explicit allowlist of only the tools and subcommands the skill needs`))
		}
	}
	return findings
}

// RegisterSettingsJSONRules registers all .claude/settings.json-class rules.
func RegisterSettingsJSONRules(registry *RuleRegistry) {
	registry.Register(&unrestrictedGrantRule{
		baseRule: baseRule{
			id:       "SD-023",
			name:     "settings.json Unrestricted Permission Grant",
			severity: model.SeverityHigh,
			category: "SettingsJSON",
			types:    []string{".json"},
			axis:     axes.PermissionHygiene,
		},
	})
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
	registry.Register(&unsanctionedHookRule{
		baseRule: baseRule{
			id:       "SD-019",
			name:     "settings.json Unsanctioned Hook",
			severity: model.SeverityMedium,
			category: "SettingsJSON",
			types:    []string{".json"},
			axis:     axes.PermissionHygiene,
		},
	})
}
