package rules

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// claudeSettings is a minimal decoder for the .claude/settings.json schema.
// Only fields used by the rules here are populated.
type claudeSettings struct {
	Permissions struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	} `json:"permissions"`
	Hooks map[string]json.RawMessage `json:"hooks"`
	// MCPServers is NOT part of the real settings.json schema — MCP server
	// definitions live in .mcp.json and ~/.claude.json only. This field is
	// kept solely so the settings.json and .mcp.json decode paths stay
	// symmetrical for mcpExternalDomainRule's fallback path.
	MCPServers map[string]struct {
		URL     string            `json:"url"`
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env"`
	} `json:"mcpServers"`
}

func parseClaudeSettings(content []byte) (claudeSettings, error) {
	var s claudeSettings
	err := json.Unmarshal(content, &s)
	return s, err
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
		if isBroadShellGrant(entry) {
			findings = append(findings, r.newFinding(ctx, 1,
				"broad shell permission granted: "+entry,
				"Replace with specific subcommand patterns; never grant Bash, Bash(*), or Bash(curl:*)"))
		}
	}
	return findings
}

type redundantDenyRule struct {
	baseRule
}

func (r *redundantDenyRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsClaudeSettings(ctx.Path) {
		return nil
	}
	s, err := parseClaudeSettings(content)
	if err != nil {
		return nil
	}
	var findings []model.Finding

	// Pattern: a broad Bash/PowerShell allow overlaps a narrower deny. Deny
	// precedence keeps the restriction effective; the finding is about the
	// risky breadth that remains outside the denied subset.
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
			if allowSubsumes(allowCmd, denyCmd) {
				findings = append(findings, r.newFinding(ctx, 1,
					"broad allow "+allow+" overlaps protective deny "+deny+"; when both rules apply, deny precedence protects the denied subset",
					"Keep the protective deny. Narrow or remove the broad allow if its remaining command range is unnecessary; do not remove the deny merely because the allow overlaps it"))
			}
		}
	}
	return findings
}

// shellTools are permission-rule tool names that gate shell execution.
// PowerShell rules share the Bash shape (G3); PowerShell command matching is
// case-insensitive with alias canonicalization on the Claude Code side, but
// the tool name itself is case-sensitive in the rule.
var shellTools = []string{"Bash", "PowerShell"}

// bashCommand extracts the inner pattern of a Bash or PowerShell permission
// entry and normalizes Claude Code's prefix-wildcard syntax ("curl:*") to the
// space form ("curl *"). A bare tool entry (no parens) grants every shell
// command and normalizes to "*". Returns "" for non-shell entries.
// NOTE: case-sensitive prefix match — replacing the old strings.EqualFold,
// which fired on invalid entries like bash(curl *).
func bashCommand(entry string) string {
	entry = strings.TrimSpace(entry)
	for _, tool := range shellTools {
		if entry == tool {
			return "*"
		}
		prefix := tool + "("
		if strings.HasPrefix(entry, prefix) && strings.HasSuffix(entry, ")") {
			inner := entry[len(prefix) : len(entry)-1]
			if strings.HasSuffix(inner, ":*") {
				inner = strings.TrimSuffix(inner, ":*") + " *"
			}
			return inner
		}
	}
	return ""
}

// broadShellHeads are commands whose wildcard grant hands the agent an
// unrestricted download-and-execute or full-shell primitive.
var broadShellHeads = map[string]bool{
	"curl": true, "wget": true, "sh": true, "bash": true, "zsh": true, "eval": true,
}

// isBroadShellGrant reports whether a permission entry is a broad shell
// grant: Bash/PowerShell, Bash(*), or Bash(<risky-head> *) in any wildcard
// syntax, including the no-space form Bash(curl*) which is strictly broader
// than Bash(curl *) — it also matches e.g. curlx (G4).
func isBroadShellGrant(entry string) bool {
	cmd := bashCommand(entry)
	if cmd == "" {
		return false
	}
	if cmd == "*" {
		return true
	}
	head, rest, found := strings.Cut(cmd, " ")
	if found && rest == "*" && broadShellHeads[head] {
		return true
	}
	// "curl*" (no space) is broader than "curl *": it also matches "curlx".
	for h := range broadShellHeads {
		if cmd == h+"*" {
			return true
		}
	}
	return false
}

// allowSubsumes reports whether a wildcard allow pattern covers the denied
// pattern, respecting token boundaries ("r *" does not subsume "rm -rf *").
func allowSubsumes(allow, deny string) bool {
	if allow == deny {
		return false
	}
	if allow == "*" {
		return true
	}
	if !strings.HasSuffix(allow, " *") {
		return false
	}
	allowPrefix := strings.TrimSuffix(allow, " *")
	denyTrim := strings.TrimSuffix(deny, " *")
	return denyTrim == allowPrefix || strings.HasPrefix(denyTrim, allowPrefix+" ")
}

type unsanctionedHookRule struct {
	baseRule
}

type hookEntry struct {
	Type           string            `json:"type"`
	Command        string            `json:"command"`
	URL            string            `json:"url"`
	Headers        map[string]string `json:"headers"`
	AllowedEnvVars []string          `json:"allowedEnvVars"`
	If             string            `json:"if"`
}

// nestedHookMatcher is one element of the real Claude Code hooks schema:
// {"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"..."}]}]}}
type nestedHookMatcher struct {
	Matcher *string     `json:"matcher"`
	Hooks   []hookEntry `json:"hooks"`
}

type hookDeclaration struct {
	Event       string
	Matcher     string
	MatcherSet  bool
	Handler     hookEntry
	Documented  bool
	Unsupported string
}

// hookDeclarations preserves event, matcher and handler type. Legacy flat
// entries remain available to SD-019/020, but diagnostics never certify them
// as active hooks.
func hookDeclarations(event string, raw json.RawMessage) []hookDeclaration {
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return []hookDeclaration{{Event: event, Unsupported: "event value is not an array"}}
	}
	var declarations []hookDeclaration
	for _, entry := range entries {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(entry, &object); err != nil || object == nil {
			declarations = append(declarations, hookDeclaration{Event: event, Unsupported: "event entry is not an object"})
			continue
		}
		if _, nested := object["hooks"]; !nested {
			var legacy hookEntry
			if err := json.Unmarshal(entry, &legacy); err == nil && strings.TrimSpace(legacy.Command) != "" {
				declarations = append(declarations, hookDeclaration{Event: event, Handler: legacy, Unsupported: "legacy flat hook shape"})
			} else {
				declarations = append(declarations, hookDeclaration{Event: event, Unsupported: "matcher group has no hooks array"})
			}
			continue
		}
		var group nestedHookMatcher
		if err := json.Unmarshal(entry, &group); err != nil || group.Hooks == nil {
			unsupported := hookDeclaration{Event: event, Unsupported: "matcher group fields use unsupported types"}
			var rawHandlers []json.RawMessage
			if raw, ok := object["hooks"]; ok && json.Unmarshal(raw, &rawHandlers) == nil {
				for _, rawHandler := range rawHandlers {
					var handler hookEntry
					if json.Unmarshal(rawHandler, &handler) == nil && strings.TrimSpace(handler.Command) != "" {
						unsupported.Handler = handler
						break
					}
				}
			}
			declarations = append(declarations, unsupported)
			continue
		}
		for _, handler := range group.Hooks {
			declaration := hookDeclaration{Event: event, Handler: handler, Documented: true}
			if group.Matcher != nil {
				declaration.Matcher = *group.Matcher
				declaration.MatcherSet = true
			}
			switch handler.Type {
			case "command":
				if strings.TrimSpace(handler.Command) == "" {
					declaration.Unsupported = "command handler has no command"
				}
			case "http":
				if strings.TrimSpace(handler.URL) == "" {
					declaration.Unsupported = "HTTP handler has no URL"
				}
			default:
				declaration.Unsupported = "handler type is not command or HTTP"
			}
			declarations = append(declarations, declaration)
		}
	}
	return declarations
}

func allHookDeclarations(hooks map[string]json.RawMessage) []hookDeclaration {
	events := make([]string, 0, len(hooks))
	for event := range hooks {
		events = append(events, event)
	}
	slices.Sort(events)
	var declarations []hookDeclaration
	for _, event := range events {
		declarations = append(declarations, hookDeclarations(event, hooks[event])...)
	}
	return declarations
}

func hookCommands(hooks map[string]json.RawMessage) []hookDeclaration {
	var commands []hookDeclaration
	for _, declaration := range allHookDeclarations(hooks) {
		if strings.TrimSpace(declaration.Handler.Command) != "" {
			commands = append(commands, declaration)
		}
	}
	return commands
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
	for _, hook := range hookCommands(s.Hooks) {
		cmd := strings.TrimSpace(hook.Handler.Command)
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
				"hook "+hook.Event+" runs unsanctioned command: "+sanitizeURLsForDisplay(cmd),
				"Restrict hook commands to in-repo scripts (./scripts/...) or maintain an explicit allowlist"))
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
				`overbroad permission grant: allow contains "*"`,
				`Current Claude Code skips an unanchored "*" allow glob with a warning, so this grants nothing — but it signals intent to disable the allowlist and may be honored by other harnesses or older versions. Replace it with an explicit list of the tools and subcommands the skill needs`))
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
			severity: model.SeverityMedium,
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
	registry.Register(&redundantDenyRule{
		baseRule: baseRule{
			id:       "SD-018",
			name:     "settings.json Broad Allow with Protective Deny",
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
