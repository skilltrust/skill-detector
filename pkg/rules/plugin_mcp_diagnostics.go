package rules

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/model"
	"gopkg.in/yaml.v3"
)

var installedCommitSHA = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

// PluginMCPDiagnostics inventories only submitted declarations. A path is not
// evidence that a managed setting, installed plugin, or session is active.
func PluginMCPDiagnostics(content []byte, ctx model.FileContext) ([]string, error) {
	if !InScope(ctx) || filepath.Ext(ctx.Path) != ".json" {
		if !InScope(ctx) {
			return nil, nil
		}
		if isClaudeAgentDefinition(ctx.Path) {
			return append(teammateProvenance(ctx), omitClaudeMdDiagnostics(content, ctx)...), nil
		}
		if filepath.Base(ctx.Path) == "AGENTS.md" {
			return agentsFallbackDiagnostics(ctx), nil
		}
		return nil, nil
	}
	settings := IsClaudeSettings(ctx.Path)
	managedMCP := filepath.Base(ctx.Path) == "managed-mcp.json"
	mcp := IsMCPConfig(ctx.Path) || managedMCP
	inventory := filepath.Base(ctx.Path) == "installed_plugins.json" && strings.Contains(filepath.ToSlash(ctx.Path), ".claude/")
	tasks := filepath.Base(ctx.Path) == "scheduled_tasks.json" && strings.Contains(filepath.ToSlash(ctx.Path), ".claude/")
	if !settings && !mcp && !inventory && !tasks && !strings.HasSuffix(ctx.Path, "marketplace.json") {
		return nil, nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(content, &root); err != nil || root == nil {
		if managedMCP {
			return nil, fmt.Errorf("%s: supplied managed MCP policy is malformed; effective policy unknown", ctx.Path)
		}
		// Claude settings validation is owned by ClaudeConfigurationDiagnostics.
		if settings {
			return nil, nil
		}
		return []string{ctx.Path + ": submitted plugin/MCP configuration is malformed; no effective policy or inventory verdict is possible"}, nil
	}
	if !hasUnambiguousAnalyzedJSONMembers(content) {
		if managedMCP {
			return nil, fmt.Errorf("%s: supplied managed MCP policy has ambiguous JSON members; effective policy unknown", ctx.Path)
		}
		return []string{ctx.Path + ": ambiguous plugin/MCP JSON members; effective policy and inventory remain unknown"}, nil
	}
	if managedMCP {
		var servers map[string]json.RawMessage
		if json.Unmarshal(root["mcpServers"], &servers) != nil || servers == nil {
			return nil, fmt.Errorf("%s: supplied managed MCP policy has malformed or missing mcpServers; effective policy unknown", ctx.Path)
		}
		for _, raw := range servers {
			if _, valid := jsonObject(raw); !valid {
				return nil, fmt.Errorf("%s: supplied managed MCP policy has malformed server entries; effective policy unknown", ctx.Path)
			}
		}
	}
	var warnings []string
	if settings {
		warnings = append(warnings, marketplacePolicyDiagnostics(root, ctx)...)
		warnings = append(warnings, mcpPolicyDiagnostics(root, ctx)...)
		warnings = append(warnings, instructionSelectionDiagnostics(root, ctx)...)
		warnings = append(warnings, cloudSettingsDiagnostics(root, ctx)...)
		if raw, ok := root["enabledPlugins"]; ok {
			var plugins map[string]bool
			if json.Unmarshal(raw, &plugins) == nil && plugins != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %d enabledPlugins preference(s) declared; a plugin name or enabled flag does not prove installation, installed commit, activation or host inventory (unavailable unless supplied)", ctx.Path, len(plugins)))
			} else {
				warnings = append(warnings, ctx.Path+": enabledPlugins uses an unsupported shape; installation and activation unknown")
			}
		}
	}
	if mcp {
		if isClaudeSDKConfig(ctx.Path) {
			warnings = append(warnings, sdkMCPDiagnostics(root, ctx)...)
		}
		if managedMCP {
			warnings = append(warnings, ctx.Path+": submitted managed-mcp.json is an exclusive-control declaration only if its managed provenance and runtime loading are established; unreadable or malformed managed policy cannot establish an effective allow verdict")
		}
	}
	if inventory {
		warnings = append(warnings, installedPluginDiagnostics(root, ctx)...)
	}
	if tasks {
		warnings = append(warnings, ctx.Path+": supplied scheduled_tasks.json is a task-reference candidate; copied tasks at the Claude Code 2.1.273 anchor do not establish current-session binding or execution ("+anchorVersionDescription(ctx.Analysis.Version, "2.1.273")+")")
	}
	if strings.HasSuffix(ctx.Path, "marketplace.json") {
		warnings = append(warnings, pluginSourceDiagnostics(root, ctx)...)
	}
	return warnings, nil
}

func agentsFallbackDiagnostics(ctx model.FileContext) []string {
	claude := ctx.Analysis.Conditions["claude_instructions"]
	state := "no CLAUDE.md was supplied in the same directory, but parent and user instructions, configured selection, provider and session are unknown"
	if claude.State == model.ContextKnown && claude.Value == "present" {
		state = "a CLAUDE.md was also supplied, so default fallback does not select AGENTS.md alone; imports or an explicit both selection may still load it"
	}
	if claude.State == model.ContextKnown && claude.Value == "absent" {
		state = "no CLAUDE.md was supplied in the same directory; parent/user files and explicit selection remain unknown"
	}
	provider := "provider unknown"
	if ctx.Analysis.Provider.State == model.ContextKnown {
		switch ctx.Analysis.Provider.Value {
		case "bedrock", "vertex", "foundry":
			provider = "supplied provider excludes AGENTS.md support at the 2.1.277 anchor"
		default:
			provider = "supplied provider is not one of the documented exclusions; support outside the exact anchor must be checked"
		}
	}
	return []string{fmt.Sprintf("%s: AGENTS.md instruction candidate; %s; %s; %s. No simultaneous loading or session activation inferred. Untracked worktree and account-synced skills are unavailable unless supplied", ctx.Path, state, provider, anchorVersionDescription(ctx.Analysis.Version, "2.1.277"))}
}

func omitClaudeMdDiagnostics(content []byte, ctx model.FileContext) []string {
	lines := strings.SplitAfter(string(content), "\n")
	if len(lines) < 3 || strings.TrimRight(lines[0], "\r\n") != "---" {
		return nil
	}
	var frontmatter strings.Builder
	closed := false
	for _, line := range lines[1:] {
		if strings.TrimRight(line, "\r\n") == "---" {
			closed = true
			break
		}
		frontmatter.WriteString(line)
		if frontmatter.Len() > maxFrontmatterBytes {
			return nil
		}
	}
	if !closed {
		return nil
	}
	var metadata struct {
		OmitClaudeMd *bool `yaml:"omitClaudeMd"`
	}
	if yaml.Unmarshal([]byte(frontmatter.String()), &metadata) != nil || metadata.OmitClaudeMd == nil {
		return nil
	}
	if !*metadata.OmitClaudeMd {
		return nil
	}
	return []string{ctx.Path + ": omitClaudeMd=true agent declaration would omit user/project/local CLAUDE.md when this agent is selected; managed instructions still load if present. Agent selection, managed provenance and session activation unknown (Claude Code 2.1.271 anchor)"}
}

func marketplacePolicyDiagnostics(root map[string]json.RawMessage, ctx model.FileContext) []string {
	var warnings []string
	for _, key := range []string{"strictKnownMarketplaces", "blockedMarketplaces"} {
		raw, present := root[key]
		if !present {
			continue // absent in this source is not evidence that the managed policy is absent
		}
		var entries []json.RawMessage
		state := "populated (entry validity not established)"
		if json.Unmarshal(raw, &entries) != nil || entries == nil {
			state = "malformed"
		} else if len(entries) == 0 {
			state = "empty"
		} else {
			for _, entry := range entries {
				if !validMarketplaceSource(entry) {
					state = "entry validity unknown (malformed or unsupported shape)"
					break
				}
			}
		}
		meaning := "a managed denylist candidate; deny restrictions take precedence over allowed sources"
		if key == "strictKnownMarketplaces" {
			meaning = "a managed allowlist candidate; empty means lockdown if the policy is applicable, not unrestricted access"
		}
		warnings = append(warnings, fmt.Sprintf("%s: %s is %s (%s); source=%s. Claude Code 2.1.277 fixes a malformed entry disabling the entire policy; the earlier affected range is unknown. Validity and file placement do not prove runtime enforcement or non-enforcement (%s)", ctx.Path, key, state, meaning, originDescription(ctx.Analysis.DeclarationOrigin), anchorVersionDescription(ctx.Analysis.Version, "2.1.277")))
		for _, entry := range entries {
			var source struct {
				Source string `json:"source"`
			}
			if json.Unmarshal(entry, &source) == nil && source.Source == "npm" {
				warnings = append(warnings, ctx.Path+": npm marketplace policy source parses but matches no registered marketplace in current documentation; it does not grant or block an npm plugin source; effective policy remains unknown")
				break
			}
		}
	}
	return warnings
}

func validMarketplaceSource(raw json.RawMessage) bool {
	var entry map[string]json.RawMessage
	if json.Unmarshal(raw, &entry) != nil || entry == nil {
		return false
	}
	var source string
	if json.Unmarshal(entry["source"], &source) != nil {
		return false
	}
	fields := map[string]string{"github": "repo", "git": "url", "url": "url", "npm": "package", "file": "path", "directory": "path", "hostPattern": "hostPattern", "pathPattern": "pathPattern"}
	if source == "skills-dir" {
		return len(entry) == 1
	}
	required := fields[source]
	if required == "" {
		return false
	}
	for key, value := range entry {
		if key == "source" {
			continue
		}
		if key != required && key != "ref" && key != "path" && key != "version" {
			return false
		}
		var text string
		if json.Unmarshal(value, &text) != nil || text == "" {
			return false
		}
		if key == required && strings.HasSuffix(source, "Pattern") {
			if _, err := regexp.Compile(text); err != nil {
				return false
			}
		}
	}
	return len(entry[required]) > 0
}

func originDescription(origin model.ContextValue) string {
	if contextKnownIs(origin, "managed") {
		return "supplied managed"
	}
	return "unverified (managed provenance unavailable)"
}

func mcpPolicyDiagnostics(root map[string]json.RawMessage, ctx model.FileContext) []string {
	var warnings []string
	for _, key := range []string{"allowManagedMcpServersOnly", "allowedMcpServers", "deniedMcpServers"} {
		raw, present := root[key]
		if !present {
			continue
		}
		state := "populated"
		if key == "allowManagedMcpServersOnly" {
			if !validJSONBool(raw) {
				state = "malformed"
			} else if strings.TrimSpace(string(raw)) == "false" {
				state = "false"
			}
		} else {
			var entries []map[string]json.RawMessage
			if json.Unmarshal(raw, &entries) != nil || entries == nil {
				state = "malformed"
			} else if len(entries) == 0 {
				state = "empty"
			} else {
				for _, entry := range entries {
					if len(entry) != 1 {
						state = "malformed"
						break
					}
					for field, value := range entry {
						if field == "serverCommand" {
							if !validJSONStringArray(value) {
								state = "malformed"
							}
						} else if (field != "serverUrl" && field != "serverName") || !validJSONString(value) {
							state = "malformed"
						}
					}
				}
			}
		}
		warnings = append(warnings, fmt.Sprintf("%s: %s is %s; managed provenance=%s. Current documented MCP policy merges denylists from all sources (deny wins); only a verified managed allowManagedMcpServersOnly=true excludes lower-tier allowlists. An empty allowlist blocks user-added servers when applicable, while an empty denylist blocks none. Unreadable/malformed managed policy and unsupplied higher-priority sources leave effective policy unknown; no server activation is inferred", ctx.Path, key, state, originDescription(ctx.Analysis.DeclarationOrigin)))
	}
	return warnings
}

func sdkMCPDiagnostics(root map[string]json.RawMessage, ctx model.FileContext) []string {
	var servers map[string]json.RawMessage
	if json.Unmarshal(root["mcpServers"], &servers) != nil || servers == nil {
		return nil
	}
	var warnings []string
	for _, raw := range servers {
		var server struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &server) == nil && server.Type == "sdk" {
			warnings = append(warnings, fmt.Sprintf("%s: MCP server declares type=sdk; Claude Code 2.1.274 skips SDK entries in configuration (in-process SDK hosts may register them). Compatibility declaration only, not an executing server (%s)", ctx.Path, anchorVersionDescription(ctx.Analysis.Version, "2.1.274")))
		}
	}
	slices.Sort(warnings)
	return warnings
}

func installedPluginDiagnostics(root map[string]json.RawMessage, ctx model.FileContext) []string {
	var plugins map[string][]map[string]json.RawMessage
	if json.Unmarshal(root["plugins"], &plugins) != nil || plugins == nil {
		return []string{ctx.Path + ": installed_plugins.json uses an unsupported inventory shape; installed commits unknown"}
	}
	var warnings []string
	for name, installs := range plugins {
		for _, install := range installs {
			var commit string
			_ = json.Unmarshal(install["gitCommitSha"], &commit)
			status := "missing installed commit (unknown; version or plugin name is not a substitute)"
			if installedCommitSHA.MatchString(commit) {
				status = "evidenced installed commit " + commit
			} else if commit != "" {
				status = "unsupported installed commit format (value withheld)"
			}
			if expected := ctx.Analysis.Conditions["plugin_commit:"+name]; expected.State == model.ContextKnown && expected.Value != "" {
				if installedCommitSHA.MatchString(commit) && commit == expected.Value {
					status += "; supplied pin matches"
				} else if installedCommitSHA.MatchString(commit) && installedCommitSHA.MatchString(expected.Value) {
					status += "; differs from supplied pin (stale relative to that evidence, not proof of runtime update)"
				}
			}
			warnings = append(warnings, fmt.Sprintf("%s: installed plugin (identifier withheld): %s; submitted inventory is not host inventory or current-session activation (Claude Code 2.1.277 anchor)", ctx.Path, status))
		}
	}
	slices.Sort(warnings)
	return warnings
}

func pluginSourceDiagnostics(root map[string]json.RawMessage, ctx model.FileContext) []string {
	var plugins []map[string]json.RawMessage
	if json.Unmarshal(root["plugins"], &plugins) != nil {
		return nil
	}
	var warnings []string
	for _, plugin := range plugins {
		var source struct {
			Source string `json:"source"`
		}
		if json.Unmarshal(plugin["source"], &source) != nil {
			continue
		}
		switch source.Source {
		case "npm":
			warnings = append(warnings, ctx.Path+": npm plugin source declared; Claude Code 2.1.275 fetch uses npm pack --ignore-scripts and integrity checks, suppressing install scripts, not runtime plugin supply-chain risk; installed version and activation unknown")
		case "command":
			warnings = append(warnings, ctx.Path+": command plugin source declares an install/update and per-session command; approval, managed restrictions and execution unknown; command and arguments withheld from diagnostics")
		}
	}
	return warnings
}

func instructionSelectionDiagnostics(root map[string]json.RawMessage, ctx model.FileContext) []string {
	var plugins map[string]json.RawMessage
	if json.Unmarshal(root["pluginConfigs"], &plugins) != nil {
		return nil
	}
	var agent struct {
		Options struct {
			InstructionFiles string `json:"instructionFiles"`
		} `json:"options"`
	}
	if json.Unmarshal(plugins["agents-md@builtin"], &agent) != nil || agent.Options.InstructionFiles == "" {
		return nil
	}
	selection := agent.Options.InstructionFiles
	if !slices.Contains([]string{"claude-md-or-agents-md", "claude-md-and-agents-md", "claude-md", "managed-only"}, selection) {
		return []string{ctx.Path + ": unsupported instruction selection; effective instruction loading unknown"}
	}
	return []string{fmt.Sprintf("%s: instruction selection %s declared; documented scope is user or managed, so a project/local declaration alone cannot establish selection. Effective selection, provider and session loading are unknown. At the Claude Code 2.1.277 anchor AGENTS.md fallback requires no CLAUDE.md; Bedrock, Vertex and Foundry sessions exclude AGENTS.md support. Current documentation permits explicit both/CLAUDE-only/managed-only choices, without establishing their introduction version", ctx.Path, selection)}
}

func cloudSettingsDiagnostics(root map[string]json.RawMessage, ctx model.FileContext) []string {
	if _, hasPlugins := root["enabledPlugins"]; !hasPlugins {
		if _, hasMarketplaces := root["extraKnownMarketplaces"]; !hasMarketplaces {
			if _, hasPermissions := root["permissions"]; !hasPermissions {
				if _, hasHooks := root["hooks"]; !hasHooks {
					return nil
				}
			}
		}
	}
	topology := "unknown"
	if contextIs(ctx.Analysis.Conditions["cloud_repositories"], "multiple") || contextIs(ctx.Analysis.Conditions["cloud_repositories"], "single") {
		topology = ctx.Analysis.Conditions["cloud_repositories"].Value
	}
	return []string{ctx.Path + ": cloud repository topology is " + topology + "; per-repository plugins/marketplaces do not by themselves establish active permissions, hooks or env in multi-repository cloud sessions. Single-repository applicability, trust and effective source still require session evidence; the September 17 settings-doc edit does not establish an introduction version"}
}

func isClaudeAgentDefinition(path string) bool {
	clean := filepath.ToSlash(path)
	return strings.HasSuffix(clean, ".md") && (strings.HasPrefix(clean, ".claude/agents/") || strings.Contains(clean, "/.claude/agents/"))
}

func teammateProvenance(ctx model.FileContext) []string {
	if !contextKnownIs(ctx.Analysis.Session, "teammate-respawn") || !contextKnownIs(ctx.Analysis.Conditions["same_name_agent"], "true") {
		return nil
	}
	if contextKnownIs(ctx.Analysis.Trust, "trusted") {
		return nil
	}
	trust := "unknown"
	if contextKnownIs(ctx.Analysis.Trust, "untrusted") {
		trust = ctx.Analysis.Trust.Value
	}
	return []string{ctx.Path + ": teammate respawn with supplied same-name agent definition; source trust=" + trust + ". Claude Code 2.1.268 fixes loading same-name files from untrusted folders; no agent was executed and earlier range is unknown"}
}
