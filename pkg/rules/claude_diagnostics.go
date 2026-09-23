package rules

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/model"
)

const (
	claudePermissionAnchor = "2.1.268"
	claudeAutoModeAnchor   = "2.1.271"
	claudeSandboxAnchor    = "2.1.277"
)

type claudeDiagnosticSettings struct {
	AllowManagedPermissionRulesOnly bool `json:"allowManagedPermissionRulesOnly"`
	Permissions                     struct {
		Allow       []string `json:"allow"`
		Ask         []string `json:"ask"`
		Deny        []string `json:"deny"`
		DefaultMode string   `json:"defaultMode"`
	} `json:"permissions"`
	Sandbox struct {
		ExcludedCommands []string `json:"excludedCommands"`
	} `json:"sandbox"`
}

// ClaudeConfigurationDiagnostics inventories declarations whose runtime effect
// depends on Claude Code version, source, trust, mode, or sandbox activation.
// It never reads host settings or executes declared commands.
func ClaudeConfigurationDiagnostics(content []byte, ctx model.FileContext) ([]string, error) {
	var warnings []string
	if IsClaudeSettings(ctx.Path) {
		var settings claudeDiagnosticSettings
		if err := json.Unmarshal(content, &settings); err != nil {
			return nil, fmt.Errorf("malformed Claude settings JSON or unsupported analyzed field type; configuration was not assessed")
		}
		warnings = append(warnings, claudePermissionDiagnostics(settings, ctx)...)
	}
	if isClaudeSkillOrCommand(ctx.Path) {
		if count := inlineShellDeclarationCount(string(content)); count > 0 {
			version := anchorVersionDescription(ctx.Analysis.Version, claudeAutoModeAnchor)
			warnings = append(warnings, fmt.Sprintf("%s: %d executable inline shell declaration(s) use !`command` or a ```! block; %s. At the 2.1.271 anchor, auto-mode skill/command injections use default-mode permissions and an undecided command falls back to a reviewed tool call. This is parsed as a declaration only; execution, approval and session activation were not tested.", ctx.Path, count, version))
		}
	}
	warnings = append(warnings, allowedDomainDiagnostics(content, ctx)...)
	return warnings, nil
}

func claudePermissionDiagnostics(settings claudeDiagnosticSettings, ctx model.FileContext) []string {
	var warnings []string
	origin := ctx.Analysis.DeclarationOrigin
	version := ctx.Analysis.Version
	prefix := ctx.Path + ": "
	versionCompared, comparableStableVersion := compareStableVersion(version, 2, 1, 257)

	if settings.Permissions.DefaultMode == "bypassPermissions" {
		switch {
		case (contextIs(origin, "project") || contextIs(origin, "project-local")) && comparableStableVersion && versionCompared >= 0:
			warnings = append(warnings, prefix+"declares permissions.defaultMode=bypassPermissions, but Claude Code "+version.Value+" does not activate auto or bypassPermissions from project/local settings; this is not an effective bypass declaration for the supplied context. Session flags and higher-precedence sources remain unavailable.")
		case (contextIs(origin, "project") || contextIs(origin, "project-local")) && comparableStableVersion:
			warnings = append(warnings, prefix+"declares permissions.defaultMode=bypassPermissions from project/local settings. At the supplied pre-2.1.257 version this source could select the mode only when its activation conditions, including workspace trust, were met; session overrides remain unavailable.")
		case contextIs(origin, "project") || contextIs(origin, "project-local"):
			warnings = append(warnings, prefix+"declares permissions.defaultMode=bypassPermissions from a project/local candidate source. It took effect from these sources before Claude Code 2.1.257 and does not in current versions; the effective version, trust and session override are unknown, so activation is unresolved.")
		default:
			warnings = append(warnings, prefix+"declares permissions.defaultMode=bypassPermissions. The supplied source is not established as an active user/managed source, and session overrides are unavailable, so this is a declaration rather than proof that prompts are bypassed.")
		}
	}
	if len(settings.Permissions.Allow) > 0 && (contextIs(origin, "project") || contextIs(origin, "project-local")) {
		warnings = append(warnings, fmt.Sprintf("%s%d project/local permission allow rule(s) are candidate grants, not proof of effective access: project allow rules require the applicable workspace-trust conditions, and managed or other-source deny/ask rules still take precedence.", prefix, len(settings.Permissions.Allow)))
	}
	if settings.AllowManagedPermissionRulesOnly {
		if origin.State == model.ContextKnown && origin.Value == "managed" {
			warnings = append(warnings, prefix+"managed allowManagedPermissionRulesOnly=true declares that user, project, local, --settings and --allowedTools permission rules are ignored; command-line/session deny and ask rules can still tighten policy. Runtime managed-policy activation remains a supplied-context condition, not a repository inference.")
		} else {
			warnings = append(warnings, prefix+"allowManagedPermissionRulesOnly=true appears outside established managed provenance. Only a managed source can activate this lock, so the file does not prove lower-tier permission rules are ignored.")
		}
	}

	allRules := append(append(append([]string{}, settings.Permissions.Allow...), settings.Permissions.Ask...), settings.Permissions.Deny...)
	var pathRules, writePathRules, shellDenies, negations int
	for _, entry := range allRules {
		tool, spec, scoped := permissionRuleParts(entry)
		if !scoped {
			continue
		}
		switch tool {
		case "Read", "Edit", "Write":
			pathRules++
			if tool == "Write" {
				writePathRules++
			}
			if strings.HasPrefix(spec, "!") {
				negations++
			}
		}
	}
	for _, entry := range settings.Permissions.Deny {
		tool, _, scoped := permissionRuleParts(entry)
		if scoped && (tool == "Bash" || tool == "PowerShell") {
			shellDenies++
		}
	}
	if pathRules > 0 {
		anchor := anchorVersionDescription(version, claudePermissionAnchor)
		warnings = append(warnings, fmt.Sprintf("%sdeclares %d Read/Edit/Write path rule(s); %s. At the 2.1.268 anchor, deny/ask checks cover both symlink spellings and resolved paths. Current documentation says allow requires both spellings and the target to match, while deny applies when either matches; Read deny protects Edit from 2.1.208 and Write from 2.1.228, and path-scoped Write rules are not consulted. Built-in file tools and recognized shell file operands are covered, not every subprocess; sandbox filesystem policy is required for OS-level enforcement.", prefix, pathRules, anchor))
	}
	if writePathRules > 0 {
		warnings = append(warnings, fmt.Sprintf("%s%d path-scoped Write rule(s) are declarations with no path-matching effect in current Claude Code; use Edit(path) for writes or Read(path) to deny reads plus edits/writes. Bare Write still applies tool-wide. Historical behavior before the documented 2.1.210 warning is unknown.", prefix, writePathRules))
	}
	if negations > 0 {
		warnings = append(warnings, fmt.Sprintf("%s%d negated path rule(s) are present. Current documentation says they can carve out only earlier relative rules in the same settings source; they cannot remove a deny from managed or any other source, and cannot reopen an anchored or whole-directory deny. Historical applicability is unresolved.", prefix, negations))
	}
	if shellDenies > 0 {
		warnings = append(warnings, fmt.Sprintf("%s%d scoped Bash/PowerShell deny rule(s) are present. Current documentation says that, when their source is applicable, deny takes precedence over every allow and permission mode; these rules match analyzed command text, not equivalent executable paths or arbitrary subprocesses. Claude Code 2.1.268 briefly denied some unanalyzable lines; 2.1.273 reverted those lines to prompting, so other versions must not be treated as either anchor without evidence.", prefix, shellDenies))
	}
	if len(settings.Sandbox.ExcludedCommands) > 0 {
		kind := "narrow"
		for _, pattern := range settings.Sandbox.ExcludedCommands {
			if broadExcludedCommand(pattern) {
				kind = "broad or wildcard"
				break
			}
		}
		versionContext := anchorVersionDescription(version, claudeSandboxAnchor)
		warnings = append(warnings, fmt.Sprintf("%ssandbox.excludedCommands contains %d %s exclusion(s); %s. At the 2.1.277 anchor every component of a supported compound command must match before the whole call runs outside the sandbox; complex shell forms remain sandboxed. Exclusions still use regular permissions and are convenience declarations, not proof of runtime sandbox enforcement.", prefix, len(settings.Sandbox.ExcludedCommands), kind, versionContext))
	}
	return warnings
}

func permissionRuleParts(entry string) (tool, spec string, scoped bool) {
	entry = strings.TrimSpace(entry)
	i := strings.IndexByte(entry, '(')
	if i <= 0 || !strings.HasSuffix(entry, ")") {
		return entry, "", false
	}
	return entry[:i], entry[i+1 : len(entry)-1], true
}

func isClaudeSkillOrCommand(path string) bool {
	clean := filepath.ToSlash(path)
	return filepath.Base(clean) == "SKILL.md" ||
		(strings.HasSuffix(clean, ".md") && hasDirComponent(clean, ".claude/commands/"))
}

func inlineShellDeclarationCount(content string) int {
	count := 0
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```!") {
			count++
			continue
		}
		for i := 0; i+2 < len(line); i++ {
			if line[i] != '!' || line[i+1] != '`' || (i > 0 && line[i-1] != ' ' && line[i-1] != '\t') {
				continue
			}
			if strings.ContainsRune(line[i+2:], '`') {
				count++
			}
		}
	}
	return count
}

func broadExcludedCommand(pattern string) bool {
	pattern = strings.TrimSpace(strings.TrimSuffix(pattern, ":*"))
	return pattern == "*" || strings.HasPrefix(pattern, "*") || strings.HasPrefix(pattern, "bash ") ||
		strings.HasPrefix(pattern, "sh ") || strings.HasPrefix(pattern, "powershell ")
}

// excludedCommandCovers models only the documented simple compound boundary:
// every component must match at least one exclusion. Complex shell syntax is
// deliberately unresolved rather than treated as a complete shell grammar.
func excludedCommandCovers(patterns []string, command string) (covered, supported bool) {
	parts, supported := simpleCommandParts(command)
	if !supported || len(parts) == 0 {
		return false, supported
	}
	for _, part := range parts {
		matched := false
		for _, pattern := range patterns {
			if commandPatternMatches(pattern, part) {
				matched = true
				break
			}
		}
		if !matched {
			return false, true
		}
	}
	return true, true
}

func simpleCommandParts(command string) ([]string, bool) {
	if strings.ContainsAny(command, "'\"`(){}$\\") {
		return nil, false
	}
	re := regexp.MustCompile(`\s*(?:&&|\|\||\|&|[;|&\n])\s*`)
	parts := re.Split(strings.TrimSpace(command), -1)
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
		if parts[i] == "" {
			return nil, false
		}
	}
	return parts, true
}

func commandPatternMatches(pattern, command string) bool {
	pattern = strings.TrimSpace(pattern)
	if strings.HasSuffix(pattern, ":*") {
		pattern = strings.TrimSuffix(pattern, ":*") + " *"
	}
	var b strings.Builder
	for _, r := range pattern {
		if r == '*' {
			b.WriteString(".*")
		} else {
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return regexp.MustCompile("^"+b.String()+"$").MatchString(command) ||
		(strings.HasSuffix(pattern, " *") && command == strings.TrimSuffix(pattern, " *"))
}

func allowedDomainDiagnostics(content []byte, ctx model.FileContext) []string {
	if !InScope(ctx) || filepath.Ext(ctx.Path) != ".json" {
		return nil
	}
	var value any
	if json.Unmarshal(content, &value) != nil {
		return nil
	}
	var diagnostics []string
	walkAllowedDomains(value, "", func(tool, command string, domains []string) {
		class := classifyDomainDeclaration(command, domains)
		context := anchorVersionDescription(ctx.Analysis.Version, claudeAutoModeAnchor) + "; auto mode, sandbox activation and session review remain unknown"
		diagnostics = append(diagnostics, fmt.Sprintf("%s: %s allowed_domains declaration %s; %s. Per-command domains are reviewed and opened for that command alone at the 2.1.271 anchor. This inventories a declaration and does not prove network confinement.", ctx.Path, tool, class, context))
	})
	return diagnostics
}

func walkAllowedDomains(value any, inheritedTool string, emit func(string, string, []string)) {
	switch value := value.(type) {
	case []any:
		for _, child := range value {
			walkAllowedDomains(child, inheritedTool, emit)
		}
	case map[string]any:
		tool := inheritedTool
		for _, key := range []string{"tool", "name", "type"} {
			if candidate, ok := value[key].(string); ok && isDomainTool(candidate) {
				tool = candidate
			}
		}
		if raw, ok := value["allowed_domains"].([]any); ok && isDomainTool(tool) {
			var domains []string
			valid := true
			for _, item := range raw {
				domain, ok := item.(string)
				if !ok {
					valid = false
					break
				}
				domains = append(domains, domain)
			}
			if valid {
				command, _ := value["command"].(string)
				emit(tool, command, domains)
			}
		}
		for _, child := range value {
			walkAllowedDomains(child, tool, emit)
		}
	}
}

func isDomainTool(tool string) bool {
	return tool == "Bash" || tool == "PowerShell" || tool == "Monitor"
}

var commandURL = regexp.MustCompile(`https?://[^\s"'<>]+`)

func classifyDomainDeclaration(command string, domains []string) string {
	hosts := make(map[string]bool)
	for _, raw := range commandURL.FindAllString(command, -1) {
		if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
			hosts[strings.ToLower(parsed.Hostname())] = true
		}
	}
	if len(hosts) == 0 {
		return "has no literal command destination available for comparison"
	}
	broad := false
	for host := range hosts {
		matched := false
		for _, domain := range domains {
			domain = strings.ToLower(strings.TrimSpace(strings.Split(domain, ":")[0]))
			if domain == host {
				matched = true
			} else if strings.HasPrefix(domain, "*.") && strings.HasSuffix(host, domain[1:]) {
				matched, broad = true, true
			}
		}
		if !matched {
			return "does not cover every literal command destination"
		}
	}
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(strings.Split(domain, ":")[0]))
		if strings.HasPrefix(domain, "*.") || !hosts[domain] {
			broad = true
		}
	}
	if broad {
		return "is broader than its literal command destination(s)"
	}
	return "narrowly names its literal command destination(s)"
}

func contextIs(value model.ContextValue, want string) bool {
	return (value.State == model.ContextKnown || value.State == model.ContextCandidate) && value.Value == want
}

func contextKnownIs(value model.ContextValue, want string) bool {
	return value.State == model.ContextKnown && value.Value == want
}

func anchorVersionDescription(value model.ContextValue, anchor string) string {
	if contextKnownIs(value, anchor) {
		return "Claude Code " + anchor + " is supplied"
	}
	if value.State == model.ContextKnown {
		return "the supplied version is not the exact Claude Code " + anchor + " release anchor, so anchor-specific behavior is unresolved"
	}
	return "the effective installed Claude Code version is unknown"
}

func compareStableVersion(value model.ContextValue, major, minor, patch int) (int, bool) {
	if value.State != model.ContextKnown {
		return 0, false
	}
	parts := strings.Split(strings.TrimPrefix(value.Value, "v"), ".")
	if len(parts) != 3 {
		return 0, false
	}
	got := make([]int, 3)
	for i := range parts {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return 0, false
		}
		got[i] = n
	}
	want := []int{major, minor, patch}
	for i := range got {
		if got[i] != want[i] {
			if got[i] > want[i] {
				return 1, true
			}
			return -1, true
		}
	}
	return 0, true
}
