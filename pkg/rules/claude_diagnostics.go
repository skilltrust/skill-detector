package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/model"
	"gopkg.in/yaml.v3"
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
		settings, valid := decodeClaudeDiagnosticSettings(content)
		if !valid {
			return nil, fmt.Errorf("malformed Claude settings JSON or unsupported analyzed field type; configuration was not assessed")
		}
		warnings = append(warnings, claudePermissionDiagnostics(settings, ctx)...)
	}
	if isClaudeSkillOrCommand(ctx.Path) {
		body := markdownBodyWithoutParsedFrontmatter(string(content))
		if count := inlineShellDeclarationCount(body); count > 0 {
			version := anchorVersionDescription(ctx.Analysis.Version, claudeAutoModeAnchor)
			warnings = append(warnings, fmt.Sprintf("%s: %d executable inline shell declaration(s) use !`command` or a ```! block; %s. At the 2.1.271 anchor, auto-mode skill/command injections use default-mode permissions and an undecided command falls back to a reviewed tool call. This is parsed as a declaration only; execution, approval and session activation were not tested.", ctx.Path, count, version))
		}
	}
	warnings = append(warnings, allowedDomainDiagnostics(content, ctx)...)
	return warnings, nil
}

func decodeClaudeDiagnosticSettings(content []byte) (claudeDiagnosticSettings, bool) {
	var settings claudeDiagnosticSettings
	var root map[string]json.RawMessage
	if err := json.Unmarshal(content, &root); err != nil || root == nil {
		return settings, false
	}
	if !hasUnambiguousAnalyzedJSONMembers(content) {
		return settings, false
	}
	if raw, ok := jsonField(root, "allowManagedPermissionRulesOnly"); ok && !validJSONBool(raw) {
		return settings, false
	}
	if raw, ok := jsonField(root, "permissions"); ok {
		permissions, valid := jsonObject(raw)
		if !valid {
			return settings, false
		}
		for _, key := range []string{"allow", "ask", "deny"} {
			if field, present := jsonField(permissions, key); present && !validJSONStringArray(field) {
				return settings, false
			}
		}
		if field, present := jsonField(permissions, "defaultMode"); present && !validJSONString(field) {
			return settings, false
		}
	}
	if raw, ok := jsonField(root, "sandbox"); ok {
		sandbox, valid := jsonObject(raw)
		if !valid {
			return settings, false
		}
		if field, present := jsonField(sandbox, "excludedCommands"); present && !validJSONStringArray(field) {
			return settings, false
		}
	}
	if err := json.Unmarshal(content, &settings); err != nil {
		return settings, false
	}
	return settings, true
}

func hasUnambiguousAnalyzedJSONMembers(content []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if !consumeJSONValue(decoder, "root") {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func consumeJSONValue(decoder *json.Decoder, scope string) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return true
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return false
			}
			canonical, childScope := analyzedJSONMember(scope, key)
			if canonical != "" && seen[canonical] {
				return false
			}
			if canonical != "" {
				seen[canonical] = true
			}
			if !consumeJSONValue(decoder, childScope) {
				return false
			}
		}
	case '[':
		for decoder.More() {
			if !consumeJSONValue(decoder, "") {
				return false
			}
		}
	default:
		return false
	}
	closing, err := decoder.Token()
	want := json.Delim('}')
	if delimiter == '[' {
		want = ']'
	}
	return err == nil && closing == want
}

func analyzedJSONMember(scope, key string) (canonical, childScope string) {
	var names []string
	switch scope {
	case "root":
		names = []string{"allowManagedPermissionRulesOnly", "permissions", "sandbox"}
	case "permissions":
		names = []string{"allow", "ask", "deny", "defaultMode"}
	case "sandbox":
		names = []string{"excludedCommands"}
	}
	for _, name := range names {
		if strings.EqualFold(key, name) {
			if scope == "root" && (name == "permissions" || name == "sandbox") {
				childScope = name
			}
			return name, childScope
		}
	}
	return "", ""
}

func jsonField(object map[string]json.RawMessage, name string) (json.RawMessage, bool) {
	for key, value := range object {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return nil, false
}

func jsonObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var value map[string]json.RawMessage
	err := json.Unmarshal(raw, &value)
	return value, err == nil && value != nil
}

func validJSONBool(raw json.RawMessage) bool {
	if strings.TrimSpace(string(raw)) == "null" {
		return false
	}
	var value bool
	return json.Unmarshal(raw, &value) == nil
}

func validJSONString(raw json.RawMessage) bool {
	if strings.TrimSpace(string(raw)) == "null" {
		return false
	}
	var value string
	return json.Unmarshal(raw, &value) == nil
}

func validJSONStringArray(raw json.RawMessage) bool {
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return false
	}
	for _, value := range values {
		if !validJSONString(value) {
			return false
		}
	}
	return true
}

func claudePermissionDiagnostics(settings claudeDiagnosticSettings, ctx model.FileContext) []string {
	var warnings []string
	origin := ctx.Analysis.DeclarationOrigin
	version := ctx.Analysis.Version
	prefix := ctx.Path + ": "
	versionCompared, comparableStableVersion := compareStableVersion(version, 2, 1, 257)
	knownProjectOrigin := contextKnownIs(origin, "project") || contextKnownIs(origin, "project-local")
	projectOrigin := knownProjectOrigin || contextCandidateIs(origin, "project") || contextCandidateIs(origin, "project-local")

	if settings.Permissions.DefaultMode == "bypassPermissions" {
		switch {
		case knownProjectOrigin && comparableStableVersion && versionCompared >= 0:
			warnings = append(warnings, prefix+"declares permissions.defaultMode=bypassPermissions, but Claude Code "+version.Value+" does not activate auto or bypassPermissions from project/local settings; this is not an effective bypass declaration for the supplied context. Session flags and higher-precedence sources remain unavailable.")
		case projectOrigin && comparableStableVersion && versionCompared >= 0:
			warnings = append(warnings, prefix+"declares permissions.defaultMode=bypassPermissions in a candidate project/local source. If loaded from that source under Claude Code "+version.Value+", it would not activate auto or bypassPermissions; effective source, session flags and higher-precedence sources remain unresolved.")
		case knownProjectOrigin && comparableStableVersion:
			warnings = append(warnings, prefix+"declares permissions.defaultMode=bypassPermissions from project/local settings. At the supplied pre-2.1.257 version this source could select the mode only when its activation conditions, including workspace trust, were met; session overrides remain unavailable.")
		case projectOrigin && comparableStableVersion:
			warnings = append(warnings, prefix+"declares permissions.defaultMode=bypassPermissions in a candidate project/local source. If loaded from that source at the supplied pre-2.1.257 version, it could select the mode only when activation conditions, including workspace trust, were met; effective source and session overrides remain unresolved.")
		case projectOrigin:
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
			switch {
			case comparableStableVersion && versionCompared >= 0:
				warnings = append(warnings, prefix+"managed allowManagedPermissionRulesOnly=true declares that user, project, local, --settings and --allowedTools permission rules are ignored. Current documentation says command-line/session deny and ask rules can still tighten policy at the supplied version. Runtime managed-policy activation remains a supplied-context condition, not a repository inference.")
			case comparableStableVersion:
				warnings = append(warnings, prefix+"managed allowManagedPermissionRulesOnly=true declares that lower-tier permission rules are ignored. At the supplied pre-2.1.257 version, command-line/session deny and ask rules were dropped at the first settings reload, so they must not be treated as durable tightening. Runtime managed-policy activation remains a supplied-context condition.")
			default:
				warnings = append(warnings, prefix+"managed allowManagedPermissionRulesOnly=true declares that lower-tier permission rules are ignored. Current documentation says command-line/session deny and ask rules can tighten policy, but before 2.1.257 those rules were dropped at the first settings reload; applicability to the supplied unknown or prerelease version is unresolved. Runtime managed-policy activation remains a supplied-context condition.")
			}
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

func markdownBodyWithoutParsedFrontmatter(content string) string {
	lines := strings.SplitAfter(content, "\n")
	if len(lines) == 0 || strings.TrimRight(lines[0], "\r\n") != "---" {
		return content
	}
	frontmatterEnd := len(lines[0])
	for _, line := range lines[1:] {
		if strings.TrimRight(line, "\r\n") == "---" {
			frontmatter := content[len(lines[0]):frontmatterEnd]
			var value any
			if yaml.Unmarshal([]byte(frontmatter), &value) == nil {
				return content[frontmatterEnd+len(line):]
			}
			return content
		}
		frontmatterEnd += len(line)
	}
	return content
}

func broadExcludedCommand(pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if strings.HasSuffix(pattern, ":*") {
		pattern = strings.TrimSuffix(pattern, ":*") + " *"
	}
	return pattern == "*" || strings.HasPrefix(pattern, "*") || strings.HasPrefix(pattern, "bash ") ||
		strings.HasPrefix(pattern, "bash*") || strings.HasPrefix(pattern, "sh ") || strings.HasPrefix(pattern, "sh*") ||
		strings.HasPrefix(pattern, "powershell ") || strings.HasPrefix(pattern, "powershell*")
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
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return nil
	}
	if _, err := decoder.Token(); err != io.EOF {
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

var commandURL = regexp.MustCompile(`(?i:https?)://[^\s"'<>;|&()]+`)

type domainTarget struct {
	host string
	port string
}

type domainPattern struct {
	host     string
	port     string
	wildcard bool
}

func classifyDomainDeclaration(command string, domains []string) string {
	targets := make(map[domainTarget]bool)
	for _, bounds := range commandURL.FindAllStringIndex(command, -1) {
		if unsupportedURLBoundary(command, bounds[0], bounds[1]) {
			return "cannot be compared because a destination uses unsupported quoting or interpolation"
		}
		raw := command[bounds[0]:bounds[1]]
		target, valid := parseDomainTarget(raw)
		if !valid {
			return "cannot be compared because a destination uses an unsupported host/port form"
		}
		targets[target] = true
	}
	if len(targets) == 0 {
		return "has no literal command destination available for comparison"
	}
	patterns := make(map[domainPattern]bool, len(domains))
	exactPorts := make(map[domainTarget]bool)
	exactAnyPort := make(map[string]bool)
	wildcardPorts := make(map[domainTarget]bool)
	wildcardAnyPort := make(map[string]bool)
	for _, raw := range domains {
		pattern, valid := parseDomainPattern(raw)
		if !valid {
			return "cannot be compared because an allowed domain uses an unsupported host/port form"
		}
		patterns[pattern] = false
		switch {
		case pattern.wildcard && pattern.port == "":
			wildcardAnyPort[pattern.host] = true
		case pattern.wildcard:
			wildcardPorts[domainTarget{host: pattern.host, port: pattern.port}] = true
		case pattern.port == "":
			exactAnyPort[pattern.host] = true
		default:
			exactPorts[domainTarget{host: pattern.host, port: pattern.port}] = true
		}
	}
	broad := false
	for target := range targets {
		matched := false
		if exactPorts[target] {
			matched = true
			patterns[domainPattern{host: target.host, port: target.port}] = true
		}
		if exactAnyPort[target.host] {
			matched, broad = true, true
			patterns[domainPattern{host: target.host}] = true
		}
		for _, suffix := range strictDomainSuffixes(target.host) {
			if wildcardPorts[domainTarget{host: suffix, port: target.port}] {
				matched, broad = true, true
				patterns[domainPattern{host: suffix, port: target.port, wildcard: true}] = true
			}
			if wildcardAnyPort[suffix] {
				matched, broad = true, true
				patterns[domainPattern{host: suffix, wildcard: true}] = true
			}
		}
		if !matched {
			return "does not cover every literal command destination"
		}
	}
	for _, matched := range patterns {
		if !matched {
			broad = true
		}
	}
	if broad {
		return "is broader than its literal command destination(s)"
	}
	return "narrowly names its literal command destination(s)"
}

func unsupportedURLBoundary(command string, start, end int) bool {
	quoted := start > 0 && (command[start-1] == '\'' || command[start-1] == '"')
	if quoted {
		quote := command[start-1]
		if end >= len(command) || command[end] != quote {
			return true
		}
		opening := start - 1
		if opening > 0 && !isShellWordBoundaryAt(command, opening-1) {
			return true
		}
		after := end + 1
		if after < len(command) && !isShellWordBoundaryAt(command, after) {
			return true
		}
	} else {
		if start > 0 && !isShellWordBoundaryAt(command, start-1) {
			return true
		}
		if end < len(command) && !isShellWordBoundaryAt(command, end) {
			return true
		}
	}
	return strings.ContainsAny(command[start:end], "$`\\")
}

func isShellWordBoundaryAt(command string, index int) bool {
	char := command[index]
	if char != ' ' && char != '\t' && char != '\r' && char != '\n' && !strings.ContainsRune(";|&<>", rune(char)) {
		return false
	}
	if char == '\n' && index > 0 && command[index-1] == '\r' {
		index--
	}
	escapes := 0
	escape := byte(0)
	if index > 0 && (command[index-1] == '\\' || command[index-1] == '`') {
		escape = command[index-1]
	}
	for index > 0 && command[index-1] == escape {
		escapes++
		index--
	}
	return escapes%2 == 0
}

func strictDomainSuffixes(host string) []string {
	var suffixes []string
	for {
		dot := strings.IndexByte(host, '.')
		if dot < 0 {
			return suffixes
		}
		host = host[dot+1:]
		suffixes = append(suffixes, host)
	}
}

func parseDomainTarget(raw string) (domainTarget, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return domainTarget{}, false
	}
	host := normalizeDomainHost(parsed.Hostname())
	if !validDomainHost(host) {
		return domainTarget{}, false
	}
	port := parsed.Port()
	if !validDomainPort(port) {
		return domainTarget{}, false
	}
	if port == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return domainTarget{host: host, port: port}, host != ""
}

func parseDomainPattern(raw string) (domainPattern, bool) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" || strings.Contains(raw, "://") || strings.ContainsAny(raw, "/?# ") {
		return domainPattern{}, false
	}
	pattern := domainPattern{}
	if strings.HasPrefix(raw, "*.") {
		pattern.wildcard = true
		raw = raw[2:]
	}
	host, port, valid := splitDomainHostPort(raw)
	if !valid || (pattern.wildcard && net.ParseIP(host) != nil) {
		return domainPattern{}, false
	}
	pattern.host = normalizeDomainHost(host)
	pattern.port = port
	return pattern, validDomainHost(pattern.host)
}

func splitDomainHostPort(raw string) (host, port string, valid bool) {
	if strings.HasPrefix(raw, "[") {
		end := strings.IndexByte(raw, ']')
		if end < 0 {
			return "", "", false
		}
		host = raw[1:end]
		rest := raw[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") || len(rest) == 1 {
				return "", "", false
			}
			port = rest[1:]
		}
		if net.ParseIP(host) == nil {
			return "", "", false
		}
	} else if strings.Count(raw, ":") > 1 {
		return "", "", false
	} else if before, after, found := strings.Cut(raw, ":"); found {
		if after == "" {
			return "", "", false
		}
		host, port = before, after
	} else {
		host = raw
	}
	return host, port, host != "" && validDomainPort(port)
}

func normalizeDomainHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

func validDomainHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func validDomainPort(port string) bool {
	if port == "" {
		return true
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == port
}

func contextIs(value model.ContextValue, want string) bool {
	return (value.State == model.ContextKnown || value.State == model.ContextCandidate) && value.Value == want
}

func contextKnownIs(value model.ContextValue, want string) bool {
	return value.State == model.ContextKnown && value.Value == want
}

func contextCandidateIs(value model.ContextValue, want string) bool {
	return value.State == model.ContextCandidate && value.Value == want
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
