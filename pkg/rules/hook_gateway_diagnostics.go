package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/model"
	"gopkg.in/yaml.v3"
)

var gatewayBoundaryAssignment = regexp.MustCompile(`(?m)^\s*(?:export\s+)?CLAUDE_GATEWAY_PROXY_IS_EGRESS_BOUNDARY\s*=\s*["']?1["']?\s*(?:#.*)?$`)
var (
	exactHookMatcher       = regexp.MustCompile(`^[A-Za-z0-9_\- ,|]+$`)
	narrowExactHookMatcher = regexp.MustCompile(`^[A-Za-z0-9_|]+$`)
	structuredHTTPURL      = regexp.MustCompile(`(?i)https?://[^\s"'` + "`" + `<>]+`)
	anyURLScheme           = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://`)
	incompatibleHookRepeat = regexp.MustCompile(`\{(?:0[0-9]+(?:,[0-9]*)?|[0-9]+,0[0-9]+)\}`)
)

const claudeSubagentStopAnchor = "2.1.275"

type hookPolicy struct {
	urlAllowlistSet bool
	urlAllowlistLen int
	envAllowlistSet bool
	envAllowlistLen int
}

func claudeHookDiagnostics(content []byte, ctx model.FileContext) []string {
	if !IsClaudeSettings(ctx.Path) {
		return nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(content, &root); err != nil {
		return nil
	}
	var hooks map[string]json.RawMessage
	rawHooks, present := root["hooks"]
	if !present {
		return nil
	}
	if err := json.Unmarshal(rawHooks, &hooks); err != nil || hooks == nil {
		return []string{ctx.Path + ": hooks uses an unsupported top-level shape and was not assessed as active configuration"}
	}
	policy := decodeHookPolicy(content)
	var diagnostics []string
	for _, declaration := range allHookDeclarations(hooks) {
		eventLabel := declaration.Event
		if !knownHookEvent(eventLabel) {
			eventLabel = "an unknown event"
		}
		prefix := fmt.Sprintf("%s: %s hook event %s", ctx.Path, hookTypeLabel(declaration), eventLabel)
		if declaration.Unsupported != "" {
			diagnostics = append(diagnostics, prefix+" uses "+declaration.Unsupported+"; it is inspected for existing command rules when possible but is not treated as an active documented hook")
			continue
		}

		activation := hookActivationDescription(declaration, ctx.Analysis)
		switch declaration.Handler.Type {
		case "command":
			diagnostics = append(diagnostics, fmt.Sprintf("%s with %s; %s. A command handler receives event JSON on stdin. Effective settings source, trust, session and installed version remain activation conditions; the scanner parses the declaration and never executes it.", prefix, matcherLabel(declaration), activation))
		case "http":
			destination := safeURLDestination(declaration.Handler.URL)
			exposure := fmt.Sprintf("POSTs the event JSON body to %s and declares %d header(s) with %d handler-allowed environment variable(s)", destination, len(declaration.Handler.Headers), len(declaration.Handler.AllowedEnvVars))
			policyText := hookPolicyDescription(policy)
			diagnostics = append(diagnostics, fmt.Sprintf("%s with %s %s; %s. It %s. %s Effective settings source, trust, session and installed version remain activation conditions. Header values and URL credentials/query data are redacted. An endpoint response is untrusted runtime data: this scanner never contacts the host and no response can instruct or alter this analysis.", prefix, matcherLabel(declaration), policyText, activation, exposure, hookDocumentationContext(ctx.Analysis.Version)))
		}
	}
	return diagnostics
}

func hookDocumentationContext(version model.ContextValue) string {
	if version.State == model.ContextKnown {
		return "Current hooks documentation describes this shape, but does not establish its introduction or applicability to the supplied Claude Code " + version.Value + " version."
	}
	return "Current hooks documentation describes this shape; the installed version and historical applicability are unknown."
}

func decodeHookPolicy(content []byte) hookPolicy {
	var root map[string]json.RawMessage
	if json.Unmarshal(content, &root) != nil {
		return hookPolicy{}
	}
	var policy hookPolicy
	if raw, ok := root["allowedHttpHookUrls"]; ok {
		var values []string
		if json.Unmarshal(raw, &values) == nil && values != nil {
			policy.urlAllowlistSet = true
			policy.urlAllowlistLen = len(values)
		}
	}
	if raw, ok := root["httpHookAllowedEnvVars"]; ok {
		var values []string
		if json.Unmarshal(raw, &values) == nil && values != nil {
			policy.envAllowlistSet = true
			policy.envAllowlistLen = len(values)
		}
	}
	return policy
}

func hookPolicyDescription(policy hookPolicy) string {
	urlPolicy := "has no same-file URL allowlist"
	if policy.urlAllowlistSet {
		urlPolicy = fmt.Sprintf("has a same-file URL allowlist with %d pattern(s)", policy.urlAllowlistLen)
	}
	envPolicy := "has no same-file outer environment allowlist"
	if policy.envAllowlistSet {
		envPolicy = fmt.Sprintf("has a same-file outer environment allowlist with %d name(s)", policy.envAllowlistLen)
	}
	return "(" + urlPolicy + " and " + envPolicy + "; arrays from other effective settings sources may merge, so same-file policy does not prove activation)"
}

func hookTypeLabel(declaration hookDeclaration) string {
	if declaration.Handler.Type == "http" {
		return "HTTP"
	}
	if declaration.Handler.Type == "command" || declaration.Handler.Command != "" {
		return "command"
	}
	return "unsupported"
}

func matcherLabel(declaration hookDeclaration) string {
	if !declaration.MatcherSet {
		return "an omitted matcher"
	}
	if declaration.Matcher == "" {
		return "an empty catch-all matcher"
	}
	if declaration.Matcher == "*" {
		return "a wildcard matcher"
	}
	return "a specific matcher"
}

func hookActivationDescription(declaration hookDeclaration, analysis model.AnalysisContext) string {
	if !knownHookEvent(declaration.Event) {
		return "the event is not recognized by the bounded current-event model, so activation is unsupported"
	}
	if declaration.Handler.Type == "http" && (declaration.Event == "SessionStart" || declaration.Event == "Setup") {
		return "current documentation does not support HTTP handlers for this event, so this declaration is inactive in the documented schema"
	}
	event := analysis.Conditions["claude_hook_event"]
	if event.State != model.ContextKnown {
		return "runtime event data is unknown, so event and matcher activation are unresolved"
	}
	if event.Value != declaration.Event {
		return "the supplied runtime event does not match this declaration, so it is inactive for that event"
	}
	if !hookEventSupportsMatcher(declaration.Event) {
		if declaration.MatcherSet {
			return "the supplied event matches; this event does not support matcher filtering, so the configured matcher is ignored, but runtime activation is not proven"
		}
		return "the supplied event matches this declaration without matcher filtering, but runtime activation is not proven"
	}
	if !declaration.MatcherSet || declaration.Matcher == "" || declaration.Matcher == "*" {
		return "the supplied event matches this catch-all declaration, but runtime activation is not proven"
	}
	exact := hookMatcherIsExact(declaration.Event, declaration.Matcher)
	if exact && (strings.Contains(declaration.Matcher, ",") || matcherUsesWhitespaceTolerance(declaration.Matcher)) {
		if comparison, ok := compareStableVersion(analysis.Version, 2, 1, 191); !ok || comparison < 0 {
			return "the event matches, but comma-list or separator-whitespace semantics require Claude Code 2.1.191 or later and the supplied version does not establish applicability, so activation is unresolved"
		}
	}
	if exact && strings.Contains(declaration.Matcher, "-") {
		if comparison, ok := compareStableVersion(analysis.Version, 2, 1, 195); !ok || comparison < 0 {
			return "the event matches, but exact hyphen semantics require Claude Code 2.1.195 or later and the supplied version does not establish applicability, so activation is unresolved"
		}
	}
	conditionName := "claude_hook_matcher_value"
	if declaration.Event == "SubagentStop" {
		conditionName = "claude_subagent_agent_type"
	}
	value := analysis.Conditions[conditionName]
	if value.State != model.ContextKnown {
		return "the event matches but matcher input is unknown, so activation is unresolved"
	}
	matched, supported := hookMatcherMatches(declaration.Matcher, value.Value, exact)
	if !supported {
		return "the matcher uses regular-expression syntax outside the bounded evaluator, so activation is unresolved"
	}
	if matched {
		return "the supplied event and matcher input match, but runtime activation is not proven"
	}
	if declaration.Event == "SubagentStop" && value.Value == "" {
		if contextKnownIs(analysis.Version, claudeSubagentStopAnchor) {
			return "the supplied SubagentStop agent type is empty and does not match this specific matcher, as fixed at the exact Claude Code 2.1.275 release anchor"
		}
		return "the supplied SubagentStop agent type is empty, but empty-agent-type behavior is unresolved without the exact Claude Code 2.1.275 release anchor"
	}
	return "the supplied matcher input does not match, so the declaration is inactive for that event"
}

func hookMatcherIsExact(event, pattern string) bool {
	if event == "FileChanged" || event == "StopFailure" {
		return narrowExactHookMatcher.MatchString(pattern)
	}
	return exactHookMatcher.MatchString(pattern)
}

func matcherUsesWhitespaceTolerance(pattern string) bool {
	for index, char := range pattern {
		if char != '|' && char != ',' {
			continue
		}
		if (index > 0 && pattern[index-1] == ' ') || (index+1 < len(pattern) && pattern[index+1] == ' ') {
			return true
		}
	}
	return false
}

func hookMatcherMatches(pattern, value string, exact bool) (matched, supported bool) {
	if exact {
		for part := range strings.FieldsFuncSeq(pattern, func(r rune) bool { return r == '|' || r == ',' }) {
			if strings.TrimSpace(part) == value {
				return true, true
			}
		}
		return false, true
	}
	if !compatibleHookRegexp(pattern, value) {
		return false, false
	}
	matcher, err := regexp.Compile(pattern)
	if err != nil {
		return false, false
	}
	return matcher.MatchString(value), true
}

func compatibleHookRegexp(pattern, value string) bool {
	if strings.Contains(pattern, "(?") || strings.Contains(pattern, "[[:") || strings.Contains(pattern, "[]") ||
		strings.Contains(pattern, "[^]") || incompatibleHookRepeat.MatchString(pattern) {
		return false
	}
	for _, char := range pattern {
		if char > 0xffff {
			return false
		}
	}
	for _, char := range value {
		if char > 0xffff {
			return false
		}
	}
	if regexpHasWildcard(pattern) && strings.ContainsAny(value, "\r\u2028\u2029") {
		return false
	}
	for index := 0; index < len(pattern); index++ {
		if pattern[index] != '\\' || index+1 >= len(pattern) {
			continue
		}
		index++
		escaped := pattern[index]
		if escaped >= '0' && escaped <= '9' {
			return false
		}
		if (escaped >= 'A' && escaped <= 'Z') || (escaped >= 'a' && escaped <= 'z') {
			if !strings.ContainsRune("dDwWbB", rune(escaped)) {
				return false
			}
		}
	}
	return true
}

func regexpHasWildcard(pattern string) bool {
	escaped, inClass := false, false
	for _, char := range pattern {
		if escaped {
			escaped = false
			continue
		}
		switch char {
		case '\\':
			escaped = true
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '.':
			if !inClass {
				return true
			}
		}
	}
	return false
}

func hookEventSupportsMatcher(event string) bool {
	switch event {
	case "UserPromptSubmit", "PostToolBatch", "Stop", "TeammateIdle", "TaskCreated", "TaskCompleted",
		"WorktreeCreate", "WorktreeRemove", "MessageDisplay", "CwdChanged":
		return false
	default:
		return true
	}
}

func knownHookEvent(event string) bool {
	switch event {
	case "SessionStart", "Setup", "UserPromptSubmit", "PreToolUse", "PermissionRequest",
		"PostToolUse", "PostToolUseFailure", "Notification", "SubagentStart", "SubagentStop",
		"Stop", "StopFailure", "TeammateIdle", "TaskCompleted", "ConfigChange", "CwdChanged", "FileChanged",
		"WorktreeCreate", "WorktreeRemove", "PreCompact", "SessionEnd", "InstructionsLoaded",
		"Elicitation", "ElicitationResult", "PostToolBatch", "TaskCreated", "PermissionDenied",
		"UserPromptExpansion", "PreModelSwitch", "PostModelSwitch", "PostCompact", "MessageDisplay":
		return true
	default:
		return false
	}
}

func gatewayDiagnostics(content []byte, ctx model.FileContext) []string {
	if !InScope(ctx) {
		return nil
	}
	boundary := gatewayBoundaryDeclared(content, ctx.Path)
	headers, placeholders := gatewayUpstreamHeaders(content, ctx.Path)
	if !boundary && headers == 0 {
		return nil
	}
	version := anchorVersionDescription(ctx.Analysis.Version, claudeSandboxAnchor)
	var diagnostics []string
	if boundary {
		topology := ctx.Analysis.Conditions["claude_gateway_sole_egress"]
		topologyText := "the sole-egress topology is unknown"
		if topology.State == model.ContextKnown && topology.Value == "true" {
			topologyText = "supplied context says the forward proxy is the sole egress path, but static analysis cannot verify that claim"
		} else if topology.State == model.ContextKnown {
			topologyText = "supplied context does not establish the forward proxy as the sole egress path"
		}
		diagnostics = append(diagnostics, fmt.Sprintf("%s: declares CLAUDE_GATEWAY_PROXY_IS_EGRESS_BOUNDARY=1; %s. At the 2.1.277 anchor this is only for a Claude apps gateway whose sole egress is a forward proxy and changes hostname resolution by handing hostnames to that proxy. The declaration proves neither DNS/routing behavior nor network confinement; %s.", ctx.Path, version, topologyText))
	}
	if headers > 0 {
		diagnostics = append(diagnostics, fmt.Sprintf("%s: Claude apps gateway upstreams declare %d static header(s), including %d environment placeholder(s); %s. Values are redacted. Headers go to the configured base_url destination, or the provider endpoint when base_url is absent, and may reach the provider unless an intermediary removes them. A header map is exposure inventory, not evidence of malicious behavior or successful delivery.", ctx.Path, headers, placeholders, version))
	}
	return diagnostics
}

func gatewayUpstreamHeaders(content []byte, path string) (headers, placeholders int) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yaml" && ext != ".yml" && ext != ".json" {
		return 0, 0
	}
	if !bytes.Contains(content, []byte("upstreams")) || !bytes.Contains(content, []byte("headers")) {
		return 0, 0
	}
	var document yaml.Node
	if yaml.Unmarshal(content, &document) != nil || len(document.Content) == 0 {
		return 0, 0
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return 0, 0
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if yamlScalarValue(root.Content[i]) != "upstreams" {
			continue
		}
		upstreams := yamlAliasTarget(root.Content[i+1], make(map[*yaml.Node]bool))
		if upstreams == nil || upstreams.Kind != yaml.SequenceNode {
			continue
		}
		for _, rawUpstream := range upstreams.Content {
			upstream := yamlAliasTarget(rawUpstream, make(map[*yaml.Node]bool))
			if upstream == nil || upstream.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(upstream.Content); j += 2 {
				if yamlScalarValue(upstream.Content[j]) != "headers" {
					continue
				}
				values := yamlAliasTarget(upstream.Content[j+1], make(map[*yaml.Node]bool))
				if values == nil || values.Kind != yaml.MappingNode {
					continue
				}
				headers += len(values.Content) / 2
				for k := 1; k < len(values.Content); k += 2 {
					value := yamlScalarValue(values.Content[k])
					if strings.Contains(value, "${") || strings.Contains(value, "$ENV{") {
						placeholders++
					}
				}
			}
		}
	}
	return headers, placeholders
}

func gatewayBoundaryDeclared(content []byte, path string) bool {
	if gatewayBoundaryAssignment.Match(content) {
		return true
	}
	if !bytes.Contains(content, []byte("CLAUDE_GATEWAY_PROXY_IS_EGRESS_BOUNDARY")) {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yaml" && ext != ".yml" && ext != ".json" {
		return false
	}
	var document yaml.Node
	if yaml.Unmarshal(content, &document) != nil {
		return false
	}
	return yamlScalarPairExists(&document, "CLAUDE_GATEWAY_PROXY_IS_EGRESS_BOUNDARY", "1", make(map[*yaml.Node]bool))
}

func yamlScalarPairExists(node *yaml.Node, key, value string, visited map[*yaml.Node]bool) bool {
	if node == nil || visited[node] {
		return false
	}
	visited[node] = true
	if alias := yamlAliasTarget(node, make(map[*yaml.Node]bool)); alias != node {
		return yamlScalarPairExists(alias, key, value, visited)
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if yamlScalarValue(node.Content[i]) == key && yamlScalarValue(node.Content[i+1]) == value {
				return true
			}
			if yamlScalarPairExists(node.Content[i+1], key, value, visited) {
				return true
			}
		}
	}
	for _, child := range node.Content {
		if node.Kind != yaml.MappingNode && yamlScalarPairExists(child, key, value, visited) {
			return true
		}
	}
	return false
}

func yamlAliasTarget(node *yaml.Node, visited map[*yaml.Node]bool) *yaml.Node {
	for node != nil && node.Kind == yaml.AliasNode && node.Alias != nil {
		if visited[node] {
			return nil
		}
		visited[node] = true
		node = node.Alias
	}
	return node
}

func yamlScalarValue(node *yaml.Node) string {
	node = yamlAliasTarget(node, make(map[*yaml.Node]bool))
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}

func publishedURL(raw string) string {
	return safeURLDestination(raw)
}

func safeURLDestination(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if strings.Contains(trimmed, "@") {
		return "an unresolved redacted destination"
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return "an unresolved redacted destination"
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	if pathLooksSensitive(parsed.Path) {
		parsed.Path = "/[redacted]"
		parsed.RawPath = ""
	}
	if parsed.Opaque != "" && pathLooksSensitive(parsed.Opaque) {
		parsed.Opaque = "[redacted]"
	}
	return parsed.String()
}

func pathLooksSensitive(path string) bool {
	lower := strings.ToLower(path)
	if strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "password") || strings.Contains(lower, "passwd") {
		return true
	}
	for _, segment := range strings.Split(path, "/") {
		if len(segment) >= 12 && strings.ContainsAny(segment, "0123456789") && strings.ContainsAny(segment, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			return true
		}
	}
	return false
}

// RedactPublishedURL removes credential-bearing URL text from published
// rationale without changing ordinary destinations.
func RedactPublishedURL(value string) string {
	return redactURLPath(value)
}

func redactURLPath(value string) string {
	return structuredHTTPURL.ReplaceAllStringFunc(value, safeURLDestination)
}

func sanitizeURLsForDisplay(value string) string {
	return sanitizeStructuredText(value)
}

// SanitizeConfigurationForVerifier removes hook/gateway header values and URL
// credentials before deterministic URL analysis or the verifier boundary.
func SanitizeConfigurationForVerifier(content []byte, ctx model.FileContext) []byte {
	ext := strings.ToLower(filepath.Ext(ctx.Path))
	if (ext == ".json" || ext == ".yaml" || ext == ".yml") && configurationRequiresFullRedaction(content, ext) {
		return failClosedConfiguration(content)
	}
	if ext == ".json" {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.UseNumber()
		if decoder.Decode(&value) == nil {
			if _, err := decoder.Token(); err == io.EOF {
				var values []string
				collectSensitiveJSON(value, false, &values)
				collectHookIfEnvNamesJSON(value, &values)
				collectHookCommandTokensJSON(value, &values)
				return sanitizeSourceLayout(content, values)
			}
		}
		return failClosedConfiguration(content)
	}
	if ext == ".yaml" || ext == ".yml" {
		var document yaml.Node
		if yaml.Unmarshal(content, &document) == nil {
			var values []string
			if collectSensitiveYAML(&document, false, make(map[*yaml.Node]uint8), &values, 0) {
				collectHookIfEnvNamesYAML(&document, &values, make(map[*yaml.Node]bool), 0)
				collectHookCommandTokensYAML(&document, &values, make(map[*yaml.Node]bool), 0)
				return sanitizeSourceLayout(content, values)
			}
		}
		return failClosedConfiguration(content)
	}
	if stringHasSensitiveURL(string(content)) {
		return failClosedConfiguration(content)
	}
	return []byte(sanitizeURLsForDisplay(string(content)))
}

func sanitizeSourceLayout(content []byte, values []string) []byte {
	text := string(content)
	for _, value := range values {
		if value == "" {
			continue
		}
		text = strings.ReplaceAll(text, value, redactionWithLineCount(value))
		if encoded, err := json.Marshal(value); err == nil && len(encoded) >= 2 {
			escaped := string(encoded[1 : len(encoded)-1])
			text = strings.ReplaceAll(text, escaped, redactionWithLineCount(escaped))
		}
	}
	return []byte(redactURLPath(sanitizeStructuredText(text)))
}

var envNameToken = regexp.MustCompile(`\$\{?[A-Z_][A-Z0-9_]{2,}\}?`)

func jsonIfNeedsFullRedaction(value any) bool {
	text, ok := value.(string)
	if !ok {
		return jsonValueHasContent(value)
	}
	return ifHasNonEnvSecret(text)
}

func yamlIfNeedsFullRedaction(node *yaml.Node) bool {
	text := yamlScalarValue(node)
	if text == "" {
		return yamlValueHasContent(node, make(map[*yaml.Node]bool), 0)
	}
	return ifHasNonEnvSecret(text)
}

func jsonCommandNeedsFullRedaction(value any) bool {
	text, ok := value.(string)
	if !ok {
		return jsonValueHasContent(value)
	}
	return commandHasNonURLSecret(text)
}

func yamlCommandNeedsFullRedaction(node *yaml.Node) bool {
	resolved := yamlAliasTarget(node, make(map[*yaml.Node]bool))
	if resolved == nil || resolved.Kind != yaml.ScalarNode {
		return yamlValueHasContent(node, make(map[*yaml.Node]bool), 0)
	}
	return commandHasNonURLSecret(resolved.Value)
}

func commandHasNonURLSecret(text string) bool {
	return len(commandRedactionFragments(text)) > 0
}

func ifHasNonEnvSecret(text string) bool {
	remainder := envNameToken.ReplaceAllString(text, " ")
	for _, field := range strings.FieldsFunc(remainder, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '=' || r == '!' || r == '<' || r == '>' || r == '&' || r == '|' || r == '(' || r == ')' || r == '+' || r == '-' || r == '*' || r == '/' || r == '%'
	}) {
		if field != "" && !isIfLiteral(field) {
			return true
		}
	}
	return strings.ContainsAny(remainder, "\"'`:@\\$?#")
}

func isIfLiteral(field string) bool {
	if field == "true" || field == "false" || field == "null" {
		return true
	}
	if _, err := strconv.Atoi(field); err == nil {
		return true
	}
	return false
}

func collectHookIfEnvNamesJSON(value any, values *[]string) {
	switch value := value.(type) {
	case []any:
		for _, child := range value {
			collectHookIfEnvNamesJSON(child, values)
		}
	case map[string]any:
		if hookHandlerType(jsonTypeValue(value)) {
			for key, child := range value {
				if strings.EqualFold(key, "if") {
					if text, ok := child.(string); ok {
						*values = append(*values, envNameToken.FindAllString(text, -1)...)
					}
				}
			}
		}
		for _, child := range value {
			collectHookIfEnvNamesJSON(child, values)
		}
	}
}

func jsonTypeValue(value map[string]any) string {
	var handler string
	var count int
	for key, child := range value {
		if strings.EqualFold(key, "type") {
			count++
			handler, _ = child.(string)
		}
	}
	if count != 1 {
		return ""
	}
	return handler
}

func collectHookIfEnvNamesYAML(node *yaml.Node, values *[]string, visited map[*yaml.Node]bool, depth int) {
	if node == nil || depth > 100 || visited[node] {
		return
	}
	visited[node] = true
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		collectHookIfEnvNamesYAML(node.Alias, values, visited, depth+1)
		return
	}
	if node.Kind == yaml.MappingNode && yamlHookHandler(node) {
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := yamlAliasTarget(node.Content[index], make(map[*yaml.Node]bool))
			if key == nil || !strings.EqualFold(key.Value, "if") {
				continue
			}
			if text := yamlScalarValue(node.Content[index+1]); text != "" {
				*values = append(*values, envNameToken.FindAllString(text, -1)...)
			}
		}
	}
	for _, child := range node.Content {
		collectHookIfEnvNamesYAML(child, values, visited, depth+1)
	}
}

func failClosedConfiguration(content []byte) []byte {
	return []byte("[redacted: structured configuration could not be sanitized]" + strings.Repeat("\n", bytes.Count(content, []byte("\n"))))
}

func redactionWithLineCount(value string) string {
	return "[redacted]" + strings.Repeat("\n", strings.Count(value, "\n"))
}

func sanitizeStructuredText(value string) string {
	return structuredHTTPURL.ReplaceAllStringFunc(value, safeURLDestination)
}

// SanitizeConfigurationFindings prevents secret-bearing configuration fields
// from crossing the result or verifier boundary while leaving rule matching on
// the original content and source lines.
func SanitizeConfigurationFindings(findings []model.Finding, content []byte, ctx model.FileContext) {
	ext := strings.ToLower(filepath.Ext(ctx.Path))
	if ((ext == ".json" || ext == ".yaml" || ext == ".yml") && configurationRequiresFullRedaction(content, ext)) ||
		stringHasSensitiveURL(string(content)) {
		for index := range findings {
			findings[index].Description = findings[index].RuleName + " detected; configuration-derived details redacted"
			findings[index].Remediation = sanitizeStructuredText(findings[index].Remediation)
			findings[index].Diagnosis = sanitizeStructuredText(findings[index].Diagnosis)
		}
		return
	}
	values := sensitiveConfigurationValues(content, ctx.Path)
	values = append(values, hookCommandRedactionFragments(content, ctx.Path)...)
	var fragments []string
	for _, value := range values {
		fragments = append(fragments, value)
		fragments = append(fragments, structuredHTTPURL.FindAllString(value, -1)...)
		fragments = append(fragments, reFullPath.FindAllString(value, -1)...)
	}
	sort.Slice(fragments, func(i, j int) bool {
		if len(fragments[i]) != len(fragments[j]) {
			return len(fragments[i]) > len(fragments[j])
		}
		return fragments[i] < fragments[j]
	})
	unique := fragments[:0]
	for _, fragment := range fragments {
		if fragment != "" && (len(unique) == 0 || unique[len(unique)-1] != fragment) {
			unique = append(unique, fragment)
		}
	}
	fragments = unique
	sanitize := func(text string) string {
		for _, value := range fragments {
			if value == "" {
				continue
			}
			text = strings.ReplaceAll(text, value, "[redacted]")
			text = strings.ReplaceAll(text, sanitizeStructuredText(value), "[redacted]")
		}
		return sanitizeStructuredText(text)
	}
	for index := range findings {
		findings[index].Description = redactURLPath(sanitize(findings[index].Description))
		findings[index].Remediation = redactURLPath(sanitize(findings[index].Remediation))
		findings[index].Diagnosis = redactURLPath(sanitize(findings[index].Diagnosis))
	}
}

func configurationRequiresFullRedaction(content []byte, ext string) bool {
	if ext == ".json" {
		if duplicate, err := jsonHasDuplicateKey(content); err != nil || duplicate {
			return true
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.UseNumber()
		if decoder.Decode(&value) != nil {
			return true
		}
		if _, err := decoder.Token(); err != io.EOF {
			return true
		}
		return jsonHasSensitiveField(value)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	for {
		var document yaml.Node
		err := decoder.Decode(&document)
		if err == io.EOF {
			return false
		}
		if err != nil {
			return true
		}
		if yamlHasSensitiveField(&document, make(map[*yaml.Node]bool), 0) {
			return true
		}
	}
}

func jsonHasSensitiveField(value any) bool {
	switch value := value.(type) {
	case string:
		return stringHasSensitiveURL(value)
	case []any:
		for _, child := range value {
			if jsonHasSensitiveField(child) {
				return true
			}
		}
	case map[string]any:
		var httpHandler string
		var typeKeys int
		for key, child := range value {
			if strings.EqualFold(key, "type") {
				typeKeys++
				httpHandler, _ = child.(string)
			}
		}
		if typeKeys > 1 {
			return true
		}
		structuralHookField := map[string]bool{
			"type": true, "url": true, "command": true, "headers": true, "allowedEnvVars": true,
			"if": true, "timeout": true,
		}
		hookHandler := typeKeys == 1 && hookHandlerType(httpHandler)
		for key, child := range value {
			if strings.EqualFold(key, "headers") && jsonValueHasContent(child) {
				return true
			}
			if (strings.EqualFold(key, "allowedEnvVars") || strings.EqualFold(key, "httpHookAllowedEnvVars")) && jsonValueHasContent(child) {
				return true
			}
			if hookHandler && strings.EqualFold(key, "command") && jsonCommandNeedsFullRedaction(child) {
				return true
			}
			if hookHandler && strings.EqualFold(key, "if") && jsonIfNeedsFullRedaction(child) {
				return true
			}
			if hookHandler && !structuralHookField[key] && jsonValueHasContent(child) {
				return true
			}
			if jsonHasSensitiveField(child) {
				return true
			}
		}
	}
	return false
}

func jsonValueHasContent(value any) bool {
	switch value := value.(type) {
	case string:
		return value != ""
	case []any:
		for _, child := range value {
			if jsonValueHasContent(child) {
				return true
			}
		}
	case map[string]any:
		for _, child := range value {
			if jsonValueHasContent(child) {
				return true
			}
		}
	}
	return false
}

func hookHandlerType(value string) bool {
	switch strings.ToLower(value) {
	case "http", "command", "prompt", "agent", "mcp_tool":
		return true
	default:
		return false
	}
}

func yamlHasSensitiveField(node *yaml.Node, visited map[*yaml.Node]bool, depth int) bool {
	if depth > 100 || visited[node] {
		return depth > 100
	}
	visited[node] = true
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		return yamlHasSensitiveField(node.Alias, visited, depth+1)
	}
	if node.Kind == yaml.ScalarNode {
		return stringHasSensitiveURL(node.Value)
	}
	if node.Kind == yaml.MappingNode {
		handler := yamlHookHandler(node)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := yamlAliasTarget(node.Content[index], make(map[*yaml.Node]bool))
			value := node.Content[index+1]
			if key == nil || key.Kind != yaml.ScalarNode {
				return true
			}
			name := key.Value
			if yamlTypeKeyCount(node) > 1 {
				return true
			}
			if (strings.EqualFold(name, "headers") || strings.EqualFold(name, "allowedEnvVars") || strings.EqualFold(name, "httpHookAllowedEnvVars")) && yamlValueHasContent(value, make(map[*yaml.Node]bool), 0) {
				return true
			}
			if handler && strings.EqualFold(name, "if") && yamlIfNeedsFullRedaction(value) {
				return true
			}
			if handler && strings.EqualFold(name, "command") && yamlCommandNeedsFullRedaction(value) {
				return true
			}
			if handler && !yamlStructuralHookField(name) && yamlValueHasContent(value, make(map[*yaml.Node]bool), 0) {
				return true
			}
			if yamlHasSensitiveField(value, visited, depth+1) {
				return true
			}
		}
		return false
	}
	for _, child := range node.Content {
		if yamlHasSensitiveField(child, visited, depth+1) {
			return true
		}
	}
	return false
}

func yamlTypeKeyCount(node *yaml.Node) int {
	var typeKeys int
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := yamlAliasTarget(node.Content[index], make(map[*yaml.Node]bool))
		if key != nil && key.Kind == yaml.ScalarNode && strings.EqualFold(key.Value, "type") {
			typeKeys++
		}
	}
	return typeKeys
}

func yamlHookHandler(node *yaml.Node) bool {
	if yamlTypeKeyCount(node) != 1 {
		return false
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := yamlAliasTarget(node.Content[index], make(map[*yaml.Node]bool))
		if key == nil || key.Kind != yaml.ScalarNode || !strings.EqualFold(key.Value, "type") {
			continue
		}
		return hookHandlerType(yamlScalarValue(node.Content[index+1]))
	}
	return false
}

func yamlStructuralHookField(name string) bool {
	switch strings.ToLower(name) {
	case "type", "url", "command", "headers", "allowedenvvars", "if", "timeout":
		return true
	default:
		return false
	}
}

func yamlValueHasContent(node *yaml.Node, visited map[*yaml.Node]bool, depth int) bool {
	if node == nil || depth > 100 || visited[node] {
		return depth > 100
	}
	visited[node] = true
	if node.Kind == yaml.AliasNode {
		return yamlValueHasContent(node.Alias, visited, depth+1)
	}
	if node.Kind == yaml.ScalarNode {
		return node.Value != ""
	}
	for _, child := range node.Content {
		if yamlValueHasContent(child, visited, depth+1) {
			return true
		}
	}
	return false
}

func stringHasSensitiveURL(value string) bool {
	for offset := 0; offset < len(value); {
		match := anyURLScheme.FindStringIndex(value[offset:])
		if match == nil {
			return false
		}
		start := offset + match[0]
		end := start
		for end < len(value) && value[end] != ' ' && value[end] != '\t' && value[end] != '\r' && value[end] != '\n' {
			end++
		}
		raw := value[start:end]
		parsed, err := url.Parse(raw)
		if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
			strings.Contains(raw, "@") || strings.ContainsAny(raw, "?#") {
			return true
		}
		offset = end
	}
	return false
}

func jsonHasDuplicateKey(content []byte) (bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	duplicate, err := jsonValueHasDuplicateKey(decoder, 0)
	if err != nil {
		return false, err
	}
	if duplicate {
		return true, nil
	}
	if _, err := decoder.Token(); err != io.EOF {
		return false, err
	}
	return duplicate, nil
}

func jsonValueHasDuplicateKey(decoder *json.Decoder, depth int) (bool, error) {
	if depth > 100 {
		return true, nil
	}
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return false, nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return false, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return false, fmt.Errorf("JSON object key is not a string")
			}
			if seen[key] {
				return true, nil
			}
			seen[key] = true
			duplicate, err := jsonValueHasDuplicateKey(decoder, depth+1)
			if err != nil || duplicate {
				return duplicate, err
			}
		}
		_, err = decoder.Token()
		return false, err
	case '[':
		for decoder.More() {
			duplicate, err := jsonValueHasDuplicateKey(decoder, depth+1)
			if err != nil || duplicate {
				return duplicate, err
			}
		}
		_, err = decoder.Token()
		return false, err
	default:
		return false, fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func hookCommandRedactionFragments(content []byte, path string) []string {
	ext := strings.ToLower(filepath.Ext(path))
	var commands []string
	if ext == ".json" {
		var value any
		if json.Unmarshal(content, &value) == nil {
			collectHookCommandsJSON(value, &commands)
		}
	}
	if ext == ".yaml" || ext == ".yml" {
		var document yaml.Node
		if yaml.Unmarshal(content, &document) == nil {
			collectHookCommandsYAML(&document, &commands, make(map[*yaml.Node]bool), 0)
		}
	}
	var fragments []string
	for _, command := range commands {
		fragments = append(fragments, commandRedactionFragments(command)...)
	}
	return fragments
}

func commandRedactionFragments(command string) []string {
	stripped := structuredHTTPURL.ReplaceAllString(command, " ")
	stripped = envNameToken.ReplaceAllString(stripped, " ")
	var fragments []string
	fields := commandFields(stripped)
	redactRest := false
	for index, field := range fields {
		field = strings.Trim(field, "\"'`=,;()[]{}")
		if redactRest && field != "" {
			fragments = append(fragments, field)
			continue
		}
		if credentialShapedToken(field) || (index > 0 && credentialFlag(fields[index-1]) && field != "") {
			fragments = append(fragments, field)
			if strings.HasSuffix(field, ":") {
				redactRest = true
			}
		}
		if credentialFlag(field) {
			redactRest = true
		}
	}
	return fragments
}

func credentialFlag(field string) bool {
	switch strings.ToLower(strings.Trim(field, "\"'`")) {
	case "-u", "-p", "-h", "--user", "--password", "--header", "--proxy-header", "--proxy-user":
		return true
	default:
		return false
	}
}

func commandFields(command string) []string {
	var fields []string
	var current strings.Builder
	var quote rune
	for _, r := range command {
		switch {
		case quote != 0:
			if r == quote {
				if current.Len() > 0 {
					fields = append(fields, current.String())
					current.Reset()
				}
				quote = 0
				continue
			}
			current.WriteRune(r)
		case r == '"' || r == '\'':
			if current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
			}
			quote = r
		case r == ' ' || r == '\t':
			if current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	return fields
}

func credentialShapedToken(field string) bool {
	if field == "" || strings.Contains(field, "://") {
		return false
	}
	candidate := stripCredentialFlag(field)
	if strings.Contains(candidate, ":") && !strings.HasPrefix(candidate, "-") {
		user, pass, ok := strings.Cut(candidate, ":")
		if ok && user != "" && !strings.Contains(user, "/") && pass != "" {
			return true
		}
	}
	if candidate != field && candidate != "" && !strings.Contains(candidate, " ") {
		return true
	}
	lower := strings.ToLower(field)
	if strings.HasPrefix(field, "AKIA") && len(field) >= 16 {
		return true
	}
	if strings.HasPrefix(lower, "sk-") || strings.HasPrefix(lower, "ghp_") || strings.HasPrefix(lower, "github_pat_") || strings.Count(field, ".") == 2 && len(field) >= 20 {
		return true
	}
	return looksLikeCommandSecret(field)
}

func collectHookCommandTokensJSON(value any, values *[]string) {
	switch value := value.(type) {
	case []any:
		for _, child := range value {
			collectHookCommandTokensJSON(child, values)
		}
	case map[string]any:
		if hookHandlerType(jsonTypeValue(value)) {
			for key, child := range value {
				if strings.EqualFold(key, "command") {
					if text, ok := child.(string); ok {
						*values = append(*values, commandRedactionFragments(text)...)
					}
				}
			}
		}
		for _, child := range value {
			collectHookCommandTokensJSON(child, values)
		}
	}
}

func collectHookCommandTokensYAML(node *yaml.Node, values *[]string, visited map[*yaml.Node]bool, depth int) {
	if node == nil || depth > 100 || visited[node] {
		return
	}
	visited[node] = true
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		collectHookCommandTokensYAML(node.Alias, values, visited, depth+1)
		return
	}
	if node.Kind == yaml.MappingNode && yamlHookHandler(node) {
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := yamlAliasTarget(node.Content[index], make(map[*yaml.Node]bool))
			if key == nil || !strings.EqualFold(key.Value, "command") {
				continue
			}
			if text := yamlScalarValue(node.Content[index+1]); text != "" {
				*values = append(*values, commandRedactionFragments(text)...)
			}
		}
	}
	for _, child := range node.Content {
		collectHookCommandTokensYAML(child, values, visited, depth+1)
	}
}

func stripCredentialFlag(field string) string {
	lower := strings.ToLower(field)
	for _, prefix := range []string{"--header=", "--proxy-header=", "--proxy-user=", "--user=", "--password="} {
		if strings.HasPrefix(lower, prefix) && len(field) > len(prefix) {
			return field[len(prefix):]
		}
	}
	for _, flag := range []string{"-H", "-u", "-p"} {
		if len(field) > len(flag) && strings.EqualFold(field[:len(flag)], flag) && field[len(flag)] != '-' {
			return field[len(flag):]
		}
	}
	return field
}

func looksLikeCommandSecret(field string) bool {
	if len(field) < 8 || strings.Contains(field, "://") || strings.HasPrefix(field, "/") || strings.HasPrefix(field, ".") {
		return false
	}
	lower := strings.ToLower(field)
	return strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "password") || strings.Contains(lower, "bearer")
}

func collectHookCommandsJSON(value any, commands *[]string) {
	switch value := value.(type) {
	case []any:
		for _, child := range value {
			collectHookCommandsJSON(child, commands)
		}
	case map[string]any:
		if hookHandlerType(jsonTypeValue(value)) {
			for key, child := range value {
				if strings.EqualFold(key, "command") {
					if text, ok := child.(string); ok && text != "" {
						*commands = append(*commands, text)
					}
				}
			}
		}
		for _, child := range value {
			collectHookCommandsJSON(child, commands)
		}
	}
}

func collectHookCommandsYAML(node *yaml.Node, commands *[]string, visited map[*yaml.Node]bool, depth int) {
	if node == nil || depth > 100 || visited[node] {
		return
	}
	visited[node] = true
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		collectHookCommandsYAML(node.Alias, commands, visited, depth+1)
		return
	}
	if node.Kind == yaml.MappingNode && yamlHookHandler(node) {
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := yamlAliasTarget(node.Content[index], make(map[*yaml.Node]bool))
			if key == nil || !strings.EqualFold(key.Value, "command") {
				continue
			}
			if text := yamlScalarValue(node.Content[index+1]); text != "" {
				*commands = append(*commands, text)
			}
		}
	}
	for _, child := range node.Content {
		collectHookCommandsYAML(child, commands, visited, depth+1)
	}
}

func sensitiveConfigurationValues(content []byte, path string) []string {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".json" {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.UseNumber()
		if decoder.Decode(&value) == nil {
			var values []string
			collectSensitiveJSON(value, false, &values)
			return values
		}
	}
	if ext == ".yaml" || ext == ".yml" {
		var document yaml.Node
		if yaml.Unmarshal(content, &document) == nil {
			var values []string
			if !collectSensitiveYAML(&document, false, make(map[*yaml.Node]uint8), &values, 0) {
				return []string{string(content)}
			}
			return values
		}
	}
	return nil
}

func collectSensitiveJSON(value any, sensitive bool, values *[]string) {
	switch value := value.(type) {
	case string:
		if sensitive {
			*values = append(*values, value)
		}
	case []any:
		for _, child := range value {
			collectSensitiveJSON(child, sensitive, values)
		}
	case map[string]any:
		var httpHandler string
		for key, child := range value {
			if strings.EqualFold(key, "type") {
				httpHandler, _ = child.(string)
			}
		}
		structuralHookField := map[string]bool{
			"type": true, "url": true, "command": true, "headers": true, "allowedEnvVars": true,
			"if": true, "timeout": true,
		}
		hookHandler := hookHandlerType(httpHandler)
		for key, child := range value {
			childSensitive := sensitive || strings.EqualFold(key, "headers") ||
				strings.EqualFold(key, "allowedEnvVars") || strings.EqualFold(key, "httpHookAllowedEnvVars") ||
				(hookHandler && !structuralHookField[key])
			collectSensitiveJSON(child, childSensitive, values)
		}
	}
}

func collectSensitiveYAML(node *yaml.Node, sensitive bool, visited map[*yaml.Node]uint8, values *[]string, depth int) bool {
	if depth > 100 {
		return false
	}
	state := uint8(1)
	if sensitive {
		state = 2
	}
	if visited[node]&state != 0 {
		return true
	}
	visited[node] |= state
	for _, comment := range []string{node.HeadComment, node.LineComment, node.FootComment} {
		if comment != "" {
			*values = append(*values, comment)
		}
		for _, field := range strings.Fields(comment) {
			if strings.HasPrefix(field, "/") || strings.HasPrefix(field, `\`) || strings.Contains(field, "://") {
				*values = append(*values, field)
			}
		}
	}
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		return collectSensitiveYAML(node.Alias, sensitive, visited, values, depth+1)
	}
	if node.Kind == yaml.ScalarNode {
		if sensitive {
			*values = append(*values, node.Value)
		}
		return true
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			keyNode, value := node.Content[i], node.Content[i+1]
			key := keyNode.Value
			resolvedKey := yamlAliasTarget(keyNode, make(map[*yaml.Node]bool))
			keyName := key
			if resolvedKey != nil && resolvedKey.Kind == yaml.ScalarNode {
				keyName = resolvedKey.Value
			}
			childSensitive := sensitive || strings.EqualFold(keyName, "headers") || strings.EqualFold(keyName, "allowedEnvVars") || strings.EqualFold(keyName, "httpHookAllowedEnvVars") ||
				(yamlHookHandler(node) && resolvedKey != nil && resolvedKey.Kind == yaml.ScalarNode && !yamlStructuralHookField(keyName))
			if !collectSensitiveYAML(value, childSensitive, visited, values, depth+1) {
				return false
			}
		}
		return true
	}
	for _, child := range node.Content {
		if !collectSensitiveYAML(child, sensitive, visited, values, depth+1) {
			return false
		}
	}
	return true
}
