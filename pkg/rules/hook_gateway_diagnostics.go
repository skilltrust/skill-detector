package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/model"
	"gopkg.in/yaml.v3"
)

var gatewayBoundaryAssignment = regexp.MustCompile(`(?m)^\s*(?:export\s+)?CLAUDE_GATEWAY_PROXY_IS_EGRESS_BOUNDARY\s*=\s*["']?1["']?\s*(?:#.*)?$`)

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
			diagnostics = append(diagnostics, fmt.Sprintf("%s with %s %s; %s. It %s. %s Header values and URL credentials/query data are redacted. An endpoint response is untrusted runtime data: this scanner never contacts the host and no response can instruct or alter this analysis.", prefix, matcherLabel(declaration), policyText, activation, exposure, hookDocumentationContext(ctx.Analysis.Version)))
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
	if !declaration.MatcherSet || declaration.Matcher == "" || declaration.Matcher == "*" {
		return "the supplied event matches this catch-all declaration, but runtime activation is not proven"
	}
	matcher, err := regexp.Compile(declaration.Matcher)
	if err != nil {
		return "the matcher is not a supported regular expression, so activation is unresolved"
	}
	conditionName := "claude_hook_matcher_value"
	if declaration.Event == "SubagentStop" {
		conditionName = "claude_subagent_agent_type"
	}
	value := analysis.Conditions[conditionName]
	if value.State != model.ContextKnown {
		return "the event matches but matcher input is unknown, so activation is unresolved"
	}
	if matcher.MatchString(value.Value) {
		return "the supplied event and matcher input match, but runtime activation is not proven"
	}
	if declaration.Event == "SubagentStop" && value.Value == "" {
		return "the supplied SubagentStop agent type is empty and does not match this specific matcher, as fixed at Claude Code 2.1.275"
	}
	return "the supplied matcher input does not match, so the declaration is inactive for that event"
}

func knownHookEvent(event string) bool {
	switch event {
	case "SessionStart", "Setup", "UserPromptSubmit", "PreToolUse", "PermissionRequest",
		"PostToolUse", "PostToolUseFailure", "Notification", "SubagentStart", "SubagentStop",
		"Stop", "TeammateIdle", "TaskCompleted", "ConfigChange", "CwdChanged", "FileChanged",
		"WorktreeCreate", "WorktreeRemove", "PreCompact", "SessionEnd", "InstructionsLoaded",
		"Elicitation", "ElicitationResult", "PostToolBatch", "TaskCreated", "PermissionDenied",
		"UserPromptExpansion", "PreModelSwitch", "PostModelSwitch":
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
		if root.Content[i].Value != "upstreams" || root.Content[i+1].Kind != yaml.SequenceNode {
			continue
		}
		for _, upstream := range root.Content[i+1].Content {
			if upstream.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(upstream.Content); j += 2 {
				if upstream.Content[j].Value != "headers" || upstream.Content[j+1].Kind != yaml.MappingNode {
					continue
				}
				values := upstream.Content[j+1]
				headers += len(values.Content) / 2
				for k := 1; k < len(values.Content); k += 2 {
					if strings.Contains(values.Content[k].Value, "${") || strings.Contains(values.Content[k].Value, "$ENV{") {
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
	return yamlScalarPairExists(&document, "CLAUDE_GATEWAY_PROXY_IS_EGRESS_BOUNDARY", "1")
}

func yamlScalarPairExists(node *yaml.Node, key, value string) bool {
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key && node.Content[i+1].Value == value {
				return true
			}
			if yamlScalarPairExists(node.Content[i+1], key, value) {
				return true
			}
		}
	}
	for _, child := range node.Content {
		if node.Kind != yaml.MappingNode && yamlScalarPairExists(child, key, value) {
			return true
		}
	}
	return false
}

func safeURLDestination(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "an unresolved redacted destination"
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func sanitizeURLsForDisplay(value string) string {
	return reHTTPURL.ReplaceAllStringFunc(value, safeURLDestination)
}

// SanitizeConfigurationForVerifier removes hook/gateway header values and URL
// credentials before a FileContext can cross the verifier boundary.
func SanitizeConfigurationForVerifier(content []byte, ctx model.FileContext) []byte {
	if !IsClaudeSettings(ctx.Path) {
		headers, _ := gatewayUpstreamHeaders(content, ctx.Path)
		if headers == 0 && !gatewayBoundaryDeclared(content, ctx.Path) {
			return content
		}
	}
	ext := strings.ToLower(filepath.Ext(ctx.Path))
	if ext == ".json" {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.UseNumber()
		if decoder.Decode(&value) == nil {
			if _, err := decoder.Token(); err == io.EOF {
				sanitizeStructuredConfig(value)
				if sanitized, err := json.Marshal(value); err == nil {
					return sanitized
				}
			}
		}
	}
	if ext == ".yaml" || ext == ".yml" {
		var document yaml.Node
		if yaml.Unmarshal(content, &document) == nil {
			sanitizeYAMLConfig(&document, false)
			if sanitized, err := yaml.Marshal(&document); err == nil {
				return sanitized
			}
		}
	}
	return []byte(sanitizeURLsForDisplay(string(content)))
}

func sanitizeStructuredConfig(value any) {
	switch value := value.(type) {
	case []any:
		for _, child := range value {
			sanitizeStructuredConfig(child)
		}
	case map[string]any:
		if handlerType, ok := value["type"].(string); ok && handlerType == "http" {
			allowed := map[string]bool{
				"type": true, "url": true, "headers": true, "allowedEnvVars": true,
				"if": true, "timeout": true,
			}
			for key := range value {
				if !allowed[key] {
					delete(value, key)
				}
			}
		}
		for key, child := range value {
			if strings.EqualFold(key, "headers") {
				if headers, ok := child.(map[string]any); ok {
					for name := range headers {
						headers[name] = "[redacted]"
					}
				}
				continue
			}
			if text, ok := child.(string); ok && (strings.EqualFold(key, "url") || strings.EqualFold(key, "base_url")) {
				value[key] = sanitizeURLValue(text)
				continue
			}
			sanitizeStructuredConfig(child)
		}
	}
}

func sanitizeYAMLConfig(node *yaml.Node, redact bool) {
	if redact && node.Kind == yaml.ScalarNode {
		node.Value = "[redacted]"
		return
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i].Value, node.Content[i+1]
			if redact {
				sanitizeYAMLConfig(value, true)
				continue
			}
			if strings.EqualFold(key, "headers") {
				sanitizeYAMLConfig(value, true)
				continue
			}
			if value.Kind == yaml.ScalarNode && (strings.EqualFold(key, "url") || strings.EqualFold(key, "base_url")) {
				value.Value = sanitizeURLValue(value.Value)
				continue
			}
			sanitizeYAMLConfig(value, false)
		}
		return
	}
	for _, child := range node.Content {
		sanitizeYAMLConfig(child, redact)
	}
}

func sanitizeURLValue(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "[redacted-url]"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}
