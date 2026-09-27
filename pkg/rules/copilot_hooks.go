package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/model"
	"gopkg.in/yaml.v3"
)

// CopilotHookPart is one validated, decoded hook value. Only these values,
// never adjacent JSON metadata or rejected items, reach content rules.
type CopilotHookPart struct {
	Content string
	Ext     string // shell command, prose prompt, or declared HTTP endpoint
	Line    int    // physical source item start (decoded newlines have no source line)
	Limited bool   // direct-exec argument semantics were not modeled
}

var copilotHookEvents = map[string]bool{
	"agentStop": true, "errorOccurred": true, "notification": true,
	"permissionRequest": true, "postToolUse": true, "postToolUseFailure": true,
	"preCompact": true, "preToolUse": true, "PreCompact": true, "PermissionRequest": true, "sessionEnd": true,
	"sessionStart": true, "subagentStart": true, "subagentStop": true,
	"userPromptSubmitted": true, "userPromptTransformed": true,
	"SessionStart": true, "SessionEnd": true, "PreToolUse": true,
	"PostToolUse": true, "PostToolUseFailure": true, "Stop": true,
	"SubagentStop": true, "UserPromptSubmit": true, "ErrorOccurred": true,
}

var copilotAgentName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// CopilotHookDeclarations validates the documented v1 hook shape. Repository
// files drop malformed items independently; inline settings reject the whole
// hooks field. A structural failure cannot yield a graded clean result.
func CopilotHookDeclarations(content []byte, ctx model.FileContext) ([]CopilotHookPart, []string, error) {
	if !IsCopilotHookConfig(ctx.Path) {
		return nil, nil, nil
	}
	invalid := func(reason string) ([]CopilotHookPart, []string, error) {
		return nil, nil, fmt.Errorf("%s: Copilot hooks %s; configuration was not assessed", ctx.Path, reason)
	}
	var root map[string]json.RawMessage
	duplicate, duplicateErr := jsonHasDuplicateKey(content)
	if duplicateErr != nil || duplicate || json.Unmarshal(content, &root) != nil || root == nil || !hasUnambiguousAnalyzedJSONMembers(content) {
		return invalid("have malformed or ambiguous JSON")
	}
	inline := strings.HasPrefix(filepath.ToSlash(ctx.Path), ".github/copilot/")
	if !inline {
		var version int
		if json.Unmarshal(root["version"], &version) != nil || version != 1 {
			return invalid("require version 1")
		}
	}
	if flag, ok := root["disableAllHooks"]; ok && !validJSONBool(flag) {
		return invalid("have invalid disableAllHooks")
	}
	var warnings []string
	if inline {
		warnings = append(warnings, ctx.Path+": only inline hooks and disableAllHooks are assessed; other Copilot settings are not checked. Inline hooks are CLI-only; folder trust, effective settings source, installed version, session and managed policy remain unknown activation conditions")
	} else {
		warnings = append(warnings, ctx.Path+": repository hooks are candidates only; folder trust (CLI), installed version, session, disableAllHooks and managed hook policy remain unknown activation conditions")
	}
	if string(root["disableAllHooks"]) == "true" {
		warnings = append(warnings, ctx.Path+": disableAllHooks is declared; runtime effective policy remains unverified")
	}
	if len(root["hooks"]) == 0 {
		if !inline {
			return invalid("require a hooks object")
		}
		return invalid("contain no supported inline hooks")
	}
	var events map[string]json.RawMessage
	if json.Unmarshal(root["hooks"], &events) != nil || events == nil {
		return invalid("require a hooks object")
	}
	var parts []CopilotHookPart
	dropped := false
	accepted := 0
	keys := make([]string, 0, len(events))
	for event := range events {
		keys = append(keys, event)
	}
	slices.Sort(keys)
	for _, event := range keys {
		if !copilotHookEvents[event] {
			return invalid("contain an unsupported hook event")
		}
		raw := events[event]
		eventOffset := bytes.Index(content, []byte(`"`+event+`"`))
		if eventOffset >= 0 {
			if offset := bytes.Index(content[eventOffset:], raw); offset >= 0 {
				eventOffset += offset
			} else {
				eventOffset = -1
			}
		}
		cursor := 0
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil || items == nil {
			return invalid("require event arrays")
		}
		for i, item := range items {
			itemOffset := bytes.Index(raw[cursor:], item)
			if itemOffset >= 0 {
				itemOffset += cursor
				cursor = itemOffset + len(item)
			}
			fields, ok := jsonObject(item)
			if !ok {
				if inline {
					return invalid("contain an invalid inline hook item")
				}
				warnings = append(warnings, fmt.Sprintf("%s: %s item %d is invalid and was dropped; not assessed as an executable hook", ctx.Path, event, i+1))
				dropped = true
				continue
			}
			entry, valid := copilotHookItem(event, fields)
			if !valid {
				if inline {
					return invalid("contain an invalid inline hook item")
				}
				warnings = append(warnings, fmt.Sprintf("%s: %s item %d is invalid and was dropped; not assessed as an executable hook", ctx.Path, event, i+1))
				dropped = true
				continue
			}
			accepted++
			line := 1
			if eventOffset >= 0 && itemOffset >= 0 {
				line += bytes.Count(content[:eventOffset+itemOffset], []byte("\n"))
			}
			for _, part := range entry {
				part.Line = line
				parts = append(parts, part)
				if part.Limited {
					warnings = append(warnings, fmt.Sprintf("%s: %s item %d direct-exec arguments were not interpreted as shell; non-shell executable semantics remain unassessed", ctx.Path, event, i+1))
				}
				if part.Ext == ".json" && strings.HasPrefix(part.Content, "http://") {
					warnings = append(warnings, fmt.Sprintf("%s: %s item %d local HTTP hook requires COPILOT_HOOK_ALLOW_LOCALHOST=1; runtime environment is unknown", ctx.Path, event, i+1))
				}
			}
		}
	}
	if dropped && accepted == 0 {
		return invalid("contain only rejected hook items")
	}
	if inline && accepted == 0 {
		return invalid("contain no supported inline hooks")
	}
	return parts, warnings, nil
}

func copilotHookItem(event string, fields map[string]json.RawMessage) ([]CopilotHookPart, bool) {
	get := func(key string) (string, bool) {
		raw, exists := fields[key]
		if !exists {
			return "", true
		}
		var value string
		return value, json.Unmarshal(raw, &value) == nil && string(raw) != "null"
	}
	typ, ok := get("type")
	if !ok {
		return nil, false
	}
	if _, present := fields["type"]; present && typ == "" {
		return nil, false
	}
	if typ == "" {
		typ = "command"
	}
	if raw, exists := fields["timeoutSec"]; exists && !validJSONNumber(raw) {
		return nil, false
	}
	if raw, exists := fields["timeout"]; exists && !validJSONNumber(raw) {
		return nil, false
	}
	if raw, exists := fields["env"]; exists {
		var env map[string]json.RawMessage
		if json.Unmarshal(raw, &env) != nil || env == nil {
			return nil, false
		}
		for _, value := range env {
			if !validJSONString(value) {
				return nil, false
			}
		}
	}
	if raw, exists := fields["matcher"]; exists && !validJSONString(raw) {
		return nil, false
	}
	switch typ {
	case "command":
		var parts []CopilotHookPart
		for _, key := range []string{"bash", "powershell", "command", "exec", "cwd"} {
			if _, ok := get(key); !ok {
				return nil, false
			}
		}
		bash, _ := get("bash")
		powershell, _ := get("powershell")
		fallback, _ := get("command")
		exec, _ := get("exec")
		if _, exists := fields["exec"]; exists && exec == "" {
			return nil, false
		}
		if exec != "" && (bash != "" || powershell != "" || fallback != "") {
			return nil, false
		}
		var args []string
		if raw, exists := fields["args"]; exists {
			if exec == "" || !validJSONStringArray(raw) || json.Unmarshal(raw, &args) != nil {
				return nil, false
			}
		}
		if exec != "" {
			cmd := exec
			limited := false
			switch filepath.Base(exec) {
			case "cat", "sh", "bash", "powershell", "pwsh":
				cmd += " " + strings.Join(args, " ")
			case "printf", "echo":
				// Arguments are data, not another shell command.
			default:
				limited = len(args) > 0
			}
			parts = append(parts, CopilotHookPart{Content: cmd, Ext: ".sh", Limited: limited})
		} else {
			if bash == "" && powershell == "" && fallback == "" {
				return nil, false
			}
			if bash == "" {
				bash = fallback
			}
			if powershell == "" {
				powershell = fallback
			}
			for _, cmd := range []string{bash, powershell} {
				if cmd != "" && (len(parts) == 0 || parts[0].Content != cmd) {
					parts = append(parts, CopilotHookPart{Content: cmd, Ext: ".sh"})
				}
			}
		}
		return parts, true
	case "prompt":
		prompt, ok := get("prompt")
		return []CopilotHookPart{{Content: prompt, Ext: ".md"}}, ok && prompt != "" && event == "sessionStart"
	case "http":
		rawURL, ok := get("url")
		endpoint, err := url.Parse(rawURL)
		if !ok || err != nil || endpoint.Hostname() == "" ||
			(endpoint.Scheme != "https" && endpoint.Scheme != "http") {
			return nil, false
		}
		if (event == "preToolUse" || event == "PreToolUse" || event == "permissionRequest" || event == "PermissionRequest") && endpoint.Scheme != "https" {
			return nil, false
		}
		if raw, exists := fields["headers"]; exists {
			var headers map[string]json.RawMessage
			if json.Unmarshal(raw, &headers) != nil || headers == nil {
				return nil, false
			}
			for _, value := range headers {
				if !validJSONString(value) {
					return nil, false
				}
			}
		}
		if raw, exists := fields["allowedEnvVars"]; exists {
			if !validJSONStringArray(raw) || endpoint.Scheme != "https" {
				return nil, false
			}
		}
		if endpoint.Scheme == "http" && endpoint.Hostname() != "localhost" && !strings.HasPrefix(endpoint.Hostname(), "127.") && endpoint.Hostname() != "::1" {
			return nil, false
		}
		return []CopilotHookPart{{Content: rawURL, Ext: ".json"}}, true
	default:
		return nil, false
	}
}

func validJSONNumber(raw json.RawMessage) bool {
	var value float64
	return json.Unmarshal(raw, &value) == nil && string(raw) != "null"
}

// CopilotProseBody separates activation metadata from instructions. Invalid
// frontmatter fails closed, rather than grading a path-specific file as safe.
func CopilotProseBody(content []byte, path string) ([]byte, []string, error) {
	clean := filepath.ToSlash(path)
	instructions := strings.HasPrefix(clean, ".github/instructions/") && strings.HasSuffix(clean, ".instructions.md")
	agent := strings.HasPrefix(clean, ".github/agents/") && strings.HasSuffix(clean, ".agent.md") &&
		!strings.Contains(strings.TrimPrefix(clean, ".github/agents/"), "/")
	if !instructions && !agent {
		return content, nil, nil
	}
	invalid := func() ([]byte, []string, error) {
		return nil, nil, fmt.Errorf("%s: Copilot frontmatter malformed or unsupported; instructions were not assessed", path)
	}
	if agent && !copilotAgentName.MatchString(strings.TrimSuffix(filepath.Base(clean), ".agent.md")) {
		return invalid()
	}
	lines := strings.SplitAfter(string(content), "\n")
	if len(lines) < 3 || strings.TrimRight(lines[0], "\r\n") != "---" {
		return invalid()
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimRight(lines[i], "\r\n") == "---" {
			end = i
			break
		}
	}
	if end < 0 {
		return invalid()
	}
	front := strings.Join(lines[1:end], "")
	if len(front) > maxFrontmatterBytes {
		return invalid()
	}
	var document yaml.Node
	if yaml.Unmarshal([]byte(front), &document) != nil {
		return invalid()
	}
	valid, complete := validateFrontmatterNode(&document, 0, new(int))
	if !valid || !complete {
		return invalid()
	}
	var fields map[string]any
	if yaml.Unmarshal([]byte(front), &fields) != nil || fields == nil {
		return invalid()
	}
	if instructions {
		applyTo, ok := fields["applyTo"].(string)
		if !ok || strings.TrimSpace(applyTo) == "" {
			return invalid()
		}
	} else {
		description, ok := fields["description"].(string)
		if !ok || strings.TrimSpace(description) == "" {
			return invalid()
		}
		if opt, exists := fields["include-custom-instructions"]; exists {
			if _, ok := opt.(bool); !ok {
				return invalid()
			}
		}
	}
	var warning string
	if instructions {
		warning = path + ": applyTo is path-specific; matching target file, instruction selection and folder trust remain unknown"
	} else {
		warning = path + ": agent selection and folder trust remain unknown; include-custom-instructions only controls repository instruction inheritance for subagents, not activation of this profile"
	}
	for i := 0; i <= end; i++ {
		lines[i] = strings.Repeat("\n", strings.Count(lines[i], "\n"))
	}
	return []byte(strings.Join(lines, "")), []string{warning}, nil
}
