package rules

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

var (
	gitConfigKey     = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]*$`)
	gitConfigSection = regexp.MustCompile(`^\[([a-zA-Z][a-zA-Z0-9-]*)(?: "([^"\\]*)")?\]$`)
)

type gitConfigValue struct {
	value string
	line  int
}

// parseNestedBareGitConfig reads only the local config. Includes and syntax we
// cannot interpret are errors, not proof that no executable setting exists.
func parseNestedBareGitConfig(content []byte) (map[string]gitConfigValue, error) {
	values := make(map[string]gitConfigValue)
	section := ""
	for i, raw := range bytes.Split(content, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			match := gitConfigSection.FindStringSubmatch(line)
			if match == nil {
				return nil, fmt.Errorf("unsupported Git config section on line %d", i+1)
			}
			section = strings.ToLower(line[1 : len(line)-1])
			if strings.EqualFold(match[1], "include") || strings.EqualFold(match[1], "includeIf") {
				return nil, fmt.Errorf("git config includes are not assessed (line %d)", i+1)
			}
			continue
		}
		key, value, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if section == "" || !gitConfigKey.MatchString(key) {
			return nil, fmt.Errorf("unsupported Git config syntax on line %d", i+1)
		}
		if !found {
			value = "true" // Git treats a bare key as a boolean true.
		}
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, `"`) {
			decoded, err := strconv.Unquote(value)
			if err != nil {
				return nil, fmt.Errorf("unsupported Git config value on line %d", i+1)
			}
			value = decoded
		} else if strings.ContainsAny(value, `\#;`) {
			return nil, fmt.Errorf("unsupported Git config value on line %d", i+1)
		}
		values[section+"."+strings.ToLower(key)] = gitConfigValue{value: value, line: i + 1}
	}
	return values, nil
}

func gitBool(s string) (bool, bool) {
	switch strings.ToLower(s) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0", "":
		return false, true
	}
	return false, false
}

// NestedBareGitDiagnostics validates before grading, even if the finding rule
// was disabled. No config value is included in an error or published warning.
func NestedBareGitDiagnostics(content []byte, ctx model.FileContext) ([]string, error) {
	if !ctx.NestedBareGitConfig {
		return nil, nil
	}
	values, err := parseNestedBareGitConfig(content)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ctx.Path, err)
	}
	bare, ok := values["core.bare"]
	if !ok {
		return nil, fmt.Errorf("%s: core.bare not declared; nested bare Git config not assessed", ctx.Path)
	}
	if _, valid := gitBool(bare.value); !valid {
		return nil, fmt.Errorf("%s: invalid core.bare declaration", ctx.Path)
	}
	return []string{ctx.Path + ": nested Git config is repository-contained inventory only; Git auto-discovery, command execution and affected agent/version are unverified. Copilot CLI <=1.0.42 is affected by GHSA-9ccr-r5hg-74gf; 1.0.43 is patched. Includes are unsupported; host/global config was not read."}, nil
}

type nestedBareGitRule struct{ baseRule }

func (r *nestedBareGitRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !ctx.NestedBareGitConfig {
		return nil
	}
	values, err := parseNestedBareGitConfig(content)
	if err != nil { // The scanner's diagnostics reports the error before Match.
		return nil
	}
	bare, valid := gitBool(values["core.bare"].value)
	if !valid || !bare {
		return nil
	}
	var findings []model.Finding
	for _, key := range []string{"core.fsmonitor", "diff.external"} {
		setting, exists := values[key]
		if !exists || setting.value == "" {
			continue
		}
		if key == "core.fsmonitor" {
			if _, boolean := gitBool(setting.value); boolean {
				continue
			}
		}
		findings = append(findings, r.newFinding(ctx, setting.line,
			"Nested bare Git config declares command-valued "+key+"; execution and CVE-2026-45033 exposure are not confirmed without runtime Git auto-discovery and an affected agent version",
			"Remove the executable setting; upgrade affected Copilot CLI to 1.0.43 or later and prevent automatic bare-repository discovery"))
	}
	return findings
}

func RegisterNestedBareGitRules(registry *RuleRegistry) {
	registry.Register(&nestedBareGitRule{baseRule: baseRule{
		id: "SD-027", name: "Nested Bare Git Execution Config", severity: model.SeverityHigh,
		category: "Integrity", types: []string{""}, axis: axes.Security,
	}})
}
