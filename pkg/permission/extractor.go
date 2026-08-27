package permission

import (
	"regexp"
	"slices"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/model"
)

// Permission type constants.
const (
	TypeFilesystem   = "filesystem"
	TypeNetwork      = "network"
	TypeShellExec    = "shell_execution"
	TypeEnvVarAccess = "env_var_access"
)

var (
	reEnvVar = regexp.MustCompile(`\$\{?([A-Z_][A-Z0-9_]{2,})\}?`)
	reDomain = regexp.MustCompile(`https?://([^/\s"']+)`)
)

var envVarExclusions = map[string]bool{
	"PATH": true, "PWD": true, "SHELL": true, "USER": true,
	"TERM": true, "LANG": true, "EDITOR": true, "PAGER": true,
}

// capability is one permission a rule implies. detail is a fixed annotation;
// mineDomain pulls a domain out of the finding description instead.
type capability struct {
	typ        string
	detail     string
	mineDomain bool
}

// ruleCapabilities maps a rule ID to the capabilities a finding of that rule
// implies. Every registered rule must appear here or in capabilityFreeRules —
// TestCapabilityTableCoversEveryRegisteredRule enforces it, so a new rule
// cannot silently skip the permissions surface.
var ruleCapabilities = map[string][]capability{
	"SD-001": {{typ: TypeShellExec}},
	"SD-003": {{typ: TypeFilesystem}},
	"SD-004": {{typ: TypeFilesystem, detail: "incl. credentials"}},
	"SD-005": {{typ: TypeFilesystem}},
	"SD-006": {{typ: TypeFilesystem, detail: "incl. credentials"}},
	"SD-007": {{typ: TypeNetwork, mineDomain: true}},
	"SD-009": {{typ: TypeShellExec}, {typ: TypeNetwork, mineDomain: true}},
	"SD-010": {{typ: TypeNetwork, mineDomain: true}},
	"SD-012": {{typ: TypeShellExec}},
	"SD-013": {{typ: TypeShellExec}},
	"SD-014": {{typ: TypeFilesystem}},
	"SD-016": {{typ: TypeNetwork, mineDomain: true}},
	"SD-017": {{typ: TypeShellExec}},
	"SD-019": {{typ: TypeShellExec}},
	"SD-020": {{typ: TypeShellExec}},
	"SD-021": {{typ: TypeNetwork, mineDomain: true}},
	"SD-022": {{typ: TypeNetwork}},
	"SD-023": {{typ: TypeShellExec}},
	"SD-024": {{typ: TypeShellExec}},
	"SD-025": {{typ: TypeShellExec}, {typ: TypeNetwork}},
}

// capabilityFreeRules are rules that describe a technique, a documentation gap
// or a deny-side setting rather than a capability the skill exercises.
var capabilityFreeRules = map[string]struct{}{
	"SD-002": {}, // prompt injection — a technique, not a capability
	"SD-008": {}, // base64 obfuscation — a technique, not a capability
	"SD-011": {}, // vulnerable dependency — a property of what is installed
	"SD-015": {}, // SQL injection guidance — no matching capability type
	"SD-018": {}, // redundant deny rule — deny side, grants nothing
}

// Extract infers permissions from scan findings and discovered files.
func Extract(findings []model.Finding, files []model.FileContext) []model.Permission {
	perms := make(map[string]map[string]bool)

	for _, f := range findings {
		for _, c := range ruleCapabilities[f.RuleID] {
			switch {
			case c.mineDomain:
				if d := extractDomain(f.Description); d != "" {
					add(perms, c.typ, d)
				} else {
					ensure(perms, c.typ)
				}
			case c.detail != "":
				add(perms, c.typ, c.detail)
			default:
				ensure(perms, c.typ)
			}
		}
	}

	// Env var detection from file contents.
	for _, v := range extractEnvVars(files) {
		add(perms, TypeEnvVarAccess, v)
	}

	// Base filesystem permission when files are discovered.
	if len(files) > 0 {
		add(perms, TypeFilesystem, "reads local files")
	}

	return buildResult(perms)
}

func ensure(m map[string]map[string]bool, typ string) {
	if m[typ] == nil {
		m[typ] = make(map[string]bool)
	}
}

func add(m map[string]map[string]bool, typ, detail string) {
	if m[typ] == nil {
		m[typ] = make(map[string]bool)
	}
	if detail != "" {
		m[typ][detail] = true
	}
}

func extractDomain(desc string) string {
	match := reDomain.FindStringSubmatch(desc)
	if len(match) >= 2 {
		return match[1]
	}
	return ""
}

func extractEnvVars(files []model.FileContext) []string {
	seen := make(map[string]bool)
	for _, f := range files {
		for _, m := range reEnvVar.FindAllSubmatch(f.Content, -1) {
			name := string(m[1])
			if !envVarExclusions[name] {
				seen[name] = true
			}
		}
	}
	vars := make([]string, 0, len(seen))
	for v := range seen {
		vars = append(vars, v)
	}
	slices.Sort(vars)
	return vars
}

func buildResult(perms map[string]map[string]bool) []model.Permission {
	var result []model.Permission
	for typ, details := range perms {
		var detailList []string
		for d := range details {
			detailList = append(detailList, d)
		}
		slices.Sort(detailList)

		// "reads local files" should be first in filesystem details.
		if typ == TypeFilesystem {
			for i, d := range detailList {
				if d == "reads local files" && i > 0 {
					detailList = slices.Delete(detailList, i, i+1)
					detailList = slices.Insert(detailList, 0, "reads local files")
					break
				}
			}
		}

		if len(detailList) == 0 {
			detailList = nil
		}

		result = append(result, model.Permission{Type: typ, Details: detailList})
	}

	slices.SortFunc(result, func(a, b model.Permission) int {
		return strings.Compare(a.Type, b.Type)
	})

	return result
}
