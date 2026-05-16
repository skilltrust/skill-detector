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

// Extract infers permissions from scan findings and discovered files.
func Extract(findings []model.Finding, files []model.FileContext) []model.Permission {
	perms := make(map[string]map[string]bool)

	for _, f := range findings {
		switch f.RuleID {
		case "SD-001":
			ensure(perms, TypeShellExec)
		case "SD-003":
			ensure(perms, TypeFilesystem)
		case "SD-004":
			add(perms, TypeFilesystem, "incl. credentials")
		case "SD-007":
			if d := extractDomain(f.Description); d != "" {
				add(perms, TypeNetwork, d)
			} else {
				ensure(perms, TypeNetwork)
			}
		case "SD-009":
			ensure(perms, TypeShellExec)
			if d := extractDomain(f.Description); d != "" {
				add(perms, TypeNetwork, d)
			} else {
				ensure(perms, TypeNetwork)
			}
		case "SD-010":
			if d := extractDomain(f.Description); d != "" {
				add(perms, TypeNetwork, d)
			} else {
				ensure(perms, TypeNetwork)
			}
		case "SD-012", "SD-013":
			ensure(perms, TypeShellExec)
		case "SD-014":
			ensure(perms, TypeFilesystem)
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
