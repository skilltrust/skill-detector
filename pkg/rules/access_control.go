package rules

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// Path traversal detection patterns.
var (
	rePathTraversal = regexp.MustCompile(`\.\.\/`)
	reAbsolutePath  = regexp.MustCompile(`(?:^|[\s"'=:])(/etc/|/home/|/root/|/var/|/tmp/|/usr/|/opt/)`)
	reWindowsPath   = regexp.MustCompile(`(?i)(?:^|[\s"'=:])[A-Z]:\\`)
	reURLScheme     = regexp.MustCompile(`://`)
	reFullPath      = regexp.MustCompile(`(/(?:etc|home|root|var|tmp|usr|opt)/[^\s"')\]>,;|&#${}` + "`" + `]*)`)
)

// reNegatedGuidance matches prohibition phrasing. When it precedes a
// sensitive-path mention on the same line, the line is security guidance,
// not an access attempt. Bypassable by construction — the layered
// mitigation is rule co-occurrence plus LLM triage; this trades a
// contrived false-negative class for a guaranteed false-positive class.
var reNegatedGuidance = regexp.MustCompile(`(?i)\b(never|do\s+not|don'?t|avoid|must\s+not|not\s+allowed|forbidden|refuse\s+to)\b`)

// reDocumentaryContext matches lines that are documentation *about* sensitive
// paths rather than instructions to touch them: Markdown table rows and
// interrogative bullets from threat-model docs (dogfood FP-1, FP-2 verbatim).
// Same tradeoff as reNegatedGuidance — bypassable by construction, but it
// removes a guaranteed false-positive class.
var reDocumentaryContext = regexp.MustCompile(`(?i)^\s*(\|.*\|\s*$|[-*]\s+(could|does|would|should|can|is|are|might|may)\b.*\?\s*$)`)

// Credential path patterns as literal byte slices for bytes.Contains matching.
var credentialPaths = [][]byte{
	[]byte("~/.aws/"),
	[]byte("~/.ssh/"),
	[]byte("~/.gnupg/"),
	[]byte("~/.env"),
	[]byte("/etc/shadow"),
	[]byte("/etc/passwd"),
	[]byte(".credentials"),
}

type credentialAccessRule struct {
	baseRule
}

func (r *credentialAccessRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsAgentFile(ctx.Path) && !isInAgentConfigDir(ctx.Path) {
		return nil
	}
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1
		if reDocumentaryContext.Match(line) {
			continue
		}
		for _, pattern := range credentialPaths {
			if bytes.Contains(line, pattern) {
				if loc := reNegatedGuidance.FindIndex(line); loc != nil && loc[0] < bytes.Index(line, pattern) {
					continue
				}
				desc := fmt.Sprintf("access to credential path %s", string(pattern))
				findings = append(findings, r.newFinding(ctx, lineNum,
					desc,
					"Remove credential path access or document why it's needed"))
				break
			}
		}
	}
	return findings
}

type pathTraversalRule struct {
	baseRule
}

func (r *pathTraversalRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsAgentFile(ctx.Path) && !isInAgentConfigDir(ctx.Path) {
		return nil
	}
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1

		hasURL := reURLScheme.Match(line)

		if rePathTraversal.Match(line) && !hasURL {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"path traversal pattern detected — access outside skill directory",
				"Use relative paths within the skill directory; avoid ../ references"))
		}
		if reAbsolutePath.Match(line) {
			desc := "suspicious absolute path reference outside skill directory"
			if match := reFullPath.FindString(string(line)); match != "" {
				desc = fmt.Sprintf("absolute path reference: %s", match)
			}
			findings = append(findings, r.newFinding(ctx, lineNum,
				desc,
				"Avoid absolute paths to system directories; use relative paths within the skill"))
		}
		if reWindowsPath.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"suspicious Windows absolute path reference",
				"Avoid absolute paths to system directories; use relative paths within the skill"))
		}
	}
	return findings
}

// RegisterAccessControlRules registers all access control detection rules.
func RegisterAccessControlRules(registry *RuleRegistry) {
	registry.Register(&pathTraversalRule{
		baseRule: baseRule{
			id:       "SD-003",
			name:     "Path Traversal",
			severity: model.SeverityHigh,
			category: "Broken Access Control",
			types:    ContentScanTypes,
			axis:     axes.PermissionHygiene,
		},
	})

	registry.Register(&credentialAccessRule{
		baseRule: baseRule{
			id:       "SD-004",
			name:     "Credential Access",
			severity: model.SeverityCritical,
			category: "Broken Access Control",
			types:    ContentScanTypes,
			axis:     axes.PermissionHygiene,
		},
	})
}
