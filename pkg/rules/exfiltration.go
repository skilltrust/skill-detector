package rules

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// SD-007: Outbound network call patterns.
var (
	reNetworkCommand = regexp.MustCompile(`\b(curl|wget|fetch|nc|ncat)\s+`)
	reHTTPURL        = regexp.MustCompile(`https?://[^\s"')\]>]+`)
	reRequestsLib    = regexp.MustCompile(`\b(requests\.(get|post|put|delete|patch)|urllib\.request|fetch\()`)
	reGitFetch       = regexp.MustCompile(`\bgit\s+fetch\b`)
)

// SD-008: Base64 obfuscation patterns.
var (
	reBase64Command = regexp.MustCompile(`\bbase64\s+(-d|--decode)`)
	reBase64Inline  = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	reBase64Decode  = regexp.MustCompile(`\b(atob|b64decode|Base64\.decode|base64\.b64decode)\s*\(`)
	reHashLine      = regexp.MustCompile(`(?i)(sha(256|512|1)?|md5|checksum|hash)\s*[:=]`)
)

type networkCallRule struct {
	baseRule
}

func (r *networkCallRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsAgentFile(ctx.Path) && !isInClaudeOrCodexDir(ctx.Path) {
		return nil
	}
	docFile := isDocFile(ctx.Path)
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1
		urlMatch := reHTTPURL.Find(line)
		if reNetworkCommand.Match(line) && !reGitFetch.Match(line) {
			desc := "outbound network call detected"
			if urlMatch != nil {
				desc = "outbound network call to " + string(urlMatch)
			}
			findings = append(findings, r.newFinding(ctx, lineNum,
				desc,
				"Remove or restrict outbound network calls; document why external access is needed"))
			continue
		}
		if reRequestsLib.Match(line) {
			desc := "outbound network call via library"
			if urlMatch != nil {
				desc = "outbound network call via library to " + string(urlMatch)
			}
			findings = append(findings, r.newFinding(ctx, lineNum,
				desc,
				"Remove or restrict outbound network calls; document why external access is needed"))
			continue
		}
		if urlMatch != nil && !docFile {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"outbound network reference to "+string(urlMatch),
				"Remove or restrict outbound network references; document why external access is needed"))
		}
	}
	return findings
}

type base64ObfuscationRule struct {
	baseRule
}

func (r *base64ObfuscationRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsAgentFile(ctx.Path) && !isInClaudeOrCodexDir(ctx.Path) {
		return nil
	}
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1
		if reBase64Command.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"base64 decode command detected — potential obfuscation",
				"Avoid using base64 to decode data at runtime; use plaintext configuration instead"))
			continue
		}
		if reBase64Decode.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"base64 decode function call detected — potential obfuscation",
				"Avoid using base64 to decode data at runtime; use plaintext configuration instead"))
			continue
		}
		// Inline base64 string — skip if the match is inside a URL or the line is a hash.
		if b64Loc := reBase64Inline.FindIndex(line); b64Loc != nil && !reHashLine.Match(line) {
			inURL := false
			for _, urlLoc := range reHTTPURL.FindAllIndex(line, -1) {
				if b64Loc[0] >= urlLoc[0] && b64Loc[1] <= urlLoc[1] {
					inURL = true
					break
				}
			}
			if !inURL {
				findings = append(findings, r.newFinding(ctx, lineNum,
					"long base64-encoded string detected — potential obfuscation",
					"Avoid embedding base64-encoded data; use plaintext or reference external config"))
			}
		}
	}
	return findings
}

// isDocFile reports whether the path looks like a documentation file
// where a bare URL reference is expected noise, not an executable call.
func isDocFile(path string) bool {
	p := strings.ToLower(path)
	return strings.HasSuffix(p, ".md") ||
		strings.HasSuffix(p, ".txt") ||
		strings.HasSuffix(p, ".rst")
}

// RegisterExfiltrationRules registers all exfiltration detection rules.
func RegisterExfiltrationRules(registry *RuleRegistry) {
	registry.Register(&networkCallRule{
		baseRule: baseRule{
			id:       "SD-007",
			name:     "Outbound Network Call",
			severity: model.SeverityHigh,
			category: "SSRF / Data Exfiltration",
			types:    []string{".sh", ".bash", ".md", ".yaml", ".yml", ".txt", ".json", ".toml", ".env", ".cfg", ".conf", ".ini", ".xml"},
			axis:     axes.Security,
		},
	})
	registry.Register(&base64ObfuscationRule{
		baseRule: baseRule{
			id:       "SD-008",
			name:     "Base64 Obfuscation",
			severity: model.SeverityMedium,
			category: "SSRF / Data Exfiltration",
			types:    []string{".sh", ".bash", ".md", ".yaml", ".yml", ".txt", ".json", ".toml", ".env", ".cfg", ".conf", ".ini", ".xml"},
			axis:     axes.Security,
		},
	})
	registry.Register(&dnsExfilRule{
		baseRule: baseRule{
			id:       "SD-022",
			name:     "DNS Exfiltration",
			severity: model.SeverityHigh,
			category: "SSRF / Data Exfiltration",
			types:    []string{".sh", ".bash", ".md", ".yaml", ".yml", ".txt", ".json", ".toml", ".env", ".cfg", ".conf", ".ini", ".xml"},
			axis:     axes.Security,
		},
	})
}
