package rules

import (
	"bytes"
	"regexp"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// SD-009: Curl-pipe-bash patterns.
var (
	reCurlPipeBash = regexp.MustCompile(`\b(curl|wget)\s+[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b`)
	reWgetExec     = regexp.MustCompile(`\bwget\s+.*-O\s*-\s*.*\|\s*(sudo\s+)?(ba|z)?sh\b`)
)

// SD-010: Runtime download-and-execute patterns.
var (
	reCurlDownload = regexp.MustCompile(`\b(curl|wget)\s+.*-[oO]\s*\S+.*\.(sh|bash|py|rb|pl)\b`)
	reDownloadExec = regexp.MustCompile(`\b(curl|wget)\s+[^;|&]*&&\s*(sudo\s+)?(ba|z)?sh\b`)
	reRemoteExec   = regexp.MustCompile(`\b(python|python3|ruby|perl|node)\s+<\(curl\b`)
)

// SD-011: Vulnerable dependency patterns.
var (
	rePipURL    = regexp.MustCompile(`\bpip3?\s+install\s+.*https?://`)
	reNpmURL    = regexp.MustCompile(`\bnpm\s+install\s+.*(https?://|git[+:]//|github:)`)
	reGoInstall = regexp.MustCompile(`\bgo\s+install\s+.*https?://`)
	reRawGitHub = regexp.MustCompile(`raw\.githubusercontent\.com/[^\s"']+\.(sh|py|rb|js|pl)\b`)
)

type curlBashRule struct {
	baseRule
}

func (r *curlBashRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsAgentFile(ctx.Path) && !isInClaudeOrCodexDir(ctx.Path) {
		return nil
	}
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1
		if reCurlPipeBash.Match(line) || reWgetExec.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"pipe-to-shell execution detected — remote code execution risk",
				"Never pipe downloaded content directly to a shell; download, verify, then execute"))
		}
	}
	return findings
}

type runtimeDownloadRule struct {
	baseRule
}

func (r *runtimeDownloadRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsAgentFile(ctx.Path) && !isInClaudeOrCodexDir(ctx.Path) {
		return nil
	}
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1
		if reCurlDownload.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"download of executable script at runtime",
				"Avoid downloading scripts at runtime; bundle dependencies or use verified package managers"))
			continue
		}
		if reDownloadExec.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"download-and-execute pattern detected",
				"Avoid downloading and immediately executing scripts; verify integrity first"))
			continue
		}
		if reRemoteExec.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"remote script execution via process substitution",
				"Avoid executing remote scripts via process substitution; download and verify first"))
		}
	}
	return findings
}

type vulnerableDepsRule struct {
	baseRule
}

func (r *vulnerableDepsRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsAgentFile(ctx.Path) && !isInClaudeOrCodexDir(ctx.Path) {
		return nil
	}
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1
		if rePipURL.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"pip install from URL — untrusted package source",
				"Install packages from PyPI using package names; avoid installing from URLs"))
			continue
		}
		if reNpmURL.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"npm install from URL or git — untrusted package source",
				"Install packages from npm registry using package names; avoid installing from URLs"))
			continue
		}
		if reGoInstall.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"go install from URL — untrusted package source",
				"Install Go packages using module paths; avoid installing from raw URLs"))
			continue
		}
		if reRawGitHub.Match(line) {
			findings = append(findings, r.newFinding(ctx, lineNum,
				"reference to raw GitHub script — unverified code execution risk",
				"Avoid fetching scripts from raw GitHub URLs; use versioned releases or package managers"))
		}
	}
	return findings
}

// RegisterSupplyChainRules registers all supply chain detection rules.
func RegisterSupplyChainRules(registry *RuleRegistry) {
	registry.Register(&curlBashRule{
		baseRule: baseRule{
			id:       "SD-009",
			name:     "Curl Pipe Bash",
			severity: model.SeverityCritical,
			category: "Supply Chain",
			types:    ContentScanTypes,
			axis:     axes.Security,
		},
	})
	registry.Register(&runtimeDownloadRule{
		baseRule: baseRule{
			id:       "SD-010",
			name:     "Runtime Download",
			severity: model.SeverityHigh,
			category: "Supply Chain",
			types:    ContentScanTypes,
			axis:     axes.Security,
		},
	})
	registry.Register(&vulnerableDepsRule{
		baseRule: baseRule{
			id:       "SD-011",
			name:     "Vulnerable Dependencies",
			severity: model.SeverityHigh,
			category: "Supply Chain",
			types:    ContentScanTypes,
			axis:     axes.Security,
		},
	})
}
