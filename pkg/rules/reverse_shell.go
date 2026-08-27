package rules

import (
	"bytes"
	"regexp"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// SD-025: Reverse shell patterns.
//
// The connecting idea is a socket and a shell in the same statement — a
// socket alone is SD-007's job, and a shell alone is ordinary. Three
// predicates, measured against MalSkillBench (measure_sd025_source.py):
// malware 249/3944=6.31%, benign 4/4000=0.10%, lift 63.1 — the 4 benign hits
// are security/sysadmin docs quoting revshell payloads verbatim.
var (
	// reRevShellSelf matches a single line that is already socket+shell on its
	// own: `nc -e /bin/sh`, `bash -i >& /dev/tcp/...`, any shell stdio bound to
	// `/dev/(tcp|udp)/`, and the mkfifo/openssl-s_client relay idiom.
	reRevShellSelf = regexp.MustCompile(
		`\b(nc|ncat|netcat)\b[^\n]*\s-[A-Za-z]*[ec]\s+\S` +
			`|(ba|z)?sh\s+-[A-Za-z]*i\b[^\n]*(>&|0>&1|1>&0|<>|<&)\s*/dev/(tcp|udp)/` +
			`|(>&|0>&1|1>&0|<>|0<&|<&)\s*/dev/(tcp|udp)/\S+` +
			`|/dev/(tcp|udp)/\S+\s+0>&1` +
			`|(mkfifo|openssl\s+s_client)\b[^\n]*(/bin/(ba|z)?sh|(ba|z)?sh\s+-[A-Za-z]*i)` +
			`|/bin/(ba|z)?sh\b[^\n]*(mkfifo|openssl\s+s_client|/dev/(tcp|udp)/)`)

	// reRevShellSocket matches low-level socket establishment — rare in
	// benign code, common in interpreter reverse-shell one-liners.
	reRevShellSocket = regexp.MustCompile(
		`socket\.socket\s*\(` +
			`|socket\s*\([^\n]*(PF_INET|AF_INET|SOCK_STREAM)` +
			`|\bTCPSocket\b|\bfsockopen\b|Net\.Sockets\.TCPClient` +
			`|\bnet\.(connect|createConnection)\s*\(|new\s+net\.Socket\b` +
			`|\bIO::Socket::INET\b`)

	// reRevShellExec matches a shell being executed or bound — not a mere
	// shebang or a `-c` wrapper.
	reRevShellExec = regexp.MustCompile(
		`\bos\.dup2\b|\bpty\.spawn\b` +
			`|\b(exec|system|popen|Popen|spawn|call|run|proc_open|shell_exec|ProcessBuilder)\s*\(?\s*[\[\('"]*\s*/?(bin/)?(ba|z)?sh\b` +
			`|['"]/bin/(ba|z)?sh['"]` +
			`|\b(ba|z)?sh\s+-[A-Za-z]*i\b` +
			`|\bInvoke-Expression\b|\bIEX\b` +
			`|(exec|system|popen|spawn|proc_open)\s*\(?[^\n]{0,20}(cmd\.exe|powershell)` +
			`|shell\s*=\s*True` +
			`|\bos\.system\s*\(` +
			`|(Popen|spawn)\s*\([^\n]*std(in|out|err)`)
)

type reverseShellRule struct {
	baseRule
}

// Match finds a reverse shell: either a single line that is already
// socket+shell on its own, or a socket established somewhere in the file
// paired with a shell exec/bind somewhere in the file — the multi-line
// interpreter payload shape (MalSkillBench behaviour B6).
func (r *reverseShellRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsAgentFile(ctx.Path) && !isInAgentConfigDir(ctx.Path) {
		return nil
	}
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		if reRevShellSelf.Match(line) {
			return []model.Finding{r.newFinding(ctx, i+1,
				"reverse shell: socket bound to a shell",
				"Remove the reverse-shell payload; a skill must not open a socket and attach a shell to it")}
		}
	}
	if reRevShellSocket.Match(content) && reRevShellExec.Match(content) {
		for i, line := range lines {
			if reRevShellSocket.Match(line) {
				return []model.Finding{r.newFinding(ctx, i+1,
					"reverse shell: socket bound to a shell",
					"Remove the reverse-shell payload; a skill must not open a socket and attach a shell to it")}
			}
		}
	}
	return nil
}

// RegisterReverseShellRules registers the reverse-shell detection rule.
func RegisterReverseShellRules(registry *RuleRegistry) {
	registry.Register(&reverseShellRule{
		baseRule: baseRule{
			id:       "SD-025",
			name:     "Reverse Shell",
			severity: model.SeverityCritical,
			category: "Reverse Shell",
			types:    ContentScanTypes,
			axis:     axes.Security,
		},
	})
}
