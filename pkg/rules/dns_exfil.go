package rules

import (
	"bytes"
	"regexp"

	"github.com/velzepooz/skill-detector/pkg/model"
)

// SD-022: DNS exfiltration / tunneling.
//
// Fires on a DNS-resolution command whose queried hostname is built from
// dynamic or encoded data — command substitution ($(...)), backticks, or a
// shell variable ($VAR / ${VAR}) — combined with a dotted (domain-shaped)
// name on the same line. This is the classic covert channel: pack secrets
// into a subdomain label and resolve <data>.attacker.tld via dig/nslookup.
//
// Static lookups (e.g. `dig example.com`, `nslookup "$HOSTNAME"` with no
// literal domain) do NOT fire — the dynamic-hostname + dotted-name pair is
// what distinguishes tunneling from a benign connectivity check.
var (
	reDNSCmd         = regexp.MustCompile(`\b(dig|nslookup|drill|resolvectl|host)\s`)
	reDNSDynamicHost = regexp.MustCompile(`\$\(|` + "`" + `|\$\{?\w`)
	reDNSDottedName  = regexp.MustCompile(`\.[A-Za-z]{2,}`)
)

type dnsExfilRule struct {
	baseRule
}

func (r *dnsExfilRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !InScope(ctx) {
		return nil
	}
	var findings []model.Finding
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		if reDNSCmd.Match(line) && reDNSDynamicHost.Match(line) && reDNSDottedName.Match(line) {
			findings = append(findings, r.newFinding(ctx, i+1,
				"DNS lookup with dynamically-constructed hostname — potential DNS-tunneling exfiltration",
				"Avoid building DNS queries from runtime data or encoded values; DNS lookups with interpolated hostnames are a common covert exfiltration channel. Use static hostnames and document why external resolution is needed."))
		}
	}
	return findings
}
