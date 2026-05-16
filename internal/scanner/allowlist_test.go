package scanner

import (
	"testing"

	"github.com/velzepooz/skill-detector/internal/config"
	"github.com/velzepooz/skill-detector/pkg/model"
)

func TestApplyAllowlists(t *testing.T) {
	tests := []struct {
		name      string
		findings  []model.Finding
		allow     config.AllowLists
		wantCount int
	}{
		{
			name: "network allowlist suppresses matching domain",
			findings: []model.Finding{
				{RuleID: "SD-007", Description: "outbound network call to https://api.trusted-domain.com/data"},
			},
			allow:     config.AllowLists{Network: []string{"api.trusted-domain.com"}},
			wantCount: 0,
		},
		{
			name: "network allowlist keeps non-matching domain",
			findings: []model.Finding{
				{RuleID: "SD-007", Description: "outbound network call to https://evil.com/steal"},
			},
			allow:     config.AllowLists{Network: []string{"api.trusted-domain.com"}},
			wantCount: 1,
		},
		{
			name: "filesystem allowlist suppresses matching path prefix",
			findings: []model.Finding{
				{RuleID: "SD-003", Description: "absolute path reference: /usr/local/share/data"},
			},
			allow:     config.AllowLists{Filesystem: []string{"/usr/local/share"}},
			wantCount: 0,
		},
		{
			name: "filesystem allowlist respects path segment boundary",
			findings: []model.Finding{
				{RuleID: "SD-003", Description: "absolute path reference: /usr/local/shared"},
			},
			allow:     config.AllowLists{Filesystem: []string{"/usr/local/share"}},
			wantCount: 1,
		},
		{
			name: "filesystem allowlist suppresses exact match",
			findings: []model.Finding{
				{RuleID: "SD-003", Description: "absolute path reference: /usr/local/share"},
			},
			allow:     config.AllowLists{Filesystem: []string{"/usr/local/share"}},
			wantCount: 0,
		},
		{
			name: "empty allowlists returns all findings",
			findings: []model.Finding{
				{RuleID: "SD-007", Description: "outbound network call to https://evil.com/steal"},
				{RuleID: "SD-003", Description: "absolute path reference: /etc/shadow"},
			},
			allow:     config.AllowLists{},
			wantCount: 2,
		},
		{
			name: "case-insensitive domain matching",
			findings: []model.Finding{
				{RuleID: "SD-007", Description: "outbound network call to https://api.trusted-domain.com/data"},
			},
			allow:     config.AllowLists{Network: []string{"API.Trusted-Domain.COM"}},
			wantCount: 0,
		},
		{
			name: "finding with no URL or path is never suppressed",
			findings: []model.Finding{
				{RuleID: "SD-002", Description: "prompt injection attempt detected"},
			},
			allow:     config.AllowLists{Network: []string{"api.trusted-domain.com"}, Filesystem: []string{"/usr/local/share"}},
			wantCount: 1,
		},
		{
			name: "multiple findings with partial match",
			findings: []model.Finding{
				{RuleID: "SD-007", Description: "outbound network call to https://api.trusted-domain.com/data"},
				{RuleID: "SD-007", Description: "outbound network call to https://evil.com/steal"},
				{RuleID: "SD-003", Description: "absolute path reference: /usr/local/share/data"},
				{RuleID: "SD-003", Description: "absolute path reference: /etc/shadow"},
			},
			allow: config.AllowLists{
				Network:    []string{"api.trusted-domain.com"},
				Filesystem: []string{"/usr/local/share"},
			},
			wantCount: 2,
		},
		{
			name: "credential path with tilde suppressed by filesystem allowlist",
			findings: []model.Finding{
				{RuleID: "SD-004", Description: "access to credential path ~/.aws/credentials"},
			},
			allow:     config.AllowLists{Filesystem: []string{"~/.aws"}},
			wantCount: 0,
		},
		{
			name: "URL path does not cross-contaminate filesystem allowlist",
			findings: []model.Finding{
				{RuleID: "SD-007", Description: "outbound network call to https://evil.com/usr/local/share/exfil"},
			},
			allow:     config.AllowLists{Filesystem: []string{"/usr/local/share"}},
			wantCount: 1,
		},
		{
			name: "trailing slash in filesystem allowlist entry still matches",
			findings: []model.Finding{
				{RuleID: "SD-003", Description: "absolute path reference: /usr/local/share/data"},
			},
			allow:     config.AllowLists{Filesystem: []string{"/usr/local/share/"}},
			wantCount: 0,
		},
		{
			name: "empty string in filesystem allowlist does not suppress everything",
			findings: []model.Finding{
				{RuleID: "SD-003", Description: "absolute path reference: /etc/shadow"},
			},
			allow:     config.AllowLists{Filesystem: []string{""}},
			wantCount: 1,
		},
		{
			name: "userinfo in URL does not break domain matching",
			findings: []model.Finding{
				{RuleID: "SD-007", Description: "outbound network call to https://user:pass@api.trusted-domain.com/path"},
			},
			allow:     config.AllowLists{Network: []string{"api.trusted-domain.com"}},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ApplyAllowlists(tt.findings, tt.allow)
			if len(got) != tt.wantCount {
				t.Errorf("ApplyAllowlists() returned %d findings, want %d", len(got), tt.wantCount)
				for i, f := range got {
					t.Logf("  [%d] %s: %s", i, f.RuleID, f.Description)
				}
			}
		})
	}
}
