package rules

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// mcpFile is a minimal decoder for .mcp.json.
type mcpFile struct {
	MCPServers map[string]struct {
		URL      string `json:"url"`
		Endpoint string `json:"endpoint"`
		Command  string `json:"command"`
	} `json:"mcpServers"`
}

type mcpExternalDomainRule struct {
	baseRule
}

func (r *mcpExternalDomainRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsMCPConfig(ctx.Path) && !IsClaudeSettings(ctx.Path) {
		return nil
	}
	// Try .mcp.json shape first.
	var f mcpFile
	if err := json.Unmarshal(content, &f); err != nil || len(f.MCPServers) == 0 {
		// Fall back to claudeSettings.MCPServers from settings_json.go.
		s, err2 := parseClaudeSettings(content)
		if err2 != nil {
			return nil
		}
		f.MCPServers = make(map[string]struct {
			URL      string `json:"url"`
			Endpoint string `json:"endpoint"`
			Command  string `json:"command"`
		})
		for name, srv := range s.MCPServers {
			f.MCPServers[name] = struct {
				URL      string `json:"url"`
				Endpoint string `json:"endpoint"`
				Command  string `json:"command"`
			}{URL: srv.URL, Command: srv.Command}
		}
	}
	var findings []model.Finding
	for name, srv := range f.MCPServers {
		raw := srv.URL
		if raw == "" {
			raw = srv.Endpoint
		}
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := u.Hostname()
		if host == "" {
			continue
		}
		if !isLocalHost(host) {
			findings = append(findings, r.newFinding(ctx, 1,
				"MCP server "+name+" reaches external host: "+host,
				"Configure an MCP allowlist; restrict servers to localhost or a known allowlisted set"))
		}
	}
	return findings
}

func isLocalHost(h string) bool {
	switch strings.ToLower(h) {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	}
	return strings.HasSuffix(h, ".local")
}

// RegisterMCPRules registers the default-severity MCP rules.
func RegisterMCPRules(registry *RuleRegistry) {
	registry.Register(&mcpExternalDomainRule{
		baseRule: baseRule{
			id:       "SD-021",
			name:     "MCP External Domain Reach",
			severity: model.SeverityMedium,
			category: "MCP",
			types:    []string{".json"},
			axis:     axes.PermissionHygiene,
		},
	})
}

// RegisterMCPRulesStrict registers the MCP rules with High severity instead of
// Medium. Used by the --strict-mcp CLI flag.
func RegisterMCPRulesStrict(registry *RuleRegistry) {
	registry.Register(&mcpExternalDomainRule{
		baseRule: baseRule{
			id:       "SD-021",
			name:     "MCP External Domain Reach",
			severity: model.SeverityHigh,
			category: "MCP",
			types:    []string{".json"},
			axis:     axes.PermissionHygiene,
		},
	})
}
