package rules

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// mcpServer is one server entry in .mcp.json or settings.json mcpServers.
type mcpServer struct {
	URL      string   `json:"url"`
	Endpoint string   `json:"endpoint"`
	Command  string   `json:"command"`
	Args     []string `json:"args"`
}

// mcpFile is a minimal decoder for .mcp.json. Servers holds the "servers"
// key, which VS Code's .vscode/mcp.json uses instead of "mcpServers".
type mcpFile struct {
	MCPServers map[string]mcpServer `json:"mcpServers"`
	Servers    map[string]mcpServer `json:"servers"`
}

// decodeMCPServers decodes mcpServers from either .mcp.json (mcpServers or,
// for VS Code's .vscode/mcp.json, servers) or the .claude/settings.json
// shape. Returns nil if none decode.
func decodeMCPServers(content []byte) map[string]mcpServer {
	var f mcpFile
	if err := json.Unmarshal(content, &f); err == nil {
		if len(f.MCPServers) > 0 {
			return f.MCPServers
		}
		if len(f.Servers) > 0 {
			return f.Servers
		}
	}
	// Fall back to claudeSettings.MCPServers from settings_json.go — that
	// shape doesn't decode cleanly into mcpFile because its struct type
	// differs, so it needs an explicit conversion.
	s, err := parseClaudeSettings(content)
	if err != nil || len(s.MCPServers) == 0 {
		return nil
	}
	servers := make(map[string]mcpServer, len(s.MCPServers))
	for name, srv := range s.MCPServers {
		servers[name] = mcpServer{URL: srv.URL, Command: srv.Command, Args: srv.Args}
	}
	return servers
}

// packageRunners auto-fetch and execute a package from a public registry.
//
// G6 limitation: this matches literal command names only. `${VAR}` /
// `${VAR:-default}` shell-style expansion in "command" (and "args", "env",
// "url") is not resolved here, so `{"command":"${EVIL_CMD}"}` defeats this
// check.
var packageRunners = map[string]bool{
	"npx": true, "uvx": true, "pipx": true, "bunx": true,
}

type mcpExternalDomainRule struct {
	baseRule
}

func (r *mcpExternalDomainRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsMCPConfig(ctx.Path) && !IsClaudeSettings(ctx.Path) {
		return nil
	}
	servers := decodeMCPServers(content)
	var findings []model.Finding
	for name, srv := range servers {
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

type mcpAutoInstallRule struct {
	baseRule
}

func (r *mcpAutoInstallRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsMCPConfig(ctx.Path) && !IsClaudeSettings(ctx.Path) {
		return nil
	}
	servers := decodeMCPServers(content)
	var findings []model.Finding
	for name, srv := range servers {
		head := filepath.Base(strings.TrimSpace(srv.Command))
		if !packageRunners[head] {
			continue
		}
		pkg := firstNonFlagArg(srv.Args)
		if pkg == "" {
			pkg = "(unspecified package)"
		}
		findings = append(findings, r.newFinding(ctx, 1,
			"MCP server "+name+" auto-installs and executes registry package "+pkg+" via "+head,
			"Pin the package to an exact version and audit it, or vendor the server binary instead of fetching at startup"))
	}
	return findings
}

func firstNonFlagArg(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
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
	registry.Register(&mcpAutoInstallRule{
		baseRule: baseRule{
			id:       "SD-024",
			name:     "MCP Auto-Installed Package Execution",
			severity: model.SeverityMedium,
			category: "MCP",
			types:    []string{".json"},
			axis:     axes.Transparency,
		},
	})
}
