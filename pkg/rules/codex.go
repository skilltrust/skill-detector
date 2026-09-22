package rules

import (
	"fmt"
	"math"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// IsCodexConfig identifies repository copies of Codex config and v2 profiles.
// It does not establish CODEX_HOME, project trust, or runtime activation.
func IsCodexConfig(path string) bool {
	return !isExcluded(path) && filepath.Base(filepath.Dir(path)) == ".codex" &&
		(filepath.Base(path) == "config.toml" || strings.HasSuffix(path, ".config.toml"))
}

type codexPermissions struct {
	Approval any     `toml:"approval_policy"`
	Sandbox  *string `toml:"sandbox_mode"`
}

type codexProfile struct {
	codexPermissions
	MCP any `toml:"mcp_servers"` // not supported inside inline profiles
}

type codexConfig struct {
	codexPermissions
	Profile   string                    `toml:"profile"`
	Profiles  map[string]codexProfile   `toml:"profiles"`
	MCP       map[string]map[string]any `toml:"mcp_servers"`
	Providers map[string]struct {
		AWS struct {
			Export  *codexHelper `toml:"credential_export"`
			Refresh *codexHelper `toml:"auth_refresh"`
		} `toml:"aws"`
	} `toml:"model_providers"`
}

type codexHelper struct {
	Command string   `toml:"command"`
	Args    []string `toml:"args"`
	Timeout *uint64  `toml:"timeout_ms"`
}

type codexAnalysis struct {
	config   codexConfig
	servers  map[string]mcpServer
	warnings []string
}

// CodexConfigDiagnostics validates the analyzed subset before the scanner runs
// rules. Errors contain no TOML values (which may contain credentials). Unknown
// runtime state is a warning, never a guessed effective configuration.
func CodexConfigDiagnostics(content []byte, ctx model.FileContext) ([]string, error) {
	if !IsCodexConfig(ctx.Path) {
		return nil, nil
	}
	a, err := analyzeCodex(content)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ctx.Path, err)
	}
	warnings := []string{ctx.Path + ": Codex declaration-only analysis (rust-v0.155.0 subset), not an effective-config or clean-runtime verdict. Untrusted project layers are disabled; repository trust declarations do not establish user trust. User/system/managed settings, requirements, CLI overrides, profile selection and source precedence are unresolved. Other configuration fields are not validated."}
	for _, w := range a.warnings {
		warnings = append(warnings, ctx.Path+": "+w)
	}
	if filepath.Base(ctx.Path) != "config.toml" {
		warnings = append(warnings, ctx.Path+": named profile file is only active when selected from CODEX_HOME; repository placement does not activate it")
	}
	return warnings, nil
}

func analyzeCodex(content []byte) (codexAnalysis, error) {
	a := codexAnalysis{servers: make(map[string]mcpServer)}
	if err := toml.Unmarshal(content, &a.config); err != nil {
		return a, fmt.Errorf("malformed Codex TOML or unsupported analyzed field type; configuration was not assessed")
	}
	if err := validateCodexPermissions(a.config.codexPermissions); err != nil {
		return a, err
	}
	for _, p := range a.config.Profiles {
		if p.MCP != nil {
			return a, fmt.Errorf("unsupported Codex MCP declaration inside inline profile; configuration was not assessed")
		}
		if err := validateCodexPermissions(p.codexPermissions); err != nil {
			return a, err
		}
	}
	if a.config.Profile != "" || len(a.config.Profiles) > 0 {
		a.warnings = append(a.warnings, "profile/profiles are ignored in project-local layers in Codex 0.155.0; inline profile findings describe dormant declarations, not a selected effective profile")
		if a.config.Profile != "" {
			if _, ok := a.config.Profiles[a.config.Profile]; !ok {
				a.warnings = append(a.warnings, "selected profile is not defined inline; external profile source is unresolved")
			}
		}
	}
	for name, raw := range a.config.MCP {
		srv, enabled, err := codexMCPServer(raw)
		if err != nil {
			return a, err
		}
		if !enabled {
			continue
		}
		a.servers[name] = srv
		if _, ok := raw["http_headers_helper"]; ok {
			a.warnings = append(a.warnings, "MCP server "+name+": http_headers_helper declares a shell command returning credential headers; audit command provenance and secret handling. Helper was not executed; activation is unresolved")
		}
		head := filepath.Base(srv.Command)
		if head == "codex-mcp-server" || (head == "codex" && len(srv.Args) > 0 && srv.Args[0] == "mcp-server") {
			a.warnings = append(a.warnings, "MCP server "+name+": removed Codex server launch command; compatibility drift, not a CVE. Verify the installed version; do not automatically replace with app-server")
		}
	}
	for name, provider := range a.config.Providers {
		for kind, helper := range map[string]*codexHelper{"credential_export": provider.AWS.Export, "auth_refresh": provider.AWS.Refresh} {
			if helper == nil {
				continue
			}
			if strings.TrimSpace(helper.Command) == "" || (helper.Timeout != nil && *helper.Timeout == 0) {
				return a, fmt.Errorf("unsupported AWS credential helper command or timeout; configuration was not assessed")
			}
			a.warnings = append(a.warnings, "model provider "+name+" aws."+kind+": credential command declared; audit executable provenance and secret handling. model_providers is ignored in project-local layers in Codex 0.155.0; execution from another source is unresolved. Helper was not executed")
		}
	}
	slices.Sort(a.warnings)
	return a, nil
}

func validateCodexPermissions(p codexPermissions) error {
	if p.Sandbox != nil && !slices.Contains([]string{"read-only", "workspace-write", "danger-full-access"}, *p.Sandbox) {
		return fmt.Errorf("unsupported Codex sandbox_mode; configuration was not assessed")
	}
	switch v := p.Approval.(type) {
	case nil:
	case string:
		if !slices.Contains([]string{"on-request", "on-failure", "never"}, v) {
			return fmt.Errorf("unsupported Codex approval_policy; configuration was not assessed")
		}
	case map[string]any:
		g, ok := v["granular"].(map[string]any)
		if !ok || len(v) != 1 {
			return fmt.Errorf("unsupported Codex granular approval_policy; configuration was not assessed")
		}
		for _, key := range []string{"sandbox_approval", "rules", "mcp_elicitations"} {
			if _, ok := g[key].(bool); !ok {
				return fmt.Errorf("incomplete Codex granular approval_policy; configuration was not assessed")
			}
		}
		for key, value := range g {
			_, ok := value.(bool)
			if !ok || !slices.Contains([]string{"sandbox_approval", "rules", "mcp_elicitations", "skill_approval", "request_permissions"}, key) {
				return fmt.Errorf("unsupported Codex granular approval control; configuration was not assessed")
			}
		}
	default:
		return fmt.Errorf("unsupported Codex approval_policy type; configuration was not assessed")
	}
	return nil
}

// Decode only supported transport fields; reject other MCP controls rather than
// silently treating an unsupported declaration as a known-safe server.
func codexMCPServer(raw map[string]any) (mcpServer, bool, error) {
	var srv mcpServer
	invalid := fmt.Errorf("unsupported Codex MCP declaration (field, type or transport); configuration was not assessed")
	enabled := true
	for key, value := range raw {
		switch key {
		case "command", "url", "cwd", "bearer_token_env_var", "name", "http_headers_helper":
			v, ok := value.(string)
			if !ok || (key == "http_headers_helper" && strings.TrimSpace(v) == "") {
				return srv, false, invalid
			}
			if key == "command" {
				srv.Command = v
			}
			if key == "url" {
				srv.URL = v
			}
		case "args", "enabled_tools", "disabled_tools", "scopes":
			v, ok := value.([]any)
			if !ok {
				return srv, false, invalid
			}
			for _, item := range v {
				s, ok := item.(string)
				if !ok {
					return srv, false, invalid
				}
				if key == "args" {
					srv.Args = append(srv.Args, s)
				}
			}
		case "enabled", "required":
			v, ok := value.(bool)
			if !ok {
				return srv, false, invalid
			}
			if key == "enabled" {
				enabled = v
			}
		case "env", "http_headers", "env_http_headers":
			v, ok := value.(map[string]any)
			if !ok {
				return srv, false, invalid
			}
			for _, item := range v {
				if _, ok := item.(string); !ok {
					return srv, false, invalid
				}
			}
		case "startup_timeout_sec", "tool_timeout_sec", "startup_timeout_ms":
			switch n := value.(type) {
			case int64:
				if n < 0 {
					return srv, false, invalid
				}
			case float64:
				if n < 0 || math.IsNaN(n) || math.IsInf(n, 0) || key == "startup_timeout_ms" {
					return srv, false, invalid
				}
			default:
				return srv, false, invalid
			}
		default:
			return srv, false, invalid
		}
	}
	_, command := raw["command"]
	_, remote := raw["url"]
	if command == remote || (command && strings.TrimSpace(srv.Command) == "") {
		return srv, false, invalid
	}
	for _, key := range []string{"args", "env", "cwd"} {
		if _, ok := raw[key]; remote && ok {
			return srv, false, invalid
		}
	}
	for _, key := range []string{"bearer_token_env_var", "http_headers", "env_http_headers", "http_headers_helper"} {
		if _, ok := raw[key]; command && ok {
			return srv, false, invalid
		}
	}
	if remote {
		u, err := url.Parse(srv.URL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return srv, false, invalid
		}
	}
	return srv, enabled, nil
}

type codexPermissionsRule struct{ baseRule }

func (r *codexPermissionsRule) Match(content []byte, ctx model.FileContext) []model.Finding {
	if !IsCodexConfig(ctx.Path) {
		return nil
	}
	a, err := analyzeCodex(content)
	if err != nil {
		return nil // scanner surfaces diagnostics independently of rule toggles
	}
	var findings []model.Finding
	check := func(p codexPermissions, source string) {
		if p.Sandbox == nil || *p.Sandbox != "danger-full-access" {
			return
		}
		desc := source + " declares sandbox_mode=danger-full-access (no Codex sandbox)"
		if p.Approval == "never" {
			desc += " with approval_policy=never (no approval prompts)"
		}
		findings = append(findings, r.newFinding(ctx, 1, desc+"; activation and external enforcement are unresolved",
			"Prefer read-only or workspace-write and on-request approvals. Verify project trust, selected profile, higher-precedence sources and externally enforced requirements; never is not itself a sandbox bypass"))
	}
	check(a.config.codexPermissions, "Codex configuration")
	names := make([]string, 0, len(a.config.Profiles))
	for name := range a.config.Profiles {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		// No inheritance: project-local profiles are stripped in the supported
		// version. Combining them with base settings would fabricate a policy.
		check(a.config.Profiles[name].codexPermissions, "Codex inline profile "+name+" (ignored in project-local sources)")
	}
	return findings
}

// RegisterCodexRules registers permission analysis; MCP reuses SD-021/SD-024.
func RegisterCodexRules(registry *RuleRegistry) {
	registry.Register(&codexPermissionsRule{baseRule: baseRule{
		id: "SD-026", name: "Codex Unrestricted Sandbox", severity: model.SeverityHigh,
		category: "Codex", types: []string{".toml"}, axis: axes.PermissionHygiene,
	}})
}
