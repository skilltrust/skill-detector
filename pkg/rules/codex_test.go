package rules

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

func TestCodexMCPEquivalence(t *testing.T) {
	for _, tc := range []struct{ id, json, toml string }{
		{"SD-024", `{"mcpServers":{"audit":{"command":"npx","args":["-y","example-mcp-server"]}}}`, "[mcp_servers.audit]\ncommand='npx'\nargs=['-y', 'example-mcp-server']"},
		{"SD-024", `{"mcpServers":{"audit":{"command":"/bin/uvx","args":["example@1.2"]}}}`, "mcp_servers.audit = { command='/bin/uvx', args=['example@1.2'] }"},
		{"SD-021", `{"mcpServers":{"audit":{"url":"https://audit.example.test/mcp"}}}`, "[mcp_servers.'audit']\nurl='https://audit.example.test/mcp'"},
		{"SD-021", `{"mcpServers":{"audit":{"url":"http://[::1]:3000/mcp"}}}`, "[mcp_servers.audit]\nurl='http://[::1]:3000/mcp'"},
	} {
		t.Run(tc.id+tc.toml, func(t *testing.T) {
			r := findRule(t, tc.id)
			jsonFindings := r.Match([]byte(tc.json), model.FileContext{Path: ".mcp.json"})
			tomlFindings := r.Match([]byte(tc.toml), model.FileContext{Path: ".codex/config.toml"})
			for i := range jsonFindings {
				jsonFindings[i].FilePath = ".codex/config.toml"
			}
			if !reflect.DeepEqual(jsonFindings, tomlFindings) {
				t.Fatalf("JSON: %+v; TOML: %+v", jsonFindings, tomlFindings)
			}
		})
	}
}

func TestSD026_Permissions(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		count         int
		promptless    bool
	}{
		{"full-never", "sandbox_mode='danger-full-access'\napproval_policy='never'", 1, true},
		{"full-request", "sandbox_mode='danger-full-access'\napproval_policy='on-request'", 1, false},
		{"full-unresolved", "sandbox_mode='danger-full-access'", 1, false},
		{"readonly-never", "sandbox_mode='read-only'\napproval_policy='never'", 0, false},
		{"workspace-never", "sandbox_mode='workspace-write'\napproval_policy='never'", 0, false},
		{"workspace-request", "sandbox_mode='workspace-write'\napproval_policy='on-request'", 0, false},
		{"approval-only", "approval_policy='never'", 0, false},
		{"granular", "sandbox_mode='danger-full-access'\napproval_policy={granular={sandbox_approval=false,rules=false,mcp_elicitations=false}}", 1, false},
		{"profile", "sandbox_mode='read-only'\n[profiles.wide]\nsandbox_mode='danger-full-access'\napproval_policy='never'", 1, true},
		{"no-cross-profile-merge", "[profiles.wide]\nsandbox_mode='danger-full-access'\n[profiles.quiet]\napproval_policy='never'", 1, false},
		{"no-base-profile-merge", "approval_policy='never'\n[profiles.wide]\nsandbox_mode='danger-full-access'", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range []string{".codex/config.toml", "nested/.codex/config.toml", ".codex/work.config.toml"} {
				ctx := model.FileContext{Path: path}
				if _, err := CodexConfigDiagnostics([]byte(tc.content), ctx); err != nil {
					t.Fatal(err)
				}
				got := findRule(t, "SD-026").Match([]byte(tc.content), ctx)
				if len(got) != tc.count {
					t.Fatalf("%s: got %+v, want %d", path, got, tc.count)
				}
				for _, f := range got {
					if f.Axis != axes.PermissionHygiene || f.Severity != model.SeverityHigh ||
						strings.Contains(f.Description, "no approval prompts") != tc.promptless ||
						!strings.Contains(f.Description, "unresolved") {
						t.Fatalf("wrong semantics: %+v", f)
					}
				}
			}
		})
	}
}

func TestSD026_GatesNonAgentFile(t *testing.T) {
	content := []byte("sandbox_mode='danger-full-access'\n[mcp_servers.audit]\ncommand='npx'\nargs=['example']")
	for _, path := range []string{"config.toml", "node_modules/.codex/config.toml", "vendor/.codex/config.toml", "some.codex/config.toml", ".codex/examples/config.toml", ".codex/settings.toml"} {
		for _, id := range []string{"SD-021", "SD-024", "SD-026"} {
			if got := findRule(t, id).Match(content, model.FileContext{Path: path}); len(got) != 0 {
				t.Fatalf("%s %s: %+v", id, path, got)
			}
		}
		if warnings, err := CodexConfigDiagnostics([]byte("[broken"), model.FileContext{Path: path}); err != nil || len(warnings) != 0 {
			t.Fatalf("diagnostics escaped gate: %s %v %v", path, warnings, err)
		}
	}
}

func TestCodexTimeoutDurationRange(t *testing.T) {
	for _, field := range []string{"startup_timeout_sec", "tool_timeout_sec"} {
		for _, tc := range []struct {
			value   string
			invalid bool
		}{
			{"0", false},
			{"0.25", false},
			{"9223372036854775807", false},    // largest TOML integer
			{"18446744073709549568.0", false}, // float64 immediately below 2^64
			{"18446744073709551616.0", true},  // 2^64 seconds cannot fit Rust Duration
			{"18446744073709555712.0", true},  // float64 immediately above 2^64
			{"1e100", true},
			{"-1.0", true},
			{"nan", true},
			{"inf", true},
		} {
			t.Run(field+"/"+tc.value, func(t *testing.T) {
				content := "[mcp_servers.local]\ncommand='./local-mcp'\n" + field + "=" + tc.value
				_, err := CodexConfigDiagnostics([]byte(content), model.FileContext{Path: ".codex/config.toml"})
				if (err != nil) != tc.invalid {
					t.Fatalf("error=%v, want invalid=%v", err, tc.invalid)
				}
			})
		}
	}
}

func TestCodexInvalidIsNotPermissive(t *testing.T) {
	for _, content := range []string{
		"[broken", "approval_policy='secret-sentinel'", "sandbox_mode='external-sandbox'",
		"sandbox_mode=''", "[profiles.work.mcp_servers.audit]\ncommand='npx'",
		"approval_policy=true", "sandbox_mode=1", "approval_policy={granular={rules=false}}",
		"approval_policy={granular={sandbox_approval=false,rules=false,mcp_elicitations=false,unknown=true}}",
		"[mcp_servers.audit]\ncommand='npx'\nargs=[1]",
		"[mcp_servers.audit]\ncommand='npx'\nurl='https://example.test'",
		"[mcp_servers.audit]\nurl='${ENDPOINT}'",
		"[mcp_servers.audit]\ncommand='npx'\nversion='latest'",
		"[mcp_servers.audit]\ncommand='npx'\nenabled='false'",
		"[mcp_servers.audit]\nurl='https://example.test'\nargs=[]",
		"[mcp_servers.audit]\ncommand='npx'\nhttp_headers={a='b'}",
		"[mcp_servers.audit]\ncommand=''", "[mcp_servers.audit]",
		"[model_providers.bedrock.aws.credential_export]\nargs=[]",
		"[model_providers.bedrock.aws.credential_export]\ncommand='aws'\ntimeout_ms=0",
		"[mcp_servers.audit]\nurl='https://example.test'\nhttp_headers_helper=''",
		"[mcp_servers.audit]\ncommand='local'\nstartup_timeout_sec=nan",
	} {
		t.Run(content, func(t *testing.T) {
			ctx := model.FileContext{Path: ".codex/config.toml"}
			_, err := CodexConfigDiagnostics([]byte(content), ctx)
			if err == nil || strings.Contains(err.Error(), "secret-sentinel") {
				t.Fatalf("expected redacted error, got %v", err)
			}
			for _, id := range []string{"SD-021", "SD-024", "SD-026"} {
				if got := findRule(t, id).Match([]byte(content), ctx); len(got) > 0 {
					t.Fatalf("invalid config produced permission claim: %+v", got)
				}
			}
		})
	}
}

func TestCodexTrustHelpersAndCompatibility(t *testing.T) {
	for _, trust := range []string{"trusted", "untrusted"} {
		content := fmt.Sprintf("sandbox_mode='danger-full-access'\n[projects.'/repo']\ntrust_level='%s'", trust)
		warnings, err := CodexConfigDiagnostics([]byte(content), model.FileContext{Path: ".codex/config.toml"})
		if err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "do not establish user trust") {
			t.Fatalf("trust cannot be inferred: %v %v", warnings, err)
		}
		if len(findRule(t, "SD-026").Match([]byte(content), model.FileContext{Path: ".codex/config.toml"})) != 1 {
			t.Fatal("repository trust declaration must not suppress declaration analysis")
		}
	}
	for _, tc := range []struct{ content, warning string }{
		{"[model_providers.bedrock.aws.credential_export]\ncommand='/audit/helper'", "aws.credential_export"},
		{"[model_providers.bedrock.aws.auth_refresh]\ncommand='/audit/helper'", "aws.auth_refresh"},
		{"[mcp_servers.headers]\nurl='https://example.test'\nhttp_headers_helper='local-header-helper'", "http_headers_helper declares a shell command"},
		{"[mcp_servers.old]\ncommand='codex'\nargs=['mcp-server']", "compatibility drift, not a CVE"},
		{"[mcp_servers.old]\ncommand='codex-mcp-server'", "compatibility drift, not a CVE"},
		{"profile='missing'", "external profile source is unresolved"},
	} {
		warnings, err := CodexConfigDiagnostics([]byte(tc.content), model.FileContext{Path: ".codex/config.toml"})
		if err != nil || !strings.Contains(strings.Join(warnings, "\n"), tc.warning) {
			t.Fatalf("missing inventory/compatibility: %v %v", warnings, err)
		}
	}
	for _, content := range []string{
		"model_provider='bedrock'\n[model_providers.bedrock.aws]\nprofile='default'\nregion='us-east-1'",
		"[mcp_servers.current]\ncommand='codex'\nargs=['exec', 'mcp-server']",
		"[mcp_servers.current]\ncommand='codex'\nargs=['mcp', 'list']",
		"[mcp_servers.local]\ncommand='./bin/mcp'",
		"[mcp_servers.local]\ncommand='./bin/mcp'\ncwd='.'\nscopes=['read']\nenv={MODE='audit'}\nstartup_timeout_sec=1.5\ntool_timeout_sec=30\nstartup_timeout_ms=1000\nenabled_tools=['read']\ndisabled_tools=['write']\nrequired=true",
		"[mcp_servers.disabled]\ncommand='npx'\nargs=['example']\nenabled=false",
		"[mcp_servers.disabled]\nurl='https://example.test'\nenabled=false",
	} {
		ctx := model.FileContext{Path: ".codex/config.toml"}
		warnings, err := CodexConfigDiagnostics([]byte(content), ctx)
		if err != nil || len(warnings) != 1 {
			t.Fatalf("unexpected warning: %v %v", warnings, err)
		}
		for _, id := range []string{"SD-021", "SD-024", "SD-026"} {
			if got := findRule(t, id).Match([]byte(content), ctx); len(got) != 0 {
				t.Fatalf("benign declaration: %+v", got)
			}
		}
	}
}
