package rules

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
)

func claudeDiagnostics(t *testing.T, content []byte, ctx model.FileContext) []string {
	t.Helper()
	warnings, err := ClaudeConfigurationDiagnostics(content, ctx)
	if err != nil {
		t.Fatal(err)
	}
	return warnings
}

func TestInlineShellDistinguishesExecutableSyntax(t *testing.T) {
	content := "Run dynamic context:\n !`printf ready`\n```!\nprintf second\n```\n"
	ctx := model.FileContext{Path: ".claude/skills/audit/SKILL.md"}
	warnings := claudeDiagnostics(t, []byte(content), ctx)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "2 executable inline shell") ||
		!strings.Contains(warnings[0], "installed Claude Code version is unknown") {
		t.Fatalf("executable syntax diagnostics = %v", warnings)
	}

	for _, prose := range []string{
		"Describe the syntax `!`command`` without running it.",
		"Escaped syntax: \\!`printf ready`",
		"Assignment syntax: KEY=!`printf ready`",
		"---\nmetadata:\n  example: |\n    !`printf ready`\n---\nStatic instructions.\n",
	} {
		if got := claudeDiagnostics(t, []byte(prose), ctx); len(got) != 0 {
			t.Fatalf("ordinary prose %q produced diagnostics: %v", prose, got)
		}
	}
}

func TestAllowedDomainsArePerCommandDeclarations(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{"narrow", `{"name":"Bash","input":{"command":"curl https://api.example.com/v1","allowed_domains":["api.example.com:443"]}}`, "narrowly names"},
		{"broader", `{"name":"PowerShell","input":{"command":"curl https://api.example.com/v1","allowed_domains":["*.example.com"]}}`, "broader than"},
		{"different", `{"name":"Monitor","input":{"command":"curl https://api.example.com/v1","allowed_domains":["other.example"]}}`, "does not cover"},
		{"missing-command", `{"name":"Bash","input":{"allowed_domains":["api.example.com"]}}`, "no literal command destination"},
		{"duplicate-destination", `{"name":"Bash","input":{"command":"curl https://api.example.com/a https://api.example.com/b","allowed_domains":["api.example.com:443"]}}`, "narrowly names"},
		{"unmatched-extra", `{"name":"Bash","input":{"command":"curl https://api.example.com/a https://api.example.com/b","allowed_domains":["api.example.com:443","unrelated.example"]}}`, "broader than"},
		{"matching-port", `{"name":"Bash","input":{"command":"curl https://api.example.com:8443/a","allowed_domains":["api.example.com:8443"]}}`, "narrowly names"},
		{"mismatching-port", `{"name":"Bash","input":{"command":"curl https://api.example.com:8443/a","allowed_domains":["api.example.com:443"]}}`, "does not cover"},
		{"extra-port", `{"name":"Bash","input":{"command":"curl https://api.example.com:8443/a","allowed_domains":["api.example.com:8443","api.example.com:443"]}}`, "broader than"},
		{"unrestricted-explicit-port", `{"name":"Bash","input":{"command":"curl https://api.example.com:8443/a","allowed_domains":["api.example.com"]}}`, "broader than"},
		{"unrestricted-implicit-https-port", `{"name":"Bash","input":{"command":"curl https://api.example.com/a","allowed_domains":["api.example.com"]}}`, "broader than"},
		{"unrestricted-implicit-http-port", `{"name":"Bash","input":{"command":"curl http://api.example.com/a","allowed_domains":["api.example.com"]}}`, "broader than"},
		{"narrow-implicit-http-port", `{"name":"Bash","input":{"command":"curl http://api.example.com/a","allowed_domains":["api.example.com:80"]}}`, "narrowly names"},
		{"ipv6-port", `{"name":"Bash","input":{"command":"curl https://[2001:db8::1]:8443/a","allowed_domains":["[2001:db8::1]:8443"]}}`, "narrowly names"},
		{"wildcard-apex", `{"name":"Bash","input":{"command":"curl https://example.com/a","allowed_domains":["*.example.com:443"]}}`, "does not cover"},
		{"wildcard-direct-subdomain", `{"name":"Bash","input":{"command":"curl https://api.example.com/a","allowed_domains":["*.example.com:443"]}}`, "broader than"},
		{"wildcard-nested-subdomain", `{"name":"Bash","input":{"command":"curl https://v1.api.example.com:8443/a","allowed_domains":["*.example.com:8443"]}}`, "broader than"},
		{"unsupported-domain", `{"name":"Bash","input":{"command":"curl https://api.example.com/a","allowed_domains":["api.example.com:"]}}`, "cannot be compared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := model.FileContext{Path: ".claude/tool-calls.json"}
			got := claudeDiagnostics(t, []byte(tc.input), ctx)
			joined := strings.Join(got, "\n")
			if !strings.Contains(joined, tc.want) || !strings.Contains(joined, "does not prove network confinement") ||
				!strings.Contains(joined, "auto mode, sandbox activation") {
				t.Fatalf("diagnostic = %q", joined)
			}
		})
	}
	ctx := model.FileContext{Path: ".claude/tool-calls.json"}
	if got := claudeDiagnostics(t, []byte(`{"name":"WebFetch","input":{"allowed_domains":["example.com"]}}`), ctx); len(got) != 0 {
		t.Fatalf("unsupported tool produced diagnostic: %v", got)
	}
}

func TestInlineAndDomainAnalysisIsInert(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	content := []byte("!`touch " + marker + "`\n")
	ctx := model.FileContext{Path: "SKILL.md"}
	if got := claudeDiagnostics(t, content, ctx); len(got) != 1 {
		t.Fatalf("diagnostics = %v", got)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("inline command was executed: stat error = %v", err)
	}
}

func TestSandboxExcludedCommandsRequireEveryComponent(t *testing.T) {
	patterns := []string{"docker *", "npm *"}
	for _, tc := range []struct {
		command   string
		covered   bool
		supported bool
	}{
		{"npm ci && docker build .", true, true},
		{"npm ci && curl https://example.test", false, true},
		{"docker build .", true, true},
		{`sh -c "docker build ."`, false, false},
	} {
		covered, supported := excludedCommandCovers(patterns, tc.command)
		if covered != tc.covered || supported != tc.supported {
			t.Errorf("%q = (%v,%v), want (%v,%v)", tc.command, covered, supported, tc.covered, tc.supported)
		}
	}

	for _, tc := range []struct {
		content, want string
	}{
		{`{"sandbox":{"excludedCommands":["docker *"]}}`, "narrow exclusion"},
		{`{"sandbox":{"excludedCommands":["*"]}}`, "broad or wildcard exclusion"},
		{`{"sandbox":{"excludedCommands":["bash:*"]}}`, "broad or wildcard exclusion"},
		{`{"sandbox":{"excludedCommands":["bash *"]}}`, "broad or wildcard exclusion"},
		{`{"sandbox":{"excludedCommands":["bash*"]}}`, "broad or wildcard exclusion"},
		{`{"sandbox":{"excludedCommands":["sh:*"]}}`, "broad or wildcard exclusion"},
		{`{"sandbox":{"excludedCommands":["PowerShell:*"]}}`, "broad or wildcard exclusion"},
	} {
		ctx := model.FileContext{
			Path: ".claude/settings.json",
			Analysis: model.AnalysisContext{
				Version: model.ContextValue{State: model.ContextKnown, Value: "2.1.277"},
			},
		}
		joined := strings.Join(claudeDiagnostics(t, []byte(tc.content), ctx), "\n")
		if !strings.Contains(joined, tc.want) || !strings.Contains(joined, "every component") ||
			!strings.Contains(joined, "not proof of runtime sandbox enforcement") {
			t.Fatalf("diagnostic = %q", joined)
		}
	}
}

func TestPermissionPrecedenceNeedsVersionSource(t *testing.T) {
	content := []byte(`{"allowManagedPermissionRulesOnly":true,"permissions":{"defaultMode":"bypassPermissions","allow":["Bash(*)","Write(**/.env)"],"deny":["Bash(rm -rf *)","Read(**/.env)","Read(!sample.env)"]}}`)
	contexts := []struct {
		name           string
		analysis       model.AnalysisContext
		mustContain    []string
		mustNotContain []string
	}{
		{
			name: "known-current-project",
			analysis: model.AnalysisContext{
				Version:           model.ContextValue{State: model.ContextKnown, Value: "2.1.277"},
				DeclarationOrigin: model.ContextValue{State: model.ContextKnown, Value: "project"},
			},
			mustContain:    []string{"does not activate", "candidate grants", "outside established managed provenance", "path-scoped Write", "same settings source", "when their source is applicable", "anchor-specific behavior is unresolved"},
			mustNotContain: []string{"Claude Code 2.1.268 is supplied", "remain protective"},
		},
		{
			name: "known-old-project",
			analysis: model.AnalysisContext{
				Version:           model.ContextValue{State: model.ContextKnown, Value: "2.1.200"},
				DeclarationOrigin: model.ContextValue{State: model.ContextKnown, Value: "project"},
			},
			mustContain:    []string{"pre-2.1.257", "workspace trust", "anchor-specific behavior is unresolved"},
			mustNotContain: []string{"Claude Code 2.1.268 is supplied", "installed Claude Code version is unknown"},
		},
		{
			name: "known-current-candidate-project",
			analysis: model.AnalysisContext{
				Version:           model.ContextValue{State: model.ContextKnown, Value: "2.1.277"},
				DeclarationOrigin: model.ContextValue{State: model.ContextCandidate, Value: "project"},
			},
			mustContain:    []string{"If loaded from that source", "effective source", "remain unresolved"},
			mustNotContain: []string{"not an effective bypass declaration for the supplied context"},
		},
		{
			name: "prerelease-project",
			analysis: model.AnalysisContext{
				Version:           model.ContextValue{State: model.ContextKnown, Value: "2.1.257-beta.1"},
				DeclarationOrigin: model.ContextValue{State: model.ContextKnown, Value: "project"},
			},
			mustContain:    []string{"activation is unresolved", "anchor-specific behavior is unresolved"},
			mustNotContain: []string{"does not activate", "pre-2.1.257", "Claude Code 2.1.268 is supplied"},
		},
		{
			name: "known-managed",
			analysis: model.AnalysisContext{
				Version:           model.ContextValue{State: model.ContextKnown, Value: "2.1.277"},
				DeclarationOrigin: model.ContextValue{State: model.ContextKnown, Value: "managed"},
			},
			mustContain: []string{"declaration rather than proof", "managed allowManagedPermissionRulesOnly", "deny and ask rules can still tighten"},
		},
		{
			name: "known-old-managed",
			analysis: model.AnalysisContext{
				Version:           model.ContextValue{State: model.ContextKnown, Value: "2.1.200"},
				DeclarationOrigin: model.ContextValue{State: model.ContextKnown, Value: "managed"},
			},
			mustContain:    []string{"dropped at the first settings reload", "must not be treated as durable tightening"},
			mustNotContain: []string{"can still tighten policy at the supplied version"},
		},
		{
			name: "unknown-managed",
			analysis: model.AnalysisContext{
				DeclarationOrigin: model.ContextValue{State: model.ContextKnown, Value: "managed"},
			},
			mustContain: []string{"Current documentation", "before 2.1.257", "applicability to the supplied unknown or prerelease version is unresolved"},
		},
		{
			name: "unknown-project-candidate",
			analysis: model.AnalysisContext{
				DeclarationOrigin: model.ContextValue{State: model.ContextCandidate, Value: "project"},
			},
			mustContain:    []string{"effective version, trust and session override are unknown", "effective installed Claude Code version is unknown"},
			mustNotContain: []string{"remain protective", "deny still wins"},
		},
	}
	for _, tc := range contexts {
		t.Run(tc.name, func(t *testing.T) {
			ctx := model.FileContext{Path: ".claude/settings.json", Analysis: tc.analysis}
			joined := strings.Join(claudeDiagnostics(t, content, ctx), "\n")
			for _, want := range tc.mustContain {
				if !strings.Contains(joined, want) {
					t.Errorf("missing %q in %q", want, joined)
				}
			}
			for _, unwanted := range tc.mustNotContain {
				if strings.Contains(joined, unwanted) {
					t.Errorf("unexpected %q in %q", unwanted, joined)
				}
			}
		})
	}
}

func TestClaudeSettingsValidationFailsClosed(t *testing.T) {
	ctx := model.FileContext{Path: ".claude/settings.json"}
	for _, content := range []string{
		`{"permissions":`,
		`{"permissions":{"defaultMode":"bypassPermissions"},"sandbox":{"excludedCommands":true}}`,
		`null`,
		`{"permissions":null}`,
		`{"permissions":{"deny":[null]}}`,
		`{"allowManagedPermissionRulesOnly":null}`,
		`{"permissions":{"deny":[null]},"permissions":{}}`,
		`{"sandbox":{"excludedCommands":["*"],"EXCLUDEDCOMMANDS":[]}}`,
		`{"PERMISSIONS":{"DENY":[null]}}`,
	} {
		warnings, err := ClaudeConfigurationDiagnostics([]byte(content), ctx)
		if err == nil || warnings != nil {
			t.Fatalf("warnings=%v error=%v; want sanitized error and no diagnostics", warnings, err)
		}
		if !strings.Contains(err.Error(), "configuration was not assessed") || strings.Contains(err.Error(), "bypassPermissions") {
			t.Fatalf("unsanitized or unclear error: %v", err)
		}
	}
}

func TestClaudeSettingsAllowCaseSensitiveDataKeysAndLargeObjects(t *testing.T) {
	var content strings.Builder
	content.WriteString(`{"env":{"HTTP_PROXY":"http://proxy.example:8080","http_proxy":"http://proxy.example:8080"`)
	for i := range 20_000 {
		content.WriteString(`,"KEY_` + strconv.Itoa(i) + `":"value"`)
	}
	content.WriteString(`}}`)

	ctx := model.FileContext{Path: ".claude/settings.json"}
	warnings, err := ClaudeConfigurationDiagnostics([]byte(content.String()), ctx)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("large case-sensitive data map: warnings=%v error=%v", warnings, err)
	}
}
