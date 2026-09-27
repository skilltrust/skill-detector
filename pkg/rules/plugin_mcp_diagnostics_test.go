package rules

import (
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
)

func pluginDiagnostics(t *testing.T, path, content string, analysis model.AnalysisContext) string {
	t.Helper()
	warnings, err := PluginMCPDiagnostics([]byte(content), model.FileContext{Path: path, Analysis: analysis})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(warnings, "\n")
}

func knownPluginFact(value string) model.ContextValue {
	return model.ContextValue{State: model.ContextKnown, Value: value, Evidence: "supplied test fact"}
}

func TestMarketplacePolicyStatesAndSource(t *testing.T) {
	path := ".claude/settings.json"
	for _, tc := range []struct{ input, want string }{
		{`{}`, ""},
		{`{"strictKnownMarketplaces":[]}`, "is empty"},
		{`{"strictKnownMarketplaces":null}`, "is malformed"},
		{`{"strictKnownMarketplaces":[{"source":"bogus"}]}`, "entry validity unknown (malformed or unsupported shape)"},
		{`{"strictKnownMarketplaces":[{"source":"github","repo":"org/repo"}]}`, "entry validity not established"},
		{`{"strictKnownMarketplaces":[{"source":"npm","package":"demo"}]}`, "parses but matches no registered marketplace"},
		{`{"strictKnownMarketplaces":[],"strictKnownMarketplaces":[{"source":"github","repo":"org/repo"}]}`, "ambiguous"},
	} {
		got := pluginDiagnostics(t, path, tc.input, model.AnalysisContext{})
		if !strings.Contains(got, tc.want) || strings.Contains(got, "source=supplied managed") {
			t.Fatalf("%s: %s", tc.input, got)
		}
	}
	managed := pluginDiagnostics(t, path, `{"strictKnownMarketplaces":[]}`, model.AnalysisContext{DeclarationOrigin: knownPluginFact("managed")})
	if !strings.Contains(managed, "source=supplied managed") || !strings.Contains(managed, "runtime enforcement") {
		t.Fatal(managed)
	}
}

func TestInstalledPluginCommitEvidence(t *testing.T) {
	path := ".claude/installed_plugins.json"
	sha := strings.Repeat("a", 40)
	other := strings.Repeat("b", 40)
	input := `{"plugins":{"demo":[{"gitCommitSha":"` + sha + `"}],"missing":[{"version":"1.0"}]}}`
	for _, tc := range []struct {
		analysis model.AnalysisContext
		want     string
	}{
		{model.AnalysisContext{}, "evidenced installed commit " + sha},
		{model.AnalysisContext{Conditions: map[string]model.ContextValue{"plugin_commit:demo": knownPluginFact(sha)}}, "supplied pin matches"},
		{model.AnalysisContext{Conditions: map[string]model.ContextValue{"plugin_commit:demo": knownPluginFact(other)}}, "differs from supplied pin"},
	} {
		got := pluginDiagnostics(t, path, input, tc.analysis)
		if !strings.Contains(got, tc.want) || !strings.Contains(got, "missing installed commit") || strings.Contains(got, "current-session activation established") {
			t.Fatal(got)
		}
	}
	if got := pluginDiagnostics(t, path, `{"plugins":{"demo":[{"gitCommitSha":"https://user:secret@example.invalid/repo"}]}}`, model.AnalysisContext{}); strings.Contains(got, "secret") || !strings.Contains(got, "value withheld") {
		t.Fatal(got)
	}
}

func TestNPMPluginInstallScriptsAreNotRuntimeSafety(t *testing.T) {
	path := ".claude/marketplace.json"
	got := pluginDiagnostics(t, path, `{"plugins":[{"source":{"source":"npm","package":"demo"}},{"source":{"source":"command","command":"echo synthetic-token"}}]}`, model.AnalysisContext{})
	if !strings.Contains(got, "npm pack --ignore-scripts") || !strings.Contains(got, "not runtime plugin supply-chain risk") || !strings.Contains(got, "command and arguments withheld") || strings.Contains(got, "synthetic-token") {
		t.Fatal(got)
	}
	if got := pluginDiagnostics(t, path, `{"plugins":[{"source":{"source":"git","url":"https://user:secret@example.invalid/repo"}}]}`, model.AnalysisContext{}); got != "" {
		t.Fatal(got)
	}
}

func TestSDKMCPIsCompatibilityOnly(t *testing.T) {
	content := `{"mcpServers":{"sdk":{"type":"sdk","command":"npx","args":["unsafe"],"url":"https://example.invalid/mcp"},"ordinary":{"command":"npx","args":["ordinary"]}}}`
	path := ".mcp.json"
	got := pluginDiagnostics(t, path, content, model.AnalysisContext{})
	if !strings.Contains(got, "Compatibility declaration only") || !strings.Contains(got, "installed Claude Code version is unknown") {
		t.Fatal(got)
	}
	registry := NewRegistry()
	RegisterMCPRules(registry)
	ctx := model.FileContext{Path: path}
	var auto int
	for _, rule := range registry.RulesFor(".json") {
		for _, finding := range rule.Match([]byte(content), ctx) {
			if finding.RuleID == "SD-024" {
				auto++
				if !strings.Contains(finding.Description, "ordinary") {
					t.Fatal(finding)
				}
			}
		}
	}
	if auto != 1 {
		t.Fatalf("auto-install findings = %d", auto)
	}
}

func TestClaudeAgentsFallbackVersionProvider(t *testing.T) {
	path := "AGENTS.md"
	unknown := pluginDiagnostics(t, path, "Inert", model.AnalysisContext{})
	if !strings.Contains(unknown, "provider unknown") || !strings.Contains(unknown, "no CLAUDE.md was supplied") {
		t.Fatal(unknown)
	}
	known := pluginDiagnostics(t, path, "Inert", model.AnalysisContext{Version: knownPluginFact("2.1.277"), Provider: knownPluginFact("bedrock"), Conditions: map[string]model.ContextValue{"claude_instructions": knownPluginFact("present")}})
	if !strings.Contains(known, "also supplied") || !strings.Contains(known, "excludes AGENTS.md") || strings.Contains(known, "provider unknown") {
		t.Fatal(known)
	}
}

func TestOmitClaudeMdKeepsManagedTier(t *testing.T) {
	path := ".claude/agents/helper.md"
	for _, tc := range []struct {
		input   string
		present bool
	}{
		{"---\nomitClaudeMd: true\n---\nBody", true},
		{"---\nomitClaudeMd: false\n---\nBody", false},
		{"---\nname: demo\n---not-a-delimiter\nomitClaudeMd: true", false},
	} {
		got := pluginDiagnostics(t, path, tc.input, model.AnalysisContext{})
		if strings.Contains(got, "managed instructions still load") != tc.present {
			t.Fatal(got)
		}
	}
}

func TestCloudRepositorySettingsNeedTopologyEvidence(t *testing.T) {
	path := ".claude/settings.json"
	input := `{"enabledPlugins":{"demo":true},"hooks":{}}`
	for _, tc := range []struct {
		analysis model.AnalysisContext
		want     string
	}{
		{model.AnalysisContext{}, "topology is unknown"},
		{model.AnalysisContext{Conditions: map[string]model.ContextValue{"cloud_repositories": knownPluginFact("multiple")}}, "topology is multiple"},
		{model.AnalysisContext{Conditions: map[string]model.ContextValue{"cloud_repositories": knownPluginFact("single")}}, "topology is single"},
	} {
		got := pluginDiagnostics(t, path, input, tc.analysis)
		if !strings.Contains(got, tc.want) || !strings.Contains(got, "do not by themselves establish active permissions") {
			t.Fatal(got)
		}
	}
}

func TestScheduledTasksNeedSessionBinding(t *testing.T) {
	input := `{"tasks":[{"id":"copied"}]}`
	for _, analysis := range []model.AnalysisContext{{}, {Version: knownPluginFact("2.1.273")}} {
		got := pluginDiagnostics(t, ".claude/scheduled_tasks.json", input, analysis)
		if !strings.Contains(got, "do not establish current-session binding or execution") {
			t.Fatal(got)
		}
	}
}

func TestRespawnedAgentNeedsSourceTrust(t *testing.T) {
	path := ".claude/agents/helper.md"
	content := "Inert"
	for _, tc := range []struct {
		analysis model.AnalysisContext
		want     string
	}{
		{model.AnalysisContext{}, ""},
		{model.AnalysisContext{Session: knownPluginFact("teammate-respawn")}, ""},
		{model.AnalysisContext{Session: knownPluginFact("teammate-respawn"), Conditions: map[string]model.ContextValue{"same_name_agent": knownPluginFact("false")}}, ""},
		{model.AnalysisContext{Session: knownPluginFact("teammate-respawn"), Conditions: map[string]model.ContextValue{"same_name_agent": knownPluginFact("true")}}, "source trust=unknown"},
		{model.AnalysisContext{Session: knownPluginFact("teammate-respawn"), Trust: knownPluginFact("untrusted"), Conditions: map[string]model.ContextValue{"same_name_agent": knownPluginFact("true")}}, "source trust=untrusted"},
		{model.AnalysisContext{Session: knownPluginFact("teammate-respawn"), Trust: knownPluginFact("trusted"), Conditions: map[string]model.ContextValue{"same_name_agent": knownPluginFact("true")}}, "source trust=trusted"},
	} {
		got := pluginDiagnostics(t, path, content, tc.analysis)
		if !strings.Contains(got, tc.want) || (tc.want == "" && got != "") {
			t.Fatalf("want %q got %q", tc.want, got)
		}
	}
}

func TestExternalSkillSurfacesRemainUnavailable(t *testing.T) {
	got := pluginDiagnostics(t, "AGENTS.md", "Inert", model.AnalysisContext{})
	if !strings.Contains(got, "Untracked worktree and account-synced skills are unavailable unless supplied") {
		t.Fatal(got)
	}
}

func TestManagedMCPFailureIsNotClean(t *testing.T) {
	path := ".claude/settings.json"
	for _, input := range []string{`{"allowedMcpServers":null}`, `{"deniedMcpServers":[{"serverCommand":"npx"}]}`} {
		got := pluginDiagnostics(t, path, input, model.AnalysisContext{})
		if !strings.Contains(got, "malformed") || !strings.Contains(got, "effective policy unknown") {
			t.Fatal(got)
		}
	}
	got := pluginDiagnostics(t, path, `{"allowedMcpServers":[{"serverName":"demo"}],"deniedMcpServers":[{"serverName":"demo"}]}`, model.AnalysisContext{DeclarationOrigin: knownPluginFact("managed")})
	if !strings.Contains(got, "deny wins") || !strings.Contains(got, "managed provenance=supplied managed") {
		t.Fatal(got)
	}
}
