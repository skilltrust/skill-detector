package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/rules"
)

func scanCopilotContext(t *testing.T, root string, analysis model.AnalysisContext) (string, error) {
	t.Helper()
	result, err := New(rules.NewRegistry(), Options{}).run(context.Background(), root, analysis)
	if err != nil {
		if result != nil {
			t.Fatal("invalid configuration returned a graded result")
		}
		return "", err
	}
	return strings.Join(result.Warnings, "\n"), nil
}

func TestCopilotAllowAllExactValues(t *testing.T) {
	for _, tc := range []struct {
		value, want, not string
	}{
		{"true", "auto-approval and working-directory trust", ""},
		{" true ", "auto-approval only", "working-directory trust"},
		{"TRUE", "auto-approval only", "working-directory trust"},
		{"1", "auto-approval only", "working-directory trust"},
		{"YeS", "auto-approval only", "working-directory trust"},
		{"on", "auto-approval only", "working-directory trust"},
		{"y", "auto-approval only", "working-directory trust"},
		{"false", "explicitly off", "auto-approval"},
		{"0", "explicitly off", "auto-approval"},
		{" NO ", "explicitly off", "auto-approval"},
		{"off", "explicitly off", "auto-approval"},
		{"n", "explicitly off", "auto-approval"},
		{"", "explicitly off", "auto-approval"},
		{"2", "unrecognized", "auto-approval"},
	} {
		t.Run("value="+tc.value, func(t *testing.T) {
			root := t.TempDir()
			writeCopilot(t, root, ".github/hooks/a.json", `{"version":1,"hooks":{"sessionEnd":[{"bash":"printf ready"}]}}`)
			ctx := model.AnalysisContext{Conditions: map[string]model.ContextValue{"copilot_allow_all": {State: model.ContextKnown, Value: tc.value}}}
			got, err := scanCopilotContext(t, root, ctx)
			if err != nil || !strings.Contains(got, tc.want) || tc.not != "" && strings.Contains(got, tc.not) {
				t.Fatalf("value=%q warnings=%q err=%v", tc.value, got, err)
			}
		})
	}
	root := t.TempDir()
	writeCopilot(t, root, ".github/hooks/a.json", `{"version":1,"hooks":{"sessionEnd":[{"bash":"printf ready","env":{"COPILOT_ALLOW_ALL":"true"}}]}}`)
	got, err := scanCopilotContext(t, root, model.AnalysisContext{})
	if err != nil || strings.Contains(got, "auto-approval and working-directory trust") {
		t.Fatalf("hook env is not the launching process: %q %v", got, err)
	}
}

func TestCopilotSettingsSwitchesDoNotInventManagedBypassOrCredentialRead(t *testing.T) {
	root := t.TempDir()
	writeCopilot(t, root, ".github/copilot/settings.json", `{"sandbox":{"allowBypass":true,"allowDevToolAccess":false},"hooks":{"sessionEnd":[{"bash":"printf ready"}]}}`)
	got, err := scanCopilotContext(t, root, model.AnalysisContext{Version: model.ContextValue{State: model.ContextKnown, Value: "1.0.85"}})
	if err != nil || !strings.Contains(got, "candidate sandbox.allowBypass=true") || !strings.Contains(got, "not managed-policy evidence") || !strings.Contains(got, "allowDevToolAccess=false") || strings.Contains(got, "credential read confirmed") {
		t.Fatalf("warnings=%q err=%v", got, err)
	}
	writeCopilot(t, root, ".github/copilot/settings.json", `{"sandbox":{"allowBypass":"true"},"hooks":{"sessionEnd":[{"bash":"printf ready"}]}}`)
	if _, err := scanCopilotContext(t, root, model.AnalysisContext{}); err == nil || !strings.Contains(err.Error(), "not assessed") {
		t.Fatalf("invalid switch must not be graded: %v", err)
	}
}

func TestCopilotSettingsWithoutHooksAssessSupportedFields(t *testing.T) {
	for _, tc := range []struct {
		body, want string
	}{
		{`{"sandbox":{"allowBypass":true,"allowDevToolAccess":false}}`, "candidate sandbox.allowBypass=true"},
		{`{"worktreePathTemplate":"work/{repo}/{branchSlug}"}`, "repo, branchSlug"},
	} {
		root := t.TempDir()
		writeCopilot(t, root, ".github/copilot/settings.json", tc.body)
		result, err := scanCopilot(t, root, rules.DefaultRegistry())
		if err != nil || result.NoAgentSurface || len(result.Findings) != 0 || !strings.Contains(strings.Join(result.Warnings, "\n"), tc.want) {
			t.Fatalf("settings-only %s: result=%+v err=%v", tc.body, result, err)
		}
	}
	root := t.TempDir()
	writeCopilot(t, root, ".github/copilot/settings.json", `{"sandbox":{"other":true}}`)
	if result, err := scanCopilot(t, root, rules.DefaultRegistry()); err == nil || result != nil {
		t.Fatalf("unassessed settings must not earn grades: result=%+v err=%v", result, err)
	}
	writeCopilot(t, root, ".github/copilot/settings.json", `{"sandbox":{"allowBypass":"true"}}`)
	if result, err := scanCopilot(t, root, rules.DefaultRegistry()); err == nil || result != nil {
		t.Fatalf("invalid settings-only switch must not earn grades: result=%+v err=%v", result, err)
	}
}

func TestCopilotDeveloperToolGrantNeedsAccessEvidence(t *testing.T) {
	root := t.TempDir()
	writeCopilot(t, root, ".github/copilot/settings.json", `{"sandbox":{"allowDevToolAccess":true},"hooks":{"sessionEnd":[{"bash":"printf ready"}]}}`)
	result, err := scanCopilot(t, root, rules.DefaultRegistry())
	if err != nil || len(result.Findings) != 0 {
		t.Fatalf("grant alone is not access: findings=%v err=%v", result.Findings, err)
	}
	writeCopilot(t, root, ".github/hooks/read.json", `{"version":1,"hooks":{"sessionEnd":[{"bash":"cat ~/.npmrc"}]}}`)
	result, err = scanCopilot(t, root, rules.DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range result.Findings {
		found = found || f.RuleID == "SD-004" && f.FilePath == ".github/hooks/read.json"
	}
	if !found {
		t.Fatalf("separate credential read must survive grant: %v", result.Findings)
	}
}

func TestAdditionalMCPConfigUsesSessionCWD(t *testing.T) {
	root := t.TempDir()
	writeCopilot(t, root, ".github/hooks/a.json", `{"version":1,"hooks":{"sessionEnd":[{"bash":"printf ready"}]}}`)
	writeCopilot(t, root, "launch/server.json", `{}`)
	writeCopilot(t, root, "session/SKILL.md", "# Submitted session configuration\n")
	writeCopilot(t, root, "session/server.json", `{}`)
	base := model.AnalysisContext{Conditions: map[string]model.ContextValue{
		"copilot_additional_mcp_config": {State: model.ContextKnown, Value: "@server.json"},
		"copilot_launch_cwd":            {State: model.ContextKnown, Value: "launch"},
		"copilot_session_cwd":           {State: model.ContextKnown, Value: "session"},
	}}
	got, err := scanCopilotContext(t, root, base)
	if err != nil || !strings.Contains(got, "session/server.json") || strings.Contains(got, "launch/server.json") {
		t.Fatalf("wrong base: %q %v", got, err)
	}
	for _, ref := range []string{"@~/private.json", "@../outside.json", "@missing.json"} {
		base.Conditions["copilot_additional_mcp_config"] = model.ContextValue{State: model.ContextKnown, Value: ref}
		got, err := scanCopilotContext(t, root, base)
		if err != nil || !strings.Contains(got, "unavailable") {
			t.Fatalf("reference %s: %q %v", ref, got, err)
		}
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "secret.json"), filepath.Join(root, "session", "escape.json")); err != nil {
		t.Fatal(err)
	}
	base.Conditions["copilot_additional_mcp_config"] = model.ContextValue{State: model.ContextKnown, Value: "@escape.json"}
	got, err = scanCopilotContext(t, root, base)
	if err != nil || !strings.Contains(got, "unavailable") {
		t.Fatalf("escaping symlink: %q %v", got, err)
	}
	delete(base.Conditions, "copilot_session_cwd")
	base.Conditions["copilot_additional_mcp_config"] = model.ContextValue{State: model.ContextKnown, Value: "@server.json"}
	got, err = scanCopilotContext(t, root, base)
	if err != nil || !strings.Contains(got, "unavailable") || strings.Contains(got, "launch/server.json") {
		t.Fatalf("unknown session base: %q %v", got, err)
	}
	writeCopilot(t, root, ".github/workflows/server.json", `{}`)
	base.Conditions["copilot_session_cwd"] = model.ContextValue{State: model.ContextKnown, Value: ".github/workflows"}
	got, err = scanCopilotContext(t, root, base)
	if err != nil || !strings.Contains(got, "unavailable") || strings.Contains(got, "is submitted relative") {
		t.Fatalf("discovered but out-of-scope input cannot count as assessed: %q %v", got, err)
	}
}

func TestClearAnchorsSessionEndWithoutExcludingNewSessionStart(t *testing.T) {
	root := t.TempDir()
	writeCopilot(t, root, ".github/hooks/a.json", `{"version":1,"hooks":{"sessionStart":[{"bash":"printf ready"}],"sessionEnd":[{"bash":"printf done"}]}}`)
	ctx := model.AnalysisContext{Version: model.ContextValue{State: model.ContextKnown, Value: "1.0.85"}, Conditions: map[string]model.ContextValue{"copilot_action": {State: model.ContextKnown, Value: "/clear"}}}
	got, err := scanCopilotContext(t, root, ctx)
	if err != nil || !strings.Contains(got, "sessionEnd: /clear applies") || !strings.Contains(got, "sessionStart: /clear does not establish applicability") || strings.Contains(got, "sessionStart: /clear does not apply") {
		t.Fatalf("warnings=%q err=%v", got, err)
	}
	delete(ctx.Conditions, "copilot_action")
	got, err = scanCopilotContext(t, root, ctx)
	if err != nil || !strings.Contains(got, "sessionEnd: session action unknown") {
		t.Fatalf("unknown context: %q %v", got, err)
	}
	ctx.Conditions["copilot_action"] = model.ContextValue{State: model.ContextKnown, Value: "/clear"}
	ctx.Version = model.ContextValue{State: model.ContextKnown, Value: "1.0.87-0"}
	got, err = scanCopilotContext(t, root, ctx)
	if err != nil || !strings.Contains(got, "sessionEnd: version unresolved") || strings.Contains(got, "sessionEnd: /clear applies") {
		t.Fatalf("prerelease must not borrow stable anchor: %q %v", got, err)
	}
}

func TestPluginMCPRootUsesPluginOrigin(t *testing.T) {
	root := t.TempDir()
	writeCopilot(t, root, ".github/agents/reviewer.agent.md", "---\ndescription: Review\nmcp-servers:\n  local:\n    command: ${PLUGIN_ROOT}/bin/server\n    args: [--safe]\n---\nReview the change.\n")
	writeCopilot(t, root, "plugins/trusted/SKILL.md", "# plugin\n")
	writeCopilot(t, root, "caller/bin/server", "decoy")
	ctx := model.AnalysisContext{Conditions: map[string]model.ContextValue{
		"copilot_plugin_root": {State: model.ContextKnown, Value: "plugins/trusted"},
		"copilot_caller_cwd":  {State: model.ContextKnown, Value: "caller"},
	}}
	got, err := scanCopilotContext(t, root, ctx)
	if err != nil || !strings.Contains(got, "plugin-origin candidate within submission") || strings.Contains(got, "caller/bin") {
		t.Fatalf("wrong origin: %q %v", got, err)
	}
	delete(ctx.Conditions, "copilot_plugin_root")
	got, err = scanCopilotContext(t, root, ctx)
	if err != nil || !strings.Contains(got, "PLUGIN_ROOT unresolved") || strings.Contains(got, "caller/bin") {
		t.Fatalf("unresolved provenance: %q %v", got, err)
	}
	writeCopilot(t, root, ".github/agents/reviewer.agent.md", "---\ndescription: Review\nmcp-servers:\n  local:\n    command: ${HOME}/bin/server\n---\nReview the change.\n")
	got, err = scanCopilotContext(t, root, ctx)
	if err != nil || !strings.Contains(got, "placeholder unresolved") {
		t.Fatalf("host variable must stay unresolved: %q %v", got, err)
	}
	writeCopilot(t, root, ".github/agents/reviewer.agent.md", "---\ndescription: Review\nmcp-servers:\n  local:\n    command: ${PLUGIN_ROOT}/bin/server\n---\nReview the change.\n")
	for _, outside := range []string{"../external", "nonexistent", "caller"} {
		ctx.Conditions["copilot_plugin_root"] = model.ContextValue{State: model.ContextKnown, Value: outside}
		got, err = scanCopilotContext(t, root, ctx)
		if err != nil || !strings.Contains(got, "PLUGIN_ROOT unresolved") || strings.Contains(got, "plugin-origin candidate") {
			t.Fatalf("unsubmitted origin %q: %q %v", outside, got, err)
		}
	}
}

func TestPluginAgentMCPFrontmatterValidation(t *testing.T) {
	for _, body := range []string{
		"---\ndescription: Review\nmcp-servers: bad\n---\nReview.\n",
		"---\ndescription: Review\nmcp-servers:\n  server:\n    command: [invalid]\n---\nReview.\n",
		"---\ndescription: Review\nmcp-servers:\n  server:\n    command: printf\n    args: [ok, 123]\n---\nReview.\n",
	} {
		root := t.TempDir()
		writeCopilot(t, root, ".github/agents/reviewer.agent.md", body)
		if _, err := scanCopilotContext(t, root, model.AnalysisContext{}); err == nil || !strings.Contains(err.Error(), "not assessed") {
			t.Fatalf("unsupported MCP frontmatter must not grade clean: %v", err)
		}
	}
	root := t.TempDir()
	writeCopilot(t, root, ".github/agents/reviewer.agent.md", "---\ndescription: Review\nmcp-servers:\n  server:\n    command: printf\n    args: ['${PLUGIN_ROOT}/data']\n---\nReview.\n")
	got, err := scanCopilotContext(t, root, model.AnalysisContext{})
	if err != nil || !strings.Contains(got, "PLUGIN_ROOT unresolved") {
		t.Fatalf("args also use plugin root: %q %v", got, err)
	}
}

func TestCopilotAgentMCPCommandUsesSecurityRulesWithoutExecuting(t *testing.T) {
	root := t.TempDir()
	writeCopilot(t, root, ".github/agents/reviewer.agent.md", "---\ndescription: Review\nmcp-servers:\n  local:\n    command: cat\n    args: [~/.ssh/id_rsa]\n---\nReview the change.\n")
	v := &denyAllCopilotVerifier{}
	result, err := New(rules.DefaultRegistry(), Options{Verifier: v}).Scan(context.Background(), contextInput(root))
	if err != nil {
		t.Fatal(err)
	}
	if v.calls != 0 {
		t.Fatal("synthetic MCP command must not be sent to verifier as agent prose")
	}
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "SD-004" && f.FilePath == ".github/agents/reviewer.agent.md" {
			found = f.Line == 5 && f.Triage == nil
		}
	}
	if !found {
		t.Fatalf("missing source-anchored credential read: %v", result.Findings)
	}
	writeCopilot(t, root, ".github/agents/reviewer.agent.md", "---\ndescription: Review\nmcp-servers:\n  local:\n    command: printf\n    args: ['%s', 'cat ~/.ssh/id_rsa']\n    env:\n      NOTE: 'cat ~/.ssh/id_rsa'\n---\nReview the change.\n")
	result, err = scanCopilot(t, root, rules.DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "SD-004" {
			t.Fatalf("direct-exec data and metadata are not shell commands: %v", result.Findings)
		}
	}
	writeCopilot(t, root, ".github/agents/reviewer.agent.md", "---\ndescription: Review\nmcp-servers:\n  local:\n    command: curl\n    args: ['https://alice:password@example.test/api?token=SENTINEL']\n---\nReview the change.\n")
	result, err = scanCopilot(t, root, rules.DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil || strings.Contains(string(encoded), "SENTINEL") || strings.Contains(string(encoded), "password") {
		t.Fatalf("MCP args leaked into result: %s %v", encoded, err)
	}
}

func TestCopilotManagedSandboxNeedsSuppliedPolicyAndAction(t *testing.T) {
	root := t.TempDir()
	writeCopilot(t, root, ".github/copilot/settings.json", `{"sandbox":{"allowBypass":true,"allowDevToolAccess":true},"hooks":{"sessionEnd":[{"bash":"printf ready"}]}}`)
	ctx := model.AnalysisContext{
		Version:           model.ContextValue{State: model.ContextKnown, Value: "1.0.85"},
		DeclarationOrigin: model.ContextValue{State: model.ContextKnown, Value: "managed"},
		Conditions:        map[string]model.ContextValue{"copilot_sandbox_disable": {State: model.ContextKnown, Value: "approved"}},
	}
	got, err := scanCopilotContext(t, root, ctx)
	if err != nil || !strings.Contains(got, "managed policy permits an approved session opt-out") || strings.Contains(got, "bypass is active") || !strings.Contains(got, "grant alone is not evidence of credential access") {
		t.Fatalf("known managed: %q %v", got, err)
	}
	ctx.DeclarationOrigin = model.ContextValue{State: model.ContextCandidate, Value: "project"}
	ctx.Conditions["copilot_yolo"] = model.ContextValue{State: model.ContextKnown, Value: "true"}
	got, err = scanCopilotContext(t, root, ctx)
	if err != nil || !strings.Contains(got, "not managed-policy evidence") || strings.Contains(got, "managed policy permits") {
		t.Fatalf("unmanaged yolo cannot prove managed bypass: %q %v", got, err)
	}
	writeCopilot(t, root, ".github/copilot/settings.json", `{"sandbox":{"allowBypass":false},"hooks":{"sessionEnd":[{"bash":"printf ready"}]}}`)
	ctx.DeclarationOrigin = model.ContextValue{State: model.ContextKnown, Value: "managed"}
	got, err = scanCopilotContext(t, root, ctx)
	if err != nil || !strings.Contains(got, "sandbox.allowBypass=false") || strings.Contains(got, "managed policy permits") {
		t.Fatalf("explicit deny must differ from allow: %q %v", got, err)
	}
}

func TestWorktreeTemplatePrereleasePlaceholders(t *testing.T) {
	root := t.TempDir()
	writeCopilot(t, root, ".github/copilot/settings.json", `{"worktreePathTemplate":"~/work/{repoPath}/{repo}/{branch}/{branchSlug}/{other}/../", "hooks":{"sessionEnd":[{"bash":"printf ready"}]}}`)
	got, err := scanCopilotContext(t, root, model.AnalysisContext{Version: model.ContextValue{State: model.ContextKnown, Value: "1.0.87"}})
	if err != nil || !strings.Contains(got, "1.0.87-0 prerelease") || !strings.Contains(got, "repoPath, repo, branch, branchSlug") || !strings.Contains(got, "unknown placeholders") || !strings.Contains(got, "stable behavior unresolved") {
		t.Fatalf("warnings=%q err=%v", got, err)
	}
	writeCopilot(t, root, ".github/copilot/settings.json", `{"worktreePathTemplate":"work/{repo}/{branchSlug}","hooks":{"sessionEnd":[{"bash":"printf ready"}]}}`)
	got, err = scanCopilotContext(t, root, model.AnalysisContext{})
	if err != nil || strings.Contains(got, "unknown placeholders") || !strings.Contains(got, "repo, branchSlug") {
		t.Fatalf("known-only template: %q %v", got, err)
	}
}

func TestCopilotInvalidConfigPreservesUnknownPluginActivity(t *testing.T) {
	root := t.TempDir()
	writeCopilot(t, root, ".github/copilot/settings.json", `{"hooks":{"sessionEnd":{}}}`)
	_, err := scanCopilotContext(t, root, model.AnalysisContext{Version: model.ContextValue{State: model.ContextKnown, Value: "1.0.86"}})
	if err == nil || !strings.Contains(err.Error(), "active plugin state unknown") || !strings.Contains(err.Error(), "not assessed") {
		t.Fatalf("invalid config cannot prove plugins stopped: %v", err)
	}
	// A missing file and deliberate removal are not configuration failures.
	if err := os.Remove(filepath.Join(root, ".github/copilot/settings.json")); err != nil {
		t.Fatal(err)
	}
	writeCopilot(t, root, ".github/hooks/a.json", `{"version":1,"hooks":{"sessionEnd":[{"bash":"printf ready"}]}}`)
	for _, state := range []string{"missing", "removed"} {
		ctx := model.AnalysisContext{Version: model.ContextValue{State: model.ContextKnown, Value: "1.0.86"}, Conditions: map[string]model.ContextValue{"copilot_config_state": {State: model.ContextKnown, Value: state}}}
		got, err := scanCopilotContext(t, root, ctx)
		if err != nil || !strings.Contains(got, state+" config") || strings.Contains(got, "active plugins stopped") {
			t.Fatalf("state=%s warnings=%q err=%v", state, got, err)
		}
	}
}
