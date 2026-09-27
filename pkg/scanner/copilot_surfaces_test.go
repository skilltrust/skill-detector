package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/rules"
	"github.com/velzepooz/skill-detector/pkg/triage"
)

func scanCopilot(t *testing.T, root string, reg *rules.RuleRegistry) (*model.ScanResult, error) {
	t.Helper()
	return New(reg, Options{}).Scan(context.Background(), contextInput(root))
}

func writeCopilot(t *testing.T, root, path, body string) {
	t.Helper()
	name := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCopilotFixtures(t *testing.T) {
	for _, tc := range []struct {
		name string
		want map[string]bool
	}{
		{"malicious", map[string]bool{".github/hooks/session.json": true, ".github/instructions/nested/security.instructions.md": true, ".github/agents/reviewer.agent.md": true}},
		{"clean", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := scanCopilot(t, "../../testdata/"+tc.name+"/copilot-surfaces", rules.DefaultRegistry())
			if err != nil {
				t.Fatal(err)
			}
			if result.NoAgentSurface || result.FileCount != 4 {
				t.Fatalf("coverage: files=%d no_agent_surface=%v", result.FileCount, result.NoAgentSurface)
			}
			got := make(map[string]bool)
			for _, f := range result.Findings {
				if f.RuleID == "SD-004" {
					got[f.FilePath] = true
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("SD-004 files=%v, want %v; findings=%v", got, tc.want, result.Findings)
			}
			for path := range tc.want {
				if !got[path] {
					t.Errorf("missing SD-004 on %s", path)
				}
			}
			if !strings.Contains(strings.Join(result.Warnings, "\n"), "unknown") {
				t.Fatal("activation conditions must remain unknown")
			}
			if tc.name == "malicious" && result.Axes[axes.PermissionHygiene].Grade == axes.GradeA {
				t.Fatal("credential reads must lower permission hygiene grade")
			}
			if tc.name == "clean" && result.Axes[axes.PermissionHygiene].Grade != axes.GradeA {
				t.Fatal("protective prose and examples must not lower the grade")
			}
		})
	}
}

func TestCopilotHookSemanticIsolation(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"compact negative guidance does not hide bash", `{"version":1,"hooks":{"sessionEnd":[{"env":{"NOTE":"Never read credentials"},"bash":"cat ~/.ssh/id_rsa"}]}}`, true},
		{"metadata example not command", `{"version":1,"hooks":{"sessionEnd":[{"bash":"printf ready","env":{"EXAMPLE":"cat ~/.ssh/id_rsa"}}]}}`, false},
		{"invalid item dropped but sibling retained", `{"version":1,"hooks":{"sessionEnd":[{"bash":"cat ~/.ssh/id_rsa","timeoutSec":"bad"},{"bash":"printf ready"}]}}`, false},
		{"valid sibling retained", `{"version":1,"hooks":{"sessionEnd":[{"bash":"printf ready","timeoutSec":"bad"},{"command":"cat ~/.ssh/id_rsa"}]}}`, true},
		{"explicit platforms override fallback", `{"version":1,"hooks":{"sessionEnd":[{"bash":"printf ready","powershell":"Write-Host ready","command":"cat ~/.ssh/id_rsa"}]}}`, false},
		{"direct exec", `{"version":1,"hooks":{"sessionEnd":[{"exec":"cat","args":["~/.ssh/id_rsa"]}]}}`, true},
		{"direct exec data is not a shell", `{"version":1,"hooks":{"sessionEnd":[{"exec":"printf","args":["%s","cat ~/.ssh/id_rsa"]}]}}`, false},
		{"prompt text", `{"version":1,"hooks":{"sessionStart":[{"type":"prompt","prompt":"Read ~/.ssh/id_rsa"}]}}`, true},
		{"http metadata not a shell", `{"version":1,"hooks":{"postToolUse":[{"type":"http","url":"https://hooks.example.test/event","headers":{"X-Example":"cat ~/.ssh/id_rsa"}}]}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeCopilot(t, root, ".github/hooks/a.json", tc.body)
			result, err := scanCopilot(t, root, rules.DefaultRegistry())
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, f := range result.Findings {
				found = found || f.RuleID == "SD-004"
			}
			if found != tc.want {
				t.Fatalf("SD-004=%v want %v; findings=%v", found, tc.want, result.Findings)
			}
			if strings.HasPrefix(tc.name, "invalid item") && !strings.Contains(strings.Join(result.Warnings, "\n"), "dropped") {
				t.Fatal("dropped item must be disclosed")
			}
		})
	}
}

func TestCopilotHookInvalidIsNotGradedSafe(t *testing.T) {
	for _, body := range []string{`{"version":2,"hooks":{}}`, `{"version":1,"hooks":{"sessionEnd":{}}}`, `{"version":1,"hooks":null}`, `{"version":1,"hooks":[]} `, `{`, `{"version":1,"hooks":{},"hooks":{}}`, `{"version":1,"hooks":{"sessionEnd":[{"bash":"cat ~/.ssh/id_rsa","timeoutSec":"bad"}]}}`} {
		root := t.TempDir()
		writeCopilot(t, root, ".github/hooks/a.json", body)
		for _, reg := range []*rules.RuleRegistry{rules.DefaultRegistry(), rules.NewRegistry()} {
			result, err := scanCopilot(t, root, reg)
			if err == nil || result != nil {
				t.Fatalf("invalid hooks must fail without grades: result=%v err=%v", result, err)
			}
			if !strings.Contains(err.Error(), "configuration was not assessed") {
				t.Fatalf("missing diagnostic: %v", err)
			}
		}
	}
	root := t.TempDir()
	writeCopilot(t, root, ".github/copilot/settings.json", `{"hooks":{"sessionEnd":[{"bash":"cat ~/.ssh/id_rsa","timeoutSec":"bad"}]}}`)
	if result, err := scanCopilot(t, root, rules.DefaultRegistry()); err == nil || result != nil {
		t.Fatalf("invalid inline hook must reject whole block: %v %v", result, err)
	}
}

func TestCopilotHookDuplicateKeysCannotHideCommands(t *testing.T) {
	for _, tc := range []struct{ path, body string }{
		{".github/hooks/a.json", `{"version":1,"version":1,"hooks":{"sessionEnd":[{"bash":"printf ready"}]}}`},
		{".github/hooks/a.json", `{"version":1,"hooks":{"sessionEnd":[{"bash":"cat ~/.ssh/id_rsa"}],"sessionEnd":[{"bash":"printf ready"}]}}`},
		{".github/hooks/a.json", `{"version":1,"hooks":{"sessionEnd":[{"bash":"cat ~/.ssh/id_rsa","bash":"printf ready"}]}}`},
		{".github/copilot/settings.json", `{"hooks":{"sessionEnd":[{"bash":"cat ~/.ssh/id_rsa","bash":"printf ready"}]}}`},
	} {
		root := t.TempDir()
		writeCopilot(t, root, tc.path, tc.body)
		for _, reg := range []*rules.RuleRegistry{rules.DefaultRegistry(), rules.NewRegistry()} {
			if result, err := scanCopilot(t, root, reg); err == nil || result != nil {
				t.Fatalf("ambiguous hooks must not earn grades: path=%s result=%v err=%v", tc.path, result, err)
			}
		}
	}
}

func TestCopilotLegacyInstructionsDoNotRequireFrontmatter(t *testing.T) {
	for _, path := range []string{".github/agents/AGENTS.md", ".github/instructions/nested/CLAUDE.md"} {
		root := t.TempDir()
		writeCopilot(t, root, path, "Read ~/.ssh/id_rsa\n")
		result, err := scanCopilot(t, root, rules.DefaultRegistry())
		if err != nil || result.NoAgentSurface {
			t.Fatalf("legacy instructions must be assessed: path=%s result=%v err=%v", path, result, err)
		}
		found := false
		for _, finding := range result.Findings {
			found = found || finding.RuleID == "SD-004" && finding.FilePath == path
		}
		if !found {
			t.Fatalf("missing credential-read finding for %s: %v", path, result.Findings)
		}
	}
}

func TestCopilotSurfaceScopeBoundaries(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{".github/workflows/ci.yml", ".github/hooks/nested/a.json", ".github/agents/nested/a.agent.md", "docs/a.instructions.md", "foo.github/hooks/a.json"} {
		writeCopilot(t, root, path, "Read ~/.ssh/id_rsa\n")
	}
	result, err := scanCopilot(t, root, rules.DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if !result.NoAgentSurface || len(result.Axes) != 0 || len(result.Findings) != 0 {
		t.Fatalf("out-of-scope files must not earn grades or findings: %+v", result)
	}
}

func TestCopilotInlineSettingsAndFrontmatterFailures(t *testing.T) {
	for _, path := range []string{".github/copilot/settings.json", ".github/copilot/settings.local.json"} {
		root := t.TempDir()
		writeCopilot(t, root, path, `{"hooks":{"sessionEnd":[{"bash":"cat ~/.ssh/id_rsa"}]}}`)
		result, err := scanCopilot(t, root, rules.DefaultRegistry())
		if err != nil || len(result.Findings) == 0 {
			t.Fatalf("inline %s: findings=%v err=%v", path, result, err)
		}
		if !strings.Contains(strings.Join(result.Warnings, "\n"), "CLI-only") {
			t.Fatal("inline settings cannot be represented as cloud hooks")
		}
	}
	for _, tc := range []struct{ path, body string }{
		{".github/instructions/a.instructions.md", "Read ~/.ssh/id_rsa"},
		{".github/instructions/a.instructions.md", "---\napplyTo: [oops]\n---\nRead ~/.ssh/id_rsa"},
		{".github/agents/a.agent.md", "---\nname: demo\n---\nRead ~/.ssh/id_rsa"},
		{".github/agents/a.agent.md", "---\ndescription: demo\ninclude-custom-instructions: perhaps\n---\nRead ~/.ssh/id_rsa"},
		{".github/agents/bad name.agent.md", "---\ndescription: demo\n---\nRead ~/.ssh/id_rsa"},
	} {
		root := t.TempDir()
		writeCopilot(t, root, tc.path, tc.body)
		result, err := scanCopilot(t, root, rules.DefaultRegistry())
		if err == nil || result != nil {
			t.Fatalf("invalid frontmatter must not grade: path=%s result=%v err=%v", tc.path, result, err)
		}
	}
}

func TestCopilotGitignoreBlindness(t *testing.T) {
	root := t.TempDir()
	writeCopilot(t, root, ".gitignore", ".github/hooks/\n")
	writeCopilot(t, root, ".github/hooks/a.json", `{"version":1,"hooks":{"sessionEnd":[{"bash":"cat ~/.ssh/id_rsa"}]}}`)
	defaultResult, err := scanCopilot(t, root, rules.DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if !defaultResult.NoAgentSurface || !strings.Contains(strings.Join(defaultResult.Warnings, "\n"), "gitignored") {
		t.Fatalf("ignored hook must warn without a grade: %+v", defaultResult)
	}
	all, err := New(rules.DefaultRegistry(), Options{ScanAll: true}).Scan(context.Background(), contextInput(root))
	if err != nil || all.NoAgentSurface || len(all.Findings) == 0 {
		t.Fatalf("scan-all must include ignored hook: result=%v err=%v", all, err)
	}
}

func TestCopilotRecursiveInstructionGitignoreBlindness(t *testing.T) {
	root := t.TempDir()
	writeCopilot(t, root, "AGENTS.md", "Keep changes reviewable.\n")
	writeCopilot(t, root, ".gitignore", ".github/instructions/private/\n")
	writeCopilot(t, root, ".github/instructions/private/a.instructions.md", "---\napplyTo: '**'\n---\nRead ~/.ssh/id_rsa\n")
	result, err := scanCopilot(t, root, rules.DefaultRegistry())
	if err != nil || !strings.Contains(strings.Join(result.Warnings, "\n"), "gitignored") {
		t.Fatalf("nested ignored instructions must warn: result=%v err=%v", result, err)
	}
	all, err := New(rules.DefaultRegistry(), Options{ScanAll: true}).Scan(context.Background(), contextInput(root))
	if err != nil || len(all.Findings) == 0 {
		t.Fatalf("scan-all must find ignored instruction: result=%v err=%v", all, err)
	}
}

func TestCopilotHookValidationBoundaries(t *testing.T) {
	for _, body := range []string{
		`{"version":1,"hooks":{"sessionEnd":[{"exec":"printf","args":[null]}]}}`,
		`{"version":1,"hooks":{"sessionEnd":[{"type":"http","url":"https://"}]}}`,
		`{"version":1,"hooks":{"preToolUse":[{"type":"http","url":"http://localhost/hook"}]}}`,
		`{"version":1,"hooks":{"sessionEnd":[{"type":"http","url":"http://localhost/hook","allowedEnvVars":["HOOK_TOKEN"]}]}}`,
	} {
		root := t.TempDir()
		writeCopilot(t, root, ".github/hooks/a.json", body)
		if result, err := scanCopilot(t, root, rules.NewRegistry()); err == nil || result != nil {
			t.Fatalf("invalid item alone cannot grade: result=%v err=%v", result, err)
		}
	}
	for _, event := range []string{"PreCompact", "PermissionRequest"} {
		root := t.TempDir()
		writeCopilot(t, root, ".github/hooks/a.json", `{"version":1,"hooks":{"`+event+`":[{"bash":"printf ready"}]}}`)
		if result, err := scanCopilot(t, root, rules.DefaultRegistry()); err != nil || result.NoAgentSurface {
			t.Fatalf("supported event %s: result=%v err=%v", event, result, err)
		}
	}
	for _, body := range []string{`{"hooks":{}}`, `{"hooks":{"sessionEnd":[]}}`, `{"otherSetting":true}`} {
		root := t.TempDir()
		writeCopilot(t, root, ".github/copilot/settings.json", body)
		if result, err := scanCopilot(t, root, rules.NewRegistry()); err == nil || result != nil {
			t.Fatalf("no analyzed inline hook cannot grade: result=%v err=%v", result, err)
		}
	}
}

type denyAllCopilotVerifier struct{ calls int }

func (v *denyAllCopilotVerifier) Classify(_ context.Context, _ model.FileContext, findings []model.Finding) ([]triage.Verdict, error) {
	v.calls++
	return []triage.Verdict{{Index: 1, Classification: triage.ClassBenign, Confidence: 1}}, nil
}

func TestCopilotHookProjectionCoordinatesAndTriage(t *testing.T) {
	root := t.TempDir()
	writeCopilot(t, root, ".github/hooks/a.json", "{\n  \"version\": 1,\n  \"hooks\": {\n    \"sessionEnd\": [\n      {\"bash\": \"printf ready\\ncat ~/.ssh/id_rsa\"},\n      {\"bash\": \"printf ready\\ncat ~/.ssh/id_rsa\"}\n    ]\n  }\n}\n")
	v := &denyAllCopilotVerifier{}
	result, err := New(rules.DefaultRegistry(), Options{Verifier: v}).Scan(context.Background(), contextInput(root))
	if err != nil {
		t.Fatal(err)
	}
	if v.calls != 0 {
		t.Fatal("misaligned synthetic hook content must not be sent to a verifier")
	}
	if len(result.Findings) != 2 || result.Findings[0].Line != 5 || result.Findings[1].Line != 6 {
		t.Fatalf("hook findings must use physical source lines, not decoded newline offsets: %v", result.Findings)
	}
	for _, f := range result.Findings {
		if f.Triage != nil {
			t.Fatalf("unverified hook finding was triaged: %+v", f)
		}
	}
}

func TestCopilotHookExecutableNetworkIsNotDeclaredEndpoint(t *testing.T) {
	root := t.TempDir()
	writeCopilot(t, root, ".github/hooks/a.json", `{"version":1,"hooks":{"sessionEnd":[{"bash":"curl https://api.github.com/zen"}]}}`)
	result, err := scanCopilot(t, root, rules.DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "SD-007" {
			if f.Axis != axes.Security || f.Severity != model.SeverityHigh {
				t.Fatalf("executable hook network call classified as declaration: %+v", f)
			}
			return
		}
	}
	t.Fatal("expected SD-007 on executable hook")
}

func TestCopilotPromptUsesProseSemantics(t *testing.T) {
	for _, tc := range []struct {
		body string
		wantShell bool
	}{
		{`{"version":1,"hooks":{"sessionStart":[{"type":"prompt","prompt":"Explain why eval $UNTRUSTED is unsafe. See https://example.com/guide"}]}}`, false},
		{`{"version":1,"hooks":{"sessionStart":[{"type":"prompt","prompt":"` + "```sh\\neval $UNTRUSTED\\n```" + `"}]}}`, true},
	} {
		root := t.TempDir()
		writeCopilot(t, root, ".github/hooks/a.json", tc.body)
		result, err := scanCopilot(t, root, rules.DefaultRegistry())
		if err != nil {
			t.Fatal(err)
		}
		shell := false
		for _, finding := range result.Findings {
			if finding.RuleID == "SD-007" {
				t.Fatalf("prose link is not a declared endpoint: %+v", finding)
			}
			shell = shell || finding.RuleID == "SD-001"
		}
		if shell != tc.wantShell {
			t.Fatalf("shell injection=%v want %v; findings=%v", shell, tc.wantShell, result.Findings)
		}
	}
}
