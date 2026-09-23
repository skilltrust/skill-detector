package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/rules"
)

type contextInput string

func (i contextInput) Path() string { return string(i) }

type contextCaptureRule struct {
	seen []model.AnalysisContext
}

func (r *contextCaptureRule) ID() string               { return "TEST-CONTEXT" }
func (r *contextCaptureRule) Name() string             { return "context capture" }
func (r *contextCaptureRule) Severity() model.Severity { return model.SeverityInfo }
func (r *contextCaptureRule) Category() string         { return "Test" }
func (r *contextCaptureRule) FileTypes() []string      { return []string{".json"} }
func (r *contextCaptureRule) Axis() axes.Axis          { return axes.Transparency }
func (r *contextCaptureRule) Match(_ []byte, ctx model.FileContext) []model.Finding {
	r.seen = append(r.seen, ctx.Analysis)
	return nil
}

func TestScanRepositoryCannotSelfCertifyContext(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	content := `{"harness":"other","version":"9.9","provider":"claimed","trust":"trusted","session":"active"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	capture := &contextCaptureRule{}
	reg := rules.NewRegistry()
	reg.Register(capture)
	if _, err := New(reg, Options{}).Scan(context.Background(), contextInput(root)); err != nil {
		t.Fatal(err)
	}
	if len(capture.seen) != 1 {
		t.Fatalf("contexts = %d, want 1", len(capture.seen))
	}
	got := capture.seen[0]
	if got.Harness.State != model.ContextCandidate || got.Harness.Value != "claude-code" ||
		got.Harness.Evidence != ".claude/settings.json" {
		t.Fatalf("harness = %+v, want path candidate", got.Harness)
	}
	if got.DeclarationOrigin.State != model.ContextCandidate || got.DeclarationOrigin.Value != "project" {
		t.Fatalf("origin = %+v, want project candidate", got.DeclarationOrigin)
	}
	for name, value := range map[string]model.ContextValue{
		"version": got.Version, "provider": got.Provider, "trust": got.Trust, "session": got.Session,
	} {
		if value.State != model.ContextUnknown || value.Value != "" || value.Evidence != "" {
			t.Errorf("%s = %+v, repository content must not establish it", name, value)
		}
	}
}

func TestRunPropagatesSuppliedContextWithoutPathOverride(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".claude", "settings.local.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	want := model.AnalysisContext{
		Harness:           model.ContextValue{State: model.ContextKnown, Value: "test-harness", Evidence: "test input"},
		Version:           model.ContextValue{State: model.ContextKnown, Value: "1.2.3", Evidence: "test input"},
		Provider:          model.ContextValue{State: model.ContextKnown, Value: "test-provider", Evidence: "test input"},
		DeclarationOrigin: model.ContextValue{State: model.ContextKnown, Value: "managed", Evidence: "test input"},
		Trust:             model.ContextValue{State: model.ContextKnown, Value: "untrusted", Evidence: "test input"},
		Session:           model.ContextValue{State: model.ContextUnavailable, Evidence: "test input"},
		Conditions: map[string]model.ContextValue{
			"single_repository": {State: model.ContextKnown, Value: "true", Evidence: "test input"},
		},
	}
	capture := &contextCaptureRule{}
	reg := rules.NewRegistry()
	reg.Register(capture)
	if _, err := New(reg, Options{}).run(context.Background(), root, want); err != nil {
		t.Fatal(err)
	}
	if len(capture.seen) != 1 {
		t.Fatalf("contexts = %d, want 1", len(capture.seen))
	}
	got := capture.seen[0]
	if got.Harness != want.Harness || got.Version != want.Version || got.Provider != want.Provider ||
		got.DeclarationOrigin != want.DeclarationOrigin || got.Trust != want.Trust || got.Session != want.Session ||
		got.Conditions["single_repository"] != want.Conditions["single_repository"] {
		t.Fatalf("context changed: got %+v, want %+v", got, want)
	}
}

func TestFileAnalysisContextCandidates(t *testing.T) {
	for _, tc := range []struct {
		path, harness, origin string
	}{
		{".codex/config.toml", "codex", "project"},
		{".claude/settings.json", "claude-code", "project"},
		{"nested/.claude/settings.local.json", "claude-code", "project-local"},
		{".mcp.json", "", "project"},
		{"AGENTS.md", "", ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			got := fileAnalysisContext(model.AnalysisContext{}, tc.path)
			if got.Harness.Value != tc.harness || got.DeclarationOrigin.Value != tc.origin {
				t.Fatalf("got harness=%+v origin=%+v", got.Harness, got.DeclarationOrigin)
			}
			if tc.harness == "" && got.Harness.State != model.ContextUnknown {
				t.Fatalf("harness = %+v, want unknown", got.Harness)
			}
			if tc.origin == "" && got.DeclarationOrigin.State != model.ContextUnknown {
				t.Fatalf("origin = %+v, want unknown", got.DeclarationOrigin)
			}
		})
	}
}
