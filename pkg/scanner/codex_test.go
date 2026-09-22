package scanner_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
	"github.com/velzepooz/skill-detector/pkg/rules"
	"github.com/velzepooz/skill-detector/pkg/scanner"
)

func TestCodexFixtures(t *testing.T) {
	s := scanner.New(rules.DefaultRegistry(), scanner.Options{Version: "ST-127-test"})
	for _, tc := range []struct {
		dir string
		ids []string
	}{
		{"clean", nil},
		{"malicious", []string{"SD-007", "SD-021", "SD-024", "SD-026"}},
	} {
		t.Run(tc.dir, func(t *testing.T) {
			r := runScan(t, s, "../../testdata/"+tc.dir+"/codex-config")
			var ids []string
			for _, f := range r.Findings {
				ids = append(ids, f.RuleID)
			}
			slices.Sort(ids)
			if !reflect.DeepEqual(ids, tc.ids) {
				t.Fatalf("IDs = %v, want %v", ids, tc.ids)
			}
			if r.NoAgentSurface || r.Version != "ST-127-test" || r.SchemaVersion != model.SchemaVersion || len(r.Warnings) == 0 {
				t.Fatalf("missing provenance/scope warning: %+v", r)
			}
			want := axes.GradeA
			if tc.dir == "malicious" {
				want = axes.GradeD
			}
			if got := r.Axes[axes.PermissionHygiene].Grade; got != want {
				t.Fatalf("permission_hygiene = %s, want %s", got, want)
			}
		})
	}
}

func TestCodexValidationCannotReturnCleanResult(t *testing.T) {
	for _, content := range []string{"[broken", "approval_policy='future-policy'", "sandbox_mode='future-sandbox'", "[profiles.work.mcp_servers.audit]\ncommand='npx'"} {
		t.Run(content, func(t *testing.T) {
			dir := t.TempDir()
			writeCodexTestFile(t, dir, "AGENTS.md", "Use project tests.")
			writeCodexTestFile(t, dir, ".codex/config.toml", content)
			// Even an empty registry cannot disguise invalid analyzed config.
			s := scanner.New(rules.NewRegistry(), scanner.Options{})
			res, err := s.Scan(context.Background(), dirInput(dir))
			if err == nil || res != nil || !strings.Contains(err.Error(), ".codex/config.toml") {
				t.Fatalf("got result=%+v error=%v; want path-specific error, no grades", res, err)
			}
		})
	}
}

func TestCodexGitignoreAndSourceBoundaries(t *testing.T) {
	dir := t.TempDir()
	writeCodexTestFile(t, dir, "AGENTS.md", "Use project tests.")
	writeCodexTestFile(t, dir, ".gitignore", ".codex/\n")
	writeCodexTestFile(t, dir, ".codex/config.toml", "sandbox_mode='danger-full-access'")
	writeCodexTestFile(t, dir, "nested/.codex/config.toml", "sandbox_mode='read-only'")
	writeCodexTestFile(t, dir, "node_modules/.codex/config.toml", "[malformed")
	writeCodexTestFile(t, dir, "config.toml", "[malformed")
	r := runScan(t, scanner.New(rules.DefaultRegistry(), scanner.Options{}), dir)
	if len(r.Findings) != 0 || !strings.Contains(strings.Join(r.Warnings, "\n"), "gitignored") {
		t.Fatalf("default ignore behavior: %+v", r)
	}
	r = runScan(t, scanner.New(rules.DefaultRegistry(), scanner.Options{ScanAll: true}), dir)
	if len(r.Findings) != 1 || r.Findings[0].RuleID != "SD-026" || r.Findings[0].FilePath != ".codex/config.toml" {
		t.Fatalf("files must not override each other; hard skips must remain: %+v", r)
	}
}

func TestCodexDoesNotExecuteOrReadExternalConfiguration(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	marker := filepath.Join(home, "executed")
	t.Setenv("CODEX_HOME", home)
	// External invalid config must not affect a repository-only scan.
	writeCodexTestFile(t, home, "config.toml", "[malformed")
	content := fmt.Sprintf(`sandbox_mode='workspace-write'
approval_policy='on-request'
[model_providers.bedrock.aws.credential_export]
command='touch'
args=[%q]
[model_providers.bedrock.aws.auth_refresh]
command='touch'
args=[%q]
[mcp_servers.local]
command='touch'
args=[%q]
`, marker, marker, marker)
	writeCodexTestFile(t, dir, ".codex/config.toml", content)
	// Isolate semantic rules: general content rules legitimately inspect the
	// absolute marker paths too, but are not the execution boundary under test.
	reg := rules.NewRegistry()
	rules.RegisterMCPRules(reg)
	rules.RegisterCodexRules(reg)
	r := runScan(t, scanner.New(reg, scanner.Options{}), dir)
	if len(r.Findings) != 0 || len(r.Warnings) != 3 {
		t.Fatalf("expected helper inventory without fabricated threat: %+v", r)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("helper/server executed: %v", err)
	}
}

func writeCodexTestFile(t *testing.T, dir, path, content string) {
	t.Helper()
	full := filepath.Join(dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
