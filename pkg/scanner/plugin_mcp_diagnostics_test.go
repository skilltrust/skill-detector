package scanner_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/rules"
	"github.com/velzepooz/skill-detector/pkg/scanner"
)

func TestPluginMCPDiagnosticsSurviveFullScannerPath(t *testing.T) {
	s := scanner.New(rules.NewRegistry(), scanner.Options{Version: "test"})
	for _, tc := range []struct {
		dir          string
		want, absent []string
	}{
		{"malicious", []string{"strictKnownMarketplaces is entry validity unknown", "blockedMarketplaces is empty", "deny wins", "missing installed commit", "unsupported installed commit format", "npm pack --ignore-scripts", "command and arguments withheld", "Compatibility declaration only", "submitted managed-mcp.json", "omitClaudeMd=true", "a CLAUDE.md was also supplied", "task-reference candidate", "topology is unknown"}, []string{"synthetic-token", "auto-installs and executes"}},
		{"clean", []string{"strictKnownMarketplaces is empty", "blockedMarketplaces is populated", "evidenced installed commit", "no CLAUDE.md was supplied"}, []string{"omitClaudeMd=true", "npm pack --ignore-scripts", "Compatibility declaration only"}},
	} {
		result, err := s.Scan(context.Background(), dirInput(filepath.Join("../../testdata", tc.dir, "claude-plugin-mcp-context")))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		got := string(encoded)
		for _, want := range tc.want {
			if !strings.Contains(got, want) {
				t.Errorf("%s missing %q from serialized result", tc.dir, want)
			}
		}
		for _, absent := range tc.absent {
			if strings.Contains(got, absent) {
				t.Errorf("%s leaked/incorrectly asserted %q", tc.dir, absent)
			}
		}
		if len(result.Findings) != 0 {
			t.Errorf("%s should have no findings with empty registry, got %d", tc.dir, len(result.Findings))
		}
	}
}

func TestSDKMCPHasNoExecutingServerFindingInDefaultRegistry(t *testing.T) {
	s := scanner.New(rules.DefaultRegistry(), scanner.Options{})
	result, err := s.Scan(context.Background(), dirInput("../../testdata/malicious/claude-plugin-mcp-context"))
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range result.Findings {
		if finding.FilePath == ".claude/managed-mcp.json" && (finding.RuleID == "SD-021" || finding.RuleID == "SD-024") {
			t.Fatalf("SDK entry treated as active server: %+v", finding)
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "synthetic-token") {
		t.Fatal("credential/install argument leaked from full scan")
	}
}

func TestUnreadableManagedMCPDoesNotReturnClean(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Escaping symlinks are deliberately not followed by os.Root; even a
	// clean sibling cannot turn an unreadable submitted policy into a pass.
	if err := os.Symlink("/nonexistent/synthetic-managed-policy.json", filepath.Join(dir, ".claude", "managed-mcp.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte("Inert instruction\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := scanner.New(rules.DefaultRegistry(), scanner.Options{})
	result, err := s.Scan(context.Background(), dirInput(dir))
	if err == nil || result != nil || !strings.Contains(err.Error(), "managed MCP policy") {
		t.Fatalf("result=%v err=%v", result, err)
	}
	if err := os.Remove(filepath.Join(dir, ".claude", "managed-mcp.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".claude", "managed-mcp.json"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err = s.Scan(context.Background(), dirInput(dir))
	if err == nil || result != nil || !strings.Contains(err.Error(), "managed MCP policy is malformed") {
		t.Fatalf("malformed result=%v err=%v", result, err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".claude", "managed-mcp.json"), []byte(`{"mcpServers":null}`), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err = s.Scan(context.Background(), dirInput(dir))
	if err == nil || result != nil || !strings.Contains(err.Error(), "missing mcpServers") {
		t.Fatalf("invalid shape result=%v err=%v", result, err)
	}
	for _, content := range []string{
		`{"mcpServers":{"demo":{"command":"npx"},"demo":{"type":"sdk"}}}`,
		`{"mcpServers":{"demo":{"type":"sdk","type":"stdio"}}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, ".claude", "managed-mcp.json"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		result, err = s.Scan(context.Background(), dirInput(dir))
		if err == nil || result != nil || !strings.Contains(err.Error(), "ambiguous JSON members") {
			t.Fatalf("duplicate server result=%v err=%v", result, err)
		}
	}
}
