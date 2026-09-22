package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/model"
)

func TestCodexBinaryContract(t *testing.T) {
	bin := buildBinaryCVE(t)
	for _, tc := range []struct {
		dir  string
		code int
	}{
		{"clean", 0}, {"malicious", 2},
	} {
		out, code := runBinaryCVE(t, bin, "scan", "--format=json", "--fail-on=high", "../../testdata/"+tc.dir+"/codex-config")
		if code != tc.code {
			t.Fatalf("%s exit=%d, want %d: %s", tc.dir, code, tc.code, out)
		}
		var result model.ScanResult
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatal(err)
		}
		if result.SchemaVersion != model.SchemaVersion || len(result.Warnings) == 0 {
			t.Fatalf("wire compatibility or warning lost: %+v", result)
		}
	}
	// Strict MCP applies to TOML exactly as to JSON, through the existing flag.
	out, code := runBinaryCVE(t, bin, "scan", "--format=json", "--strict-mcp", "../../testdata/malicious/codex-config")
	if code != 1 && code != 2 {
		t.Fatalf("strict MCP exit=%d: %s", code, out)
	}
	var result model.ScanResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	var strict bool
	for _, f := range result.Findings {
		if f.RuleID == "SD-021" {
			strict = f.Severity == model.SeverityHigh && f.Axis == axes.PermissionHygiene
		}
	}
	if !strict {
		t.Fatalf("strict MCP was not applied: %+v", result.Findings)
	}

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"malformed":        "[broken",
		"startup-overflow": "[mcp_servers.local]\ncommand='./local-mcp'\nstartup_timeout_sec=1e100",
		"tool-overflow":    "[mcp_servers.local]\ncommand='./local-mcp'\ntool_timeout_sec=1e100",
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, ".codex", "config.toml"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			out, code := runBinaryCVE(t, bin, "scan", "--format=json", dir)
			if code != 3 || out != "" {
				t.Fatalf("invalid config exit=%d stdout=%q; want 3 and no graded JSON", code, out)
			}
		})
	}
}
