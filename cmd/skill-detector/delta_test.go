package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeJSON(t *testing.T, path string, body any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDeltaCmd_JSONOutput_HasPerAxis(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.json")
	head := filepath.Join(dir, "head.json")
	writeJSON(t, base, map[string]any{
		"axes":     map[string]any{"security": map[string]string{"grade": "B"}},
		"findings": []any{},
	})
	writeJSON(t, head, map[string]any{
		"axes":     map[string]any{"security": map[string]string{"grade": "A"}},
		"findings": []any{},
	})

	cmd := newRootCmd()
	cmd.SetArgs([]string{"delta", base, head, "--format", "json"})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\nout=%s", err, stdout.String())
	}
	if _, ok := got["per_axis"]; !ok {
		t.Errorf("expected per_axis key; got %v", got)
	}
}

func TestDeltaCmd_MarkdownOutput_HasArrow(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.json")
	head := filepath.Join(dir, "head.json")
	writeJSON(t, base, map[string]any{
		"axes":     map[string]any{"permission_hygiene": map[string]string{"grade": "B"}},
		"findings": []any{},
	})
	writeJSON(t, head, map[string]any{
		"axes":     map[string]any{"permission_hygiene": map[string]string{"grade": "D"}},
		"findings": []any{map[string]any{
			"rule_id":     "SD-014",
			"axis":        "permission_hygiene",
			"file_path":   ".claude/settings.json",
			"line":        42.0,
			"description": "wildcard",
		}},
	})

	cmd := newRootCmd()
	cmd.SetArgs([]string{"delta", base, head, "--format", "markdown"})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("↓ B → D")) {
		t.Errorf("expected downgrade arrow B→D in output; got: %s", stdout.String())
	}
}
