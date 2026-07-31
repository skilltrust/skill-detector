package rules

import "testing"

func TestIsClaudeMD(t *testing.T) {
	cases := map[string]bool{
		"CLAUDE.md":                  true,
		".claude/CLAUDE.md":          true,
		"subdir/CLAUDE.md":           true,
		"a/b/c/CLAUDE.md":            true,
		"node_modules/foo/CLAUDE.md": false,
		".git/CLAUDE.md":             false,
		"vendor/x/CLAUDE.md":         false,
		"README.md":                  false,
		"claude.md":                  false,
	}
	for path, want := range cases {
		if got := IsClaudeMD(path); got != want {
			t.Errorf("IsClaudeMD(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIsClaudeSettings(t *testing.T) {
	cases := map[string]bool{
		".claude/settings.json":       true,
		".claude/settings.local.json": true,
		"foo/.claude/settings.json":   true,
		"settings.json":               false,
		".claude/other.json":          false,
	}
	for path, want := range cases {
		if got := IsClaudeSettings(path); got != want {
			t.Errorf("IsClaudeSettings(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIsMCPConfig(t *testing.T) {
	cases := map[string]bool{
		".mcp.json":             true,
		".claude/mcp.json":      true,
		"foo/.mcp.json":         true,
		"mcp.json":              false,
		".claude/settings.json": false,
	}
	for path, want := range cases {
		if got := IsMCPConfig(path); got != want {
			t.Errorf("IsMCPConfig(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIsSkillManifest(t *testing.T) {
	cases := map[string]bool{
		"SKILL.md":                true,
		"skill.yaml":              true,
		"path/to/SKILL.md":        true,
		"path/to/skill.yaml":      true,
		"README.md":               false,
		"settings.yaml":           false,
		"node_modules/x/SKILL.md": true, // predicate is path-shape only; walker handles dir-skipping
	}
	for path, want := range cases {
		if got := IsSkillManifest(path); got != want {
			t.Errorf("IsSkillManifest(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIsAgentFile(t *testing.T) {
	cases := map[string]bool{
		"SKILL.md":                    true,
		"CLAUDE.md":                   true,
		".claude/settings.json":       true,
		".claude/settings.local.json": true,
		".mcp.json":                   true,
		".claude/mcp.json":            true,
		"package.json":                false,
		"README.md":                   false,
		"src/main.ts":                 false,
		"settings.json":               false, // not in .claude/
	}
	for path, want := range cases {
		if got := IsAgentFile(path); got != want {
			t.Errorf("IsAgentFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIsInAgentConfigDir(t *testing.T) {
	cases := map[string]bool{
		".claude/scripts/foo.sh":   true,
		".codex/lib/x.sh":          true,
		".opencode/util.sh":        true,
		".cursor/rules/style.mdc":  true,
		".gemini/hooks/pre.sh":     true,
		".windsurf/scripts/x.sh":   true,
		"a/b/.claude/x.sh":         true,
		"src/main.ts":              false,
		"claude/something.md":      false, // no leading dot
		".github/workflows/ci.yml": false, // must NOT count as agent config dir
		".vscode/mcp.json":         false, // must NOT count as agent config dir
	}
	for path, want := range cases {
		if got := isInAgentConfigDir(path); got != want {
			t.Errorf("isInAgentConfigDir(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIsInstructionFile_MultiHarness(t *testing.T) {
	yes := []string{
		"CLAUDE.md", "sub/CLAUDE.md", "AGENTS.md", "pkg/AGENTS.md", "GEMINI.md",
		".cursorrules", ".windsurfrules",
		".github/copilot-instructions.md", ".cursor/rules/style.mdc",
	}
	no := []string{
		"README.md", "docs/agents.md", "node_modules/x/AGENTS.md", "style.mdc",
	}
	for _, p := range yes {
		if !IsInstructionFile(p) {
			t.Errorf("IsInstructionFile(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if IsInstructionFile(p) {
			t.Errorf("IsInstructionFile(%q) = true, want false", p)
		}
	}
}

func TestIsMCPConfig_OtherHarnessLocations(t *testing.T) {
	for _, p := range []string{".cursor/mcp.json", ".vscode/mcp.json"} {
		if !IsMCPConfig(p) {
			t.Errorf("IsMCPConfig(%q) = false, want true", p)
		}
	}
}
