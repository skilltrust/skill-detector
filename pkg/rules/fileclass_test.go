package rules

import "testing"

func TestIsClaudeMD(t *testing.T) {
	cases := map[string]bool{
		"CLAUDE.md":                          true,
		".claude/CLAUDE.md":                  true,
		"subdir/CLAUDE.md":                   true,
		"a/b/c/CLAUDE.md":                    true,
		"node_modules/foo/CLAUDE.md":         false,
		".git/CLAUDE.md":                     false,
		"vendor/x/CLAUDE.md":                 false,
		"README.md":                          false,
		"claude.md":                          false,
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
