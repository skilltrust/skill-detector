package rules

import (
	"path/filepath"
	"strings"
)

// File-class predicates used by the new SP-1 rule packs to decide whether
// the file at ctx.Path is one they should inspect. Rules check these inside
// Match() because the existing registry dispatches on extension alone.

var excludedDirs = []string{
	"node_modules/",
	".git/",
	"vendor/",
	"dist/",
	"build/",
	".next/",
	"target/",
}

func isExcluded(path string) bool {
	clean := filepath.ToSlash(path)
	for _, d := range excludedDirs {
		if strings.Contains(clean, "/"+d) || strings.HasPrefix(clean, d) {
			return true
		}
	}
	return false
}

// IsClaudeMD returns true for CLAUDE.md anywhere in the tree except inside
// commonly-excluded dirs.
func IsClaudeMD(path string) bool {
	if isExcluded(path) {
		return false
	}
	return filepath.Base(path) == "CLAUDE.md"
}

// IsClaudeSettings returns true for .claude/settings.json and
// .claude/settings.local.json.
func IsClaudeSettings(path string) bool {
	clean := filepath.ToSlash(path)
	base := filepath.Base(clean)
	if base != "settings.json" && base != "settings.local.json" {
		return false
	}
	return strings.Contains(clean, ".claude/") || strings.HasPrefix(clean, ".claude/")
}

// IsMCPConfig returns true for .mcp.json and .claude/mcp.json.
func IsMCPConfig(path string) bool {
	clean := filepath.ToSlash(path)
	base := filepath.Base(clean)

	// .mcp.json (with leading dot) anywhere
	if base == ".mcp.json" {
		return true
	}

	// mcp.json (without dot) only inside .claude/ directory
	if base == "mcp.json" {
		return strings.Contains(clean, ".claude/mcp.json")
	}

	return false
}

// IsSkillManifest returns true for SKILL.md or skill.yaml — the original
// product scope before SP-1 expanded it.
func IsSkillManifest(path string) bool {
	base := filepath.Base(filepath.ToSlash(path))
	return base == "SKILL.md" || base == "skill.yaml"
}

// IsAgentFile is the union predicate covering every file class the product
// inspects: skill manifests + CLAUDE.md + .claude/settings.json + .mcp.json.
// Use this as the default gate in rules that don't need to discriminate
// between agent file classes.
func IsAgentFile(path string) bool {
	return IsSkillManifest(path) || IsClaudeMD(path) ||
		IsClaudeSettings(path) || IsMCPConfig(path)
}

// isInClaudeOrCodexDir returns true for any path under .claude/, .codex/,
// or .opencode/. Used by rules that inspect arbitrary files in agent
// config dirs (e.g., hook scripts at .claude/scripts/foo.sh).
func isInClaudeOrCodexDir(path string) bool {
	clean := filepath.ToSlash(path)
	for _, d := range []string{".claude/", ".codex/", ".opencode/"} {
		if strings.Contains(clean, "/"+d) || strings.HasPrefix(clean, d) {
			return true
		}
	}
	return false
}
