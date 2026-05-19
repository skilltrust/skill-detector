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
