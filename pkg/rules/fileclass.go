package rules

import (
	"path/filepath"
	"strings"

	"github.com/velzepooz/skill-detector/pkg/model"
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
// commonly-excluded dirs. Kept exported for API compat; gates that used to
// call this now call IsInstructionFile instead.
func IsClaudeMD(path string) bool {
	if isExcluded(path) {
		return false
	}
	return filepath.Base(path) == "CLAUDE.md"
}

// instructionFileNames are per-harness agent instruction files loaded into
// model context: Claude Code, Codex CLI/OpenCode (AGENTS.md), Gemini CLI,
// Cursor, Windsurf.
var instructionFileNames = map[string]bool{
	"CLAUDE.md": true, "AGENTS.md": true, "GEMINI.md": true,
	".cursorrules": true, ".windsurfrules": true,
}

// IsInstructionFile returns true for any harness's agent-instruction file.
func IsInstructionFile(path string) bool {
	if isExcluded(path) {
		return false
	}
	clean := filepath.ToSlash(path)
	base := filepath.Base(clean)
	if instructionFileNames[base] {
		return true
	}
	if base == "copilot-instructions.md" && hasDirComponent(clean, ".github/") {
		return true
	}
	if strings.HasSuffix(base, ".mdc") && hasDirComponent(clean, ".cursor/rules/") {
		return true
	}
	return false
}

// hasDirComponent reports whether clean has d as a path-boundary-safe
// component — either at the start of the path or immediately after a "/".
// Plain strings.Contains(clean, d) would wrongly match a basename that
// merely contains d as a substring, e.g. "foo.github/x" containing
// ".github/" without an actual .github directory component.
func hasDirComponent(clean, d string) bool {
	return strings.HasPrefix(clean, d) || strings.Contains(clean, "/"+d)
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

// IsMCPConfig returns true for .mcp.json, .claude/mcp.json, .cursor/mcp.json,
// and .vscode/mcp.json.
func IsMCPConfig(path string) bool {
	clean := filepath.ToSlash(path)
	base := filepath.Base(clean)

	// .mcp.json (with leading dot) anywhere
	if base == ".mcp.json" {
		return true
	}

	// mcp.json (without dot) only inside .claude/, .cursor/, or .vscode/
	if base == "mcp.json" {
		for _, d := range []string{".claude/mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"} {
			if strings.Contains(clean, d) {
				return true
			}
		}
		return false
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
// inspects: skill manifests + any harness's instruction file +
// .claude/settings.json + MCP configs.
// Use this as the default gate in rules that don't need to discriminate
// between agent file classes.
func IsAgentFile(path string) bool {
	return IsSkillManifest(path) || IsInstructionFile(path) ||
		IsClaudeSettings(path) || IsMCPConfig(path)
}

// agentConfigDirs are the per-harness directories whose whole subtree is in
// scope. `.agents/` is the install path `npx skills add` writes to and the
// convention third-party skill registries publish for — a skill installed the
// standard way lands there, not under a harness-specific dot-dir.
var agentConfigDirs = []string{
	".claude/", ".codex/", ".opencode/", ".cursor/", ".gemini/", ".windsurf/", ".agents/",
}

// isInAgentConfigDir returns true for any path under .claude/, .codex/,
// .opencode/, .cursor/, .gemini/, .windsurf/, or .agents/. Used by rules that inspect
// arbitrary files in agent config dirs (e.g., hook scripts at
// .claude/scripts/foo.sh). Deliberately excludes .github/ and .vscode/ —
// those dirs are walked for their specific instruction/MCP files (see
// scanner.walkableHiddenDirs) but must not count as agent config dirs, or
// every content rule would run over all of .github/workflows/.
func isInAgentConfigDir(path string) bool {
	clean := filepath.ToSlash(path)
	for _, d := range agentConfigDirs {
		if strings.Contains(clean, "/"+d) || strings.HasPrefix(clean, d) {
			return true
		}
	}
	return false
}

// skillRootExcludedDirs are directories the skill-root arm must not reach.
// They are walked so the gated predicates can match the specific files that
// live in them (copilot-instructions.md, mcp.json), but they are deliberately
// NOT agent config dirs — see isInAgentConfigDir and scanner.walkableHiddenDirs.
// A SKILL.md at a repository root would otherwise pull every CI workflow and
// editor task file into scope, which is the noise ADR-0004 exists to prevent.
// The isInAgentConfigDir arm is unaffected: a .github/ nested inside .claude/
// still reaches the rules through that arm, as it always did.
var skillRootExcludedDirs = []string{".github/", ".vscode/"}

func inSkillRootExcludedDir(path string) bool {
	clean := filepath.ToSlash(path)
	for _, d := range skillRootExcludedDirs {
		if strings.HasPrefix(clean, d) || strings.Contains(clean, "/"+d) {
			return true
		}
	}
	return false
}

// InSkillSubtree reports whether ctx's file lies inside a skill root — a
// directory containing a SKILL.md.
//
// Unlike every other predicate in this file this is NOT a path-shape test.
// Whether some ancestor directory holds a SKILL.md is a filesystem fact and
// cannot be decided from the path string, so the discovery pass computes it
// once per walk and hands it over on FileContext.SkillRoot. See ADR-0010.
//
// The excluded-directory check is repeated here rather than trusted from
// discovery: pkg/rules is a published API and a caller may build a
// FileContext by hand. A vendored skill must not re-enter scope by either
// route. .github/ and .vscode/ are excluded too — see skillRootExcludedDirs.
func InSkillSubtree(ctx model.FileContext) bool {
	return ctx.SkillRoot != "" && !isExcluded(ctx.Path) && !inSkillRootExcludedDir(ctx.Path)
}

// InScope is the standard file-class gate: an agent file by name, any file
// inside an agent config dir, or any file inside a skill root. Rules that
// need a narrower class (SD-002 excludes settings and MCP JSON) compose the
// individual predicates instead.
func InScope(ctx model.FileContext) bool {
	return IsAgentFile(ctx.Path) || isInAgentConfigDir(ctx.Path) || InSkillSubtree(ctx)
}
