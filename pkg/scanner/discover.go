package scanner

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	stdpath "path"
	"path/filepath"
	"strings"

	ignore "github.com/sabhiram/go-gitignore"
	"github.com/velzepooz/skill-detector/pkg/model"
)

// walkableHiddenDirs lists hidden directories that should still be walked
// despite the general hidden-dir skip. These contain AI-agent configuration
// files (CLAUDE.md, settings.json, MCP configs, per-harness instruction
// files, and per-harness MCP configs) that are core to the skill-detector
// scope. .github and .vscode are walkable so the gated predicates can match
// copilot-instructions.md / mcp.json inside them, but they are deliberately
// NOT agent config dirs (see inAgentDir) — walking .github/workflows/ or the
// rest of .vscode/ must not run every content rule over arbitrary files.
var walkableHiddenDirs = map[string]bool{
	".claude":   true,
	".codex":    true,
	".opencode": true,
	".cursor":   true,
	".gemini":   true,
	".windsurf": true,
	".agents":   true,
	".vscode":   true,
	".github":   true,
}

// alwaysSkipDirs lists directory names always skipped during discovery
// regardless of .gitignore or --scan-all. These are dirs that are never
// the product's scope (build output, vendored deps, VCS metadata).
var alwaysSkipDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	"target":       true,
	".next":        true,
	".git":         true,
}

// scannableExts defines file extensions that are relevant for security scanning.
var scannableExts = map[string]bool{
	".md": true, ".yaml": true, ".yml": true,
	".sh": true, ".bash": true,
	".txt": true, ".json": true, ".toml": true,
	".env": true, ".cfg": true, ".conf": true,
	".ini": true, ".xml": true,
}

// agentDirExtraExts are additionally scanned when the file lives inside an
// agent config dir (.claude/, .codex/, .opencode/, .cursor/, .gemini/,
// .windsurf/, .agents/): script languages, Cursor's rule-file extension, plus
// extensionless hook scripts. Outside those dirs the scannableExts allowlist
// applies unchanged (noise control).
var agentDirExtraExts = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".mjs": true,
	".rb": true, ".pl": true, ".ps1": true, ".zsh": true,
	".mdc": true,
	"":     true,
}

// instructionDotfiles are root-level agent instruction files with no
// conventional extension (filepath.Ext(".cursorrules") returns
// ".cursorrules" itself, which is never in scannableExts). Treated as
// scannable regardless of extension or location.
var instructionDotfiles = map[string]bool{".cursorrules": true, ".windsurfrules": true}

// inAgentDir mirrors pkg/rules' isInAgentConfigDir, which is unexported and
// therefore unreachable from here even though pkg/scanner does import
// pkg/rules (see scanner.go). The invariant that actually holds is the other
// direction: pkg/rules must never import pkg/scanner. Deliberately excludes
// .github/ and .vscode/ — see walkableHiddenDirs.
func inAgentDir(rel string) bool {
	clean := filepath.ToSlash(rel)
	for _, d := range []string{".claude/", ".codex/", ".opencode/", ".cursor/", ".gemini/", ".windsurf/", ".agents/"} {
		if strings.HasPrefix(clean, d) || strings.Contains(clean, "/"+d) {
			return true
		}
	}
	return false
}

// inSkillRootExcludedDir mirrors pkg/rules' inSkillRootExcludedDir (unexported
// there, as isInAgentConfigDir is). .github/ and .vscode/ are walked for their
// specific instruction and MCP files but must not be pulled into scope wholesale
// by a SKILL.md sitting above them — see walkableHiddenDirs and ADR-0010.
func inSkillRootExcludedDir(rel string) bool {
	clean := filepath.ToSlash(rel)
	for _, d := range []string{".github/", ".vscode/"} {
		if strings.HasPrefix(clean, d) || strings.Contains(clean, "/"+d) {
			return true
		}
	}
	return false
}

// DiscoverOptions controls walker behavior.
type DiscoverOptions struct {
	// ScanAll disables .gitignore filtering. Hardcoded skip-dirs
	// (node_modules, .git, etc.) still apply.
	ScanAll bool
}

// DiscoverStats reports counters about the discovery walk that don't belong
// in the file list itself — currently just how many agent-shaped paths were
// skipped because of .gitignore, so callers can warn that the scan may be
// blind to the primary attack surface.
type DiscoverStats struct {
	GitignoredAgentPaths int
}

// Discover walks the root directory and returns scannable files using
// default options (honor .gitignore, skip hardcoded noise dirs).
func Discover(root string) ([]model.FileContext, DiscoverStats, error) {
	return discoverImpl(root, DiscoverOptions{})
}

// DiscoverWithOptions is the option-aware sibling of Discover. Discover()
// remains for callers that want default behavior.
func DiscoverWithOptions(root string, opts DiscoverOptions) ([]model.FileContext, DiscoverStats, error) {
	return discoverImpl(root, opts)
}

// skillManifestName is the marker that makes a directory a skill root. Only
// SKILL.md: skill.yaml is an alternate manifest spelling no harness loads a
// subtree for, and admitting it would widen scope with no measured benefit.
// See ADR-0010.
const skillManifestName = "SKILL.md"

// walkCandidate is a file the walk admitted, held until the skill-root set
// is complete. Content is deliberately NOT read here: the extension gate
// depends on the skill roots, and the roots are only known once the walk
// has finished.
type walkCandidate struct {
	rel  string
	name string
	ext  string
}

// nearestSkillRoot returns the closest ancestor directory of rel that holds
// a SKILL.md, as a slash-separated path relative to the scan root ("." for
// the scan root itself), or "" when rel lies inside no skill root.
func nearestSkillRoot(rel string, roots map[string]bool) string {
	if len(roots) == 0 {
		return ""
	}
	d := stdpath.Dir(filepath.ToSlash(rel))
	for {
		if roots[d] {
			return d
		}
		if d == "." || d == "/" {
			return ""
		}
		parent := stdpath.Dir(d)
		if parent == d {
			return ""
		}
		d = parent
	}
}

func discoverImpl(root string, opts DiscoverOptions) ([]model.FileContext, DiscoverStats, error) {
	root = filepath.Clean(root)

	var stats DiscoverStats

	// Open a scoped root to prevent symlink TOCTOU traversal (gosec G122).
	osRoot, err := os.OpenRoot(root)
	if err != nil {
		return nil, stats, fmt.Errorf("discover: %w", err)
	}
	defer osRoot.Close()

	var ignoreMatcher *ignore.GitIgnore
	if !opts.ScanAll {
		ignoreMatcher, err = loadGitignore(root)
		if err != nil {
			// Don't fail discovery on a broken .gitignore — treat as no-op.
			ignoreMatcher = nil
		}
	}

	var files []model.FileContext
	var candidates []walkCandidate
	// skillRoots holds every directory the walk found a SKILL.md in, keyed
	// by its slash-separated path relative to root ("." for root itself).
	// A SKILL.md the walk never reached — skipped dir, gitignored, hidden —
	// does not create a root, which is what keeps node_modules/ and
	// vendor/ out (ADR-0010).
	skillRoots := make(map[string]bool)

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Permission denied or other walk error on a subdirectory — skip it.
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip hardcoded noise dirs (always, regardless of options).
		if d.IsDir() && path != root && alwaysSkipDirs[d.Name()] {
			return filepath.SkipDir
		}

		// Honor .gitignore (best-effort; missing/broken file = no-op).
		if ignoreMatcher != nil {
			relForIgnore, err := filepath.Rel(root, path)
			if err == nil && relForIgnore != "." {
				matchPath := filepath.ToSlash(relForIgnore)
				if d.IsDir() {
					// go-gitignore's MatchesPath only recognizes a
					// "dirname/"-style pattern against a queried path that
					// itself ends in "/" — a bare directory path (no
					// trailing slash) doesn't match even though the
					// directory is unambiguously ignored. Append the
					// trailing slash so both `dirname` and `dirname/`
					// gitignore syntaxes match the directory node itself
					// (not just files nested inside it), which matters for
					// SkipDir and for counting an empty gitignored agent
					// dir below.
					matchPath += "/"
				}
				if ignoreMatcher.MatchesPath(matchPath) {
					if d.IsDir() {
						// Count against inAgentDir (.claude/.codex/etc.), not
						// walkableHiddenDirs — the latter also contains
						// .vscode/.github, which are walkable for file
						// matching but are NOT agent config dirs. A
						// gitignored .vscode/ (near-universal boilerplate)
						// must not trip the "blind to the primary attack
						// surface" warning.
						if inAgentDir(relForIgnore + "/") {
							stats.GitignoredAgentPaths++
						}
						return filepath.SkipDir
					}
					if isAgentShapedPath(relForIgnore) {
						stats.GitignoredAgentPaths++
					}
					return nil
				}
			}
		}

		// Skip hidden directories (but not the root itself), except for an allowlist
		// of hidden dirs that contain security-relevant config.
		if d.IsDir() && path != root && d.Name()[0] == '.' {
			if !walkableHiddenDirs[d.Name()] {
				return filepath.SkipDir
			}
		}

		// Only process regular files, plus symlinks (a symlink whose target
		// escapes the scoped root errors out in readFromRoot below and is
		// skipped there — see that function's doc comment).
		if !d.Type().IsRegular() && d.Type()&fs.ModeSymlink == 0 {
			return nil
		}

		// Build relative path.
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}

		// Record skill roots as the walk finds them. The extension gate
		// below cannot run yet: WalkDir visits a directory's entries in
		// lexical order, so a subdirectory sorting before "SKILL.md" is
		// walked in full before the manifest beside it is seen. Phase two,
		// after the walk, is the first point at which the root set is
		// complete.
		if d.Name() == skillManifestName {
			skillRoots[stdpath.Dir(filepath.ToSlash(relPath))] = true
		}

		candidates = append(candidates, walkCandidate{
			rel:  relPath,
			name: d.Name(),
			ext:  filepath.Ext(path),
		})

		return nil
	})

	if err != nil {
		return nil, stats, fmt.Errorf("discover: %w", err)
	}

	// Phase two: the skill-root set is complete, so each candidate's scope
	// can be decided. Reads still go through the scoped os.Root, so the
	// TOCTOU and symlink-escape protection is unchanged; candidates are
	// consumed in walk order, so the output order is too.
	for _, c := range candidates {
		skillRoot := nearestSkillRoot(c.rel, skillRoots)
		if skillRoot != "" && inSkillRootExcludedDir(c.rel) {
			skillRoot = ""
		}

		// Root-level instruction dotfiles (.cursorrules, .windsurfrules)
		// have no conventional extension and are always in scope. Inside an
		// agent config dir OR inside a skill root, also scan script
		// languages and extensionless hook scripts.
		if !scannableExts[c.ext] && !instructionDotfiles[c.name] {
			inWideScope := inAgentDir(c.rel) || skillRoot != ""
			if !inWideScope || !agentDirExtraExts[c.ext] {
				continue
			}
		}

		content, err := readFromRoot(osRoot, c.rel)
		if err != nil {
			// Unreadable file — skip silently.
			continue
		}
		if isBinary(content) {
			continue
		}

		files = append(files, model.FileContext{
			Path:      c.rel,
			Ext:       c.ext,
			Content:   content,
			SkillRoot: skillRoot,
		})
	}

	return files, stats, nil
}

// isAgentShapedPath mirrors rules.IsAgentFile for warning purposes only.
func isAgentShapedPath(rel string) bool {
	base := filepath.Base(rel)
	switch base {
	case "SKILL.md", "skill.yaml", "CLAUDE.md", ".mcp.json":
		return true
	case "settings.json", "settings.local.json", "mcp.json":
		return inAgentDir(rel)
	}
	return false
}

// readFromRoot reads file content through the scoped os.Root to avoid TOCTOU
// races. os.Root also refuses to follow a symlink whose target escapes the
// root, so admitting symlinks into the walk above stays traversal-safe: an
// escaping symlink errors here and is skipped by the caller. A symlink whose
// target is also scanned in-tree yields findings on both paths, which is
// acceptable.
func readFromRoot(root *os.Root, relPath string) ([]byte, error) {
	f, err := root.Open(relPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// isBinary checks whether the data appears to be binary by looking for NUL bytes
// in the first 512 bytes.
func isBinary(data []byte) bool {
	checkLen := 512
	if len(data) < checkLen {
		checkLen = len(data)
	}
	for _, b := range data[:checkLen] {
		if b == 0 {
			return true
		}
	}
	return false
}
