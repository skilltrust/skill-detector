package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTree materialises a path->content map under a fresh temp dir.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for p, c := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// discovered maps slash-separated relative path -> SkillRoot.
func discovered(t *testing.T, dir string) map[string]string {
	t.Helper()
	files, _, err := DiscoverWithOptions(dir, DiscoverOptions{})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	out := make(map[string]string, len(files))
	for _, f := range files {
		out[filepath.ToSlash(f.Path)] = f.SkillRoot
	}
	return out
}

// A SKILL.md at the scan root makes the whole tree a skill subtree, and a
// script beside it becomes discoverable — the raw-layout gap this whole
// change exists to close.
func TestDiscover_SkillRootAtScanRoot(t *testing.T) {
	got := discovered(t, writeTree(t, map[string]string{
		"SKILL.md":               "---\nname: demo\n---\nRun the helper.\n",
		"scripts/payload.py":     "import os\n",
		"scripts/nested/deep.py": "import os\n",
	}))

	for _, p := range []string{"SKILL.md", "scripts/payload.py", "scripts/nested/deep.py"} {
		root, ok := got[p]
		if !ok {
			t.Fatalf("%s was not discovered; got %v", p, got)
		}
		if root != "." {
			t.Errorf("%s: SkillRoot = %q, want %q", p, root, ".")
		}
	}
}

// A skill nested at depth roots its own subtree, and each SKILL.md scopes
// only its own — the nearest ancestor wins.
func TestDiscover_NestedSkillRootsScopeIndependently(t *testing.T) {
	got := discovered(t, writeTree(t, map[string]string{
		"CLAUDE.md":                       "# repo\n",
		"skills/alpha/SKILL.md":           "---\nname: alpha\n---\n",
		"skills/alpha/scripts/a.py":       "import os\n",
		"skills/beta/SKILL.md":            "---\nname: beta\n---\n",
		"skills/beta/lib/deep/b.py":       "import os\n",
		"skills/alpha/inner/SKILL.md":     "---\nname: inner\n---\n",
		"skills/alpha/inner/scripts/c.py": "import os\n",
	}))

	want := map[string]string{
		"CLAUDE.md":                       "",
		"skills/alpha/SKILL.md":           "skills/alpha",
		"skills/alpha/scripts/a.py":       "skills/alpha",
		"skills/beta/SKILL.md":            "skills/beta",
		"skills/beta/lib/deep/b.py":       "skills/beta",
		"skills/alpha/inner/SKILL.md":     "skills/alpha/inner",
		"skills/alpha/inner/scripts/c.py": "skills/alpha/inner",
	}
	for p, w := range want {
		root, ok := got[p]
		if !ok {
			t.Fatalf("%s was not discovered; got %v", p, got)
		}
		if root != w {
			t.Errorf("%s: SkillRoot = %q, want %q", p, root, w)
		}
	}
}

// A directory that is NOT a skill root stays out of scope: its scripts are
// not discovered at all, and its scannable files carry no SkillRoot.
func TestDiscover_NonSkillDirectoryStaysOut(t *testing.T) {
	got := discovered(t, writeTree(t, map[string]string{
		"CLAUDE.md":        "# repo\n",
		"tools/payload.py": "import os\n",
		"tools/notes.md":   "# notes\n",
	}))

	if _, ok := got["tools/payload.py"]; ok {
		t.Errorf("tools/payload.py must not be discovered — no SKILL.md makes tools/ a skill root")
	}
	if root, ok := got["tools/notes.md"]; !ok {
		t.Error("tools/notes.md should still be discovered (.md is scannable everywhere)")
	} else if root != "" {
		t.Errorf("tools/notes.md: SkillRoot = %q, want \"\"", root)
	}
}

// A vendored skill must not re-enter scope through the new rule. The
// hardcoded skip list sits above it.
func TestDiscover_VendoredSkillRootsStayExcluded(t *testing.T) {
	got := discovered(t, writeTree(t, map[string]string{
		"SKILL.md":                             "---\nname: demo\n---\n",
		"node_modules/evil/SKILL.md":           "---\nname: evil\n---\n",
		"node_modules/evil/scripts/payload.py": "import os\n",
		"vendor/evil/SKILL.md":                 "---\nname: evil\n---\n",
		"vendor/evil/scripts/payload.py":       "import os\n",
		"dist/evil/SKILL.md":                   "---\nname: evil\n---\n",
		"dist/evil/scripts/payload.py":         "import os\n",
	}))

	for p := range got {
		for _, banned := range []string{"node_modules/", "vendor/", "dist/"} {
			if len(p) >= len(banned) && p[:len(banned)] == banned {
				t.Errorf("%s was discovered — the hardcoded skip list must sit above the skill-root rule", p)
			}
		}
	}
}

// A gitignored subtree inside a skill root stays gitignored. The new rule
// widens the extension gate, not the ignore policy.
func TestDiscover_GitignoreStillAppliesInsideSkillRoot(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"SKILL.md":           "---\nname: demo\n---\n",
		".gitignore":         "secret/\n",
		"secret/payload.py":  "import os\n",
		"scripts/payload.py": "import os\n",
	})
	got := discovered(t, dir)
	if _, ok := got["secret/payload.py"]; ok {
		t.Error("secret/payload.py is gitignored and must stay out of the default scan")
	}
	if _, ok := got["scripts/payload.py"]; !ok {
		t.Error("scripts/payload.py should be discovered inside the skill root")
	}
}

// .github/ and .vscode/ are walked for their specific instruction and MCP
// files, but a SKILL.md above them must not pull the rest of them into scope:
// a repository's CI workflows are not the skill's payload.
func TestDiscover_SkillRootDoesNotReachGithubOrVscode(t *testing.T) {
	got := discovered(t, writeTree(t, map[string]string{
		"SKILL.md":                 "---\nname: demo\n---\n",
		"scripts/payload.py":       "import os\n",
		".github/workflows/ci.yml": "on: [push]\n",
		".vscode/tasks.json":       "{}\n",
		".github/hook":             "#!/bin/sh\n",
	}))

	if root := got["scripts/payload.py"]; root != "." {
		t.Errorf("scripts/payload.py: SkillRoot = %q, want %q", root, ".")
	}
	for _, p := range []string{".github/workflows/ci.yml", ".vscode/tasks.json"} {
		root, ok := got[p]
		if !ok {
			t.Errorf("%s should still be DISCOVERED (walkable, .yml/.json are scannable)", p)
			continue
		}
		if root != "" {
			t.Errorf("%s: SkillRoot = %q, want \"\" — the skill-root arm must not reach it", p, root)
		}
	}
	if _, ok := got[".github/hook"]; ok {
		t.Error(".github/hook is extensionless and must not be discovered via the skill-root arm")
	}
}

// skill.yaml is the other spelling of a skill manifest — rules.IsSkillManifest
// has always accepted both — and a directory holding one is just as much a
// skill as a directory holding SKILL.md. Recognising only SKILL.md left a
// payload beside a skill.yaml out of scope while the manifest above it was
// read, which is the exact asymmetry the skill-root rule exists to remove.
// Worse than a blind spot: skill.yaml is itself an agent file, so the scan
// had an agent surface, NoAgentSurface never fired, and the tree graded a
// confident A. See ADR-0010.
func TestDiscover_SkillYAMLIsAlsoASkillRoot(t *testing.T) {
	got := discovered(t, writeTree(t, map[string]string{
		"skill.yaml":         "name: demo\nversion: 1.0.0\n",
		"scripts/payload.py": "import os\n",
	}))

	for _, p := range []string{"skill.yaml", "scripts/payload.py"} {
		root, ok := got[p]
		if !ok {
			t.Fatalf("%s was not discovered; got %v", p, got)
		}
		if root != "." {
			t.Errorf("%s: SkillRoot = %q, want %q", p, root, ".")
		}
	}
}

// Both spellings scope independently at their own depth, and a directory with
// neither stays out.
func TestDiscover_MixedManifestSpellingsScopeIndependently(t *testing.T) {
	got := discovered(t, writeTree(t, map[string]string{
		"CLAUDE.md":      "# repo\n",
		"a/SKILL.md":     "---\nname: a\n---\n",
		"a/scripts/a.py": "import os\n",
		"b/skill.yaml":   "name: b\n",
		"b/scripts/b.py": "import os\n",
		"c/notes.md":     "# not a skill\n",
		"c/scripts/c.py": "import os\n",
	}))

	for p, want := range map[string]string{
		"a/scripts/a.py": "a",
		"b/scripts/b.py": "b",
	} {
		root, ok := got[p]
		if !ok {
			t.Fatalf("%s was not discovered; got %v", p, got)
		}
		if root != want {
			t.Errorf("%s: SkillRoot = %q, want %q", p, root, want)
		}
	}
	if _, ok := got["c/scripts/c.py"]; ok {
		t.Error("c/scripts/c.py was discovered — c/ holds no manifest of either spelling")
	}
}
