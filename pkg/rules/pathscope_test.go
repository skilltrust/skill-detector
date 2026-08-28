package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/model"
)

func TestSkillRelativeDirDepth(t *testing.T) {
	tests := []struct {
		name string
		ctx  model.FileContext
		want int
	}{
		{"manifest at the scan root", model.FileContext{Path: "SKILL.md", SkillRoot: "."}, 0},
		{"nested one level", model.FileContext{Path: "scripts/run.sh", SkillRoot: "."}, 1},
		{"nested two levels", model.FileContext{Path: "a/b/run.sh", SkillRoot: "."}, 2},
		{"installed layout, manifest", model.FileContext{Path: ".claude/skills/x/SKILL.md", SkillRoot: ".claude/skills/x"}, 0},
		{"installed layout, nested", model.FileContext{Path: ".claude/skills/x/scripts/run.sh", SkillRoot: ".claude/skills/x"}, 1},
		{"no skill root known", model.FileContext{Path: ".claude/settings.json", SkillRoot: ""}, -1},
		{"path not under the root", model.FileContext{Path: "other/run.sh", SkillRoot: "skills/x"}, -1},

		// An embedder builds model.FileContext by hand; an uncanonical path
		// must not inflate the depth, because the depth is a climb budget.
		{"dot-slash prefix does not add a level", model.FileContext{Path: "./scripts/run.sh", SkillRoot: "."}, 1},
		{"doubled separator does not add a level", model.FileContext{Path: "a//b/run.sh", SkillRoot: "."}, 2},
		{"interior dot-dot resolves", model.FileContext{Path: "a/../b/run.sh", SkillRoot: "."}, 1},
		{"path above the root is not under it", model.FileContext{Path: "../run.sh", SkillRoot: "."}, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := skillRelativeDirDepth(tt.ctx); got != tt.want {
				t.Errorf("skillRelativeDirDepth(%+v) = %d, want %d", tt.ctx, got, tt.want)
			}
		})
	}
}

func TestRelativeRefStaysInSkill(t *testing.T) {
	nested := model.FileContext{Path: "scripts/run.sh", SkillRoot: "."}
	deep := model.FileContext{Path: "crates/alerter/Cargo.toml", SkillRoot: "."}
	root := model.FileContext{Path: "SKILL.md", SkillRoot: "."}
	noRoot := model.FileContext{Path: ".claude/settings.json", SkillRoot: ""}
	installed := model.FileContext{Path: ".claude/skills/x/scripts/run.sh", SkillRoot: ".claude/skills/x"}
	uncanonical := model.FileContext{Path: "./scripts/run.sh", SkillRoot: "."}
	doubledSep := model.FileContext{Path: "a//b/run.sh", SkillRoot: "."}

	tests := []struct {
		name string
		line string
		ctx  model.FileContext
		want bool
	}{
		// --- stays inside: the class this predicate exists to release ---
		{"sibling dir from a nested script", `open('../references/holdings.md')`, nested, true},
		{"workspace member from a nested manifest", `detector = { path = "../detector" }`, deep, true},
		{"dot-slash prefix is a no-op", `cat ./../data/x.txt`, deep, true},
		{"exactly cancels out to the root", `cat ../SKILL.md`, nested, true},
		{"trailing tilde is an ordinary backup name", `cat ../references/notes.md~`, nested, true},
		{"installed layout, sibling dir", `cat ../data/input.txt`, installed, true},

		// --- escapes: must stay flagged ---
		{"one level too many", `cat ../../etc/passwd`, nested, false},
		{"from the skill root any ../ escapes", `cat ../sibling/SKILL.md`, root, false},
		{"dips below the root then rejoins", `cat ../scripts/../../outside/payload.sh`, nested, false},
		{"long climb", `cat ../../../../../../outside`, deep, false},

		// --- unresolvable: must stay flagged, never guessed ---
		//
		// These four pin the BEHAVIOUR — the line stays flagged — and nothing
		// more. None of them proves unresolvableTokenChars does any work:
		// every character in that set is also outside reOrdinarySegment, so
		// the segment walk refuses these tokens on its own and deleting the
		// whole-token guard fails no test in this repository. See the comment
		// on the constant for why it is kept anyway.
		{"variable prefix", `cat $HOME/../../etc/passwd`, nested, false},
		{"brace-expanded prefix", `cat ${ROOT}/../../etc/passwd`, nested, false},
		// The pure percent-encoded form carries no literal `../` at all, so it
		// is refused earlier still, by the empty-match guard. SD-003 does not
		// match this line in the first place — before this branch or after it —
		// so this case claims no detection, only that nothing releases it.
		{"percent-encoded separators, nothing tokenised", `cat ..%2f..%2fetc/passwd`, nested, false},
		// A literal `../` plus a percent-encoded segment: refused by the
		// ordinary-segment charset, which is the check that actually decides
		// every line in this block.
		{"percent-encoded segment inside a real reference", `cat ../a%2fb/../../outside/x`, nested, false},
		{"no skill root is known", `cat ../data/x.txt`, noRoot, false},
		{"tilde is home expansion, not a directory", `cat ~/../../etc/passwd`, nested, false},
		{"tilde inside a command", `bash -c "cp ~/../etc/passwd ./x"`, nested, false},
		{"tilde-user form", `cat ~root/../../etc/passwd`, nested, false},

		// --- filter-bypass forms: must stay flagged (A4 is NOT shipped) ---
		{"dot-run bypass", `....//....//etc/passwd`, nested, false},
		{"interleaved dot bypass", `..././..././etc/passwd`, nested, false},

		// --- sigils must not be read as a path segment ---
		{"claude file-reference sigil", `@./../_shared/commands.md`, root, false},
		{"doubled sigil does not hide a tilde", `@@~/../etc/passwd`, nested, false},
		{"doubled sigil does not hide a climb", `@@../../outside/x`, nested, false},

		// --- one reference split across two matches: each half looks
		// in-package only because the walk is re-anchored at the file's own
		// depth halfway through the path, handing it the climb budget twice.
		// Every one of these escapes by exactly one level.
		{"quoted path with a space", `cat "../my data/../../outside/harvest.env"`, nested, false},
		{"glob star inside the path", `cat ../a*b/../../outside/harvest.env`, nested, false},
		{"glob class inside the path", `cat ../a[0]b/../../outside/harvest.env`, nested, false},
		{"comma inside the path", `cat ../a,b/../../outside/harvest.env`, nested, false},
		{"quoted redirection character inside the path", `cat "../a>b/../../outside/harvest.env"`, nested, false},
		{"unbalanced quote does not un-quote the space", `cat "../my data/../../outside/harvest.env`, nested, false},
		// The rest of the same class. Every character reRelativePathToken cuts
		// on is a legal POSIX filename character, so each of these is one real
		// path that the tokeniser sees as two. None of them involves a shell:
		// SD-003 reads SKILL.md, CLAUDE.md and docs, where `(`, `;`, `&` and a
		// space are ordinary prose and nothing word-splits them.
		{"parentheses in the path", `cat ../a(b)c/../../outside/x`, nested, false},
		{"semicolon in the path", `cat ../a;b/../../outside/x`, nested, false},
		{"ampersand in the path", `cat ../a&b/../../outside/x`, nested, false},
		{"pipe in the path", `cat ../a|b/../../outside/x`, nested, false},
		{"angle brackets in the path", `cat ../a<b>c/../../outside/x`, nested, false},
		{"unquoted space in the path", `cat ../a b/../../outside/x`, nested, false},
		{"tab in the path", "cat ../a\tb/../../outside/x", nested, false},
		{"markdown link, split reference", `[d](../a b/../../outside/x)`, nested, false},
		{"two refs, one ambiguous", `cat ../references/a.md ../a(b)c/../../outside/x`, nested, false},
		// The same escape spelled without a splitting character: it is the walk
		// that refuses this one, which is what makes the four above a test of
		// the tokenisation unit and not of the walk.
		{"same escape, nothing to split on", `cat "../mydata/../../outside/harvest.env"`, nested, false},
		// A glob beside an in-package reference is ambiguous — `*` is legal
		// inside a filename — so it stays flagged. Residual FP, on purpose.
		{"glob beside an in-package reference", `cat ../data/*.json`, nested, false},
		// Two in-package references on one line are equally ambiguous: the
		// bytes between them are all legal in a filename, so the line reads
		// just as well as one long reference. Refusing it is the price of
		// refusing the split-reference escape above, and it is the safe
		// direction — a false positive, never a missed escape. Residual FP,
		// on purpose; recorded in ADR-0011.
		{"two in-package references on one line", `ln -sf ../data d && ln -sf ../logs l`, nested, false},

		// --- defensive: nothing tokenised ---
		{"no token the tokeniser recognises", `..////`, nested, false},

		// --- uncanonical caller-built contexts must not buy a free climb ---
		{"dot-slash prefix does not fund a climb", `cat ../../outside/x`, uncanonical, false},
		{"doubled separator does not fund a climb", `cat ../../../outside/x`, doubledSep, false},
		{"dot-slash prefix still releases an in-package reference", `cat ../data/x.txt`, uncanonical, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := relativeRefStaysInSkill([]byte(tt.line), tt.ctx); got != tt.want {
				t.Errorf("relativeRefStaysInSkill(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}

// The predicate is a pure function of its FileContext: it must never consult
// the filesystem. The two contexts below are at the same depth and differ only
// in whether the file they name exists — the working directory is a temporary
// one in which exactly one of the two paths has been created — so an
// implementation that stat'd or opened the path could tell them apart and this
// test would catch it. (Purity is enforced structurally by the import list;
// this pins it against a future change that adds an os import.)
func TestRelativeRefStaysInSkillDoesNotTouchDisk(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scripts", "run.sh"), []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Chdir(dir)

	exists := model.FileContext{Path: "scripts/run.sh", SkillRoot: "."}
	missing := model.FileContext{Path: "absent/run.sh", SkillRoot: "."}
	if _, err := os.Stat(filepath.Join(dir, "absent", "run.sh")); !os.IsNotExist(err) {
		t.Fatalf("the missing path must not exist, got err=%v", err)
	}
	line := []byte(`cat ../data/x.txt`)
	if relativeRefStaysInSkill(line, exists) != relativeRefStaysInSkill(line, missing) {
		t.Error("result depends on whether the path exists on disk — the predicate is not pure")
	}
}
