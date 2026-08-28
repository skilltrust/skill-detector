package rules

import (
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
		{"two tokens, both inside", `ln -sf ../data d && ln -sf ../logs l`, nested, true},
		{"exactly cancels out to the root", `cat ../SKILL.md`, nested, true},

		// --- escapes: must stay flagged ---
		{"one level too many", `cat ../../etc/passwd`, nested, false},
		{"from the skill root any ../ escapes", `cat ../sibling/SKILL.md`, root, false},
		{"dips below the root then rejoins", `cat ../scripts/../../outside/payload.sh`, nested, false},
		{"long climb", `cat ../../../../../../outside`, deep, false},

		// --- unresolvable: must stay flagged, never guessed ---
		{"variable prefix", `cat $HOME/../../etc/passwd`, nested, false},
		{"brace-expanded prefix", `cat ${ROOT}/../../etc/passwd`, nested, false},
		{"percent-encoded segment", `cat ..%2f..%2fetc/passwd`, nested, false},
		{"no skill root is known", `cat ../data/x.txt`, noRoot, false},

		// --- filter-bypass forms: must stay flagged (A4 is NOT shipped) ---
		{"dot-run bypass", `....//....//etc/passwd`, nested, false},
		{"interleaved dot bypass", `..././..././etc/passwd`, nested, false},

		// --- sigils must not be read as a path segment ---
		{"claude file-reference sigil", `@./../_shared/commands.md`, root, false},

		// --- defensive: nothing tokenised ---
		{"no token the tokeniser recognises", `..////`, nested, false},
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
// the filesystem, so a context naming a path that does not exist behaves
// exactly like one that does.
func TestRelativeRefStaysInSkillDoesNotTouchDisk(t *testing.T) {
	real := model.FileContext{Path: "scripts/run.sh", SkillRoot: "."}
	fake := model.FileContext{Path: "does/not/exist.sh", SkillRoot: "."}
	line := []byte(`cat ../data/x.txt`)
	if relativeRefStaysInSkill(line, real) != relativeRefStaysInSkill(line, fake) {
		t.Error("result depends on whether the path exists on disk — the predicate is not pure")
	}
}
