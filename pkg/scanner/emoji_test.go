package scanner_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velzepooz/skill-detector/pkg/axes"
	"github.com/velzepooz/skill-detector/pkg/rules"
	"github.com/velzepooz/skill-detector/pkg/scanner"
)

func TestScanner_EmojiZWJ(t *testing.T) {
	const rainbow = "\U0001F3F3\uFE0F\u200D\U0001F308"
	for _, tc := range []struct {
		name, content string
		grade         axes.Grade
	}{
		{"issue 36", "Family: 👨‍👩‍👧 and flag " + rainbow + " are fine.", axes.GradeA},
		{"heart on fire", "\u2764\uFE0F\u200D\U0001F525", axes.GradeA},
		{"at cap", strings.Repeat(rainbow, 4), axes.GradeA},
		{"over cap", strings.Repeat(rainbow, 5), axes.GradeF},
		{"mixed cap", strings.Repeat(rainbow, 3) + "👨‍👩‍👧", axes.GradeF},
		{"letter before selector", "a\uFE0F\u200D\U0001F308", axes.GradeF},
		{"check mark before selector", "\u2713\uFE0F\u200D\U0001F308", axes.GradeF},
		{"missing left emoji", "\uFE0F\u200D\U0001F308", axes.GradeF},
		{"missing right emoji", "\U0001F3F3\uFE0F\u200D", axes.GradeF},
		{"letter after joiner", "\U0001F3F3\uFE0F\u200Dx", axes.GradeF},
		{"repeated selector", "\U0001F3F3\uFE0F\uFE0F\u200D\U0001F308", axes.GradeF},
		{"text selector", "\U0001F3F3\uFE0E\u200D\U0001F308", axes.GradeF},
		{"ZWSP payload", rainbow + "a\u200Bb", axes.GradeF},
		{"ZWNJ payload", rainbow + "a\u200Cb", axes.GradeF},
		{"ZWJ payload", rainbow + "a\u200Db", axes.GradeF},
		{"word joiner payload", rainbow + "a\u2060b", axes.GradeF},
		{"BOM payload", rainbow + "a\uFEFFb", axes.GradeF},
		{"tag payload", rainbow + "\U000E0061\U000E007F", axes.GradeF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			content := "---\nname: emoji\ndescription: d\n---\n" + tc.content + "\n"
			if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			s := scanner.New(rules.DefaultRegistry(), scanner.Options{})
			res := runScan(t, s, dir)
			if got := res.Axes[axes.Security].Grade; got != tc.grade {
				t.Fatalf("security = %s, want %s: %+v", got, tc.grade, res.Findings)
			}
			want := 0
			if tc.grade == axes.GradeF {
				want = 1
			}
			if len(res.Findings) != want {
				t.Fatalf("want %d findings, got %+v", want, res.Findings)
			}
			for _, f := range res.Findings {
				if f.RuleID != "SD-002" || f.Line != 5 {
					t.Fatalf("unexpected finding: %+v", f)
				}
				if tc.name == "over cap" || tc.name == "mixed cap" {
					const description = "5 invisible Unicode character(s) detected in prompt template"
					if f.Description != description {
						t.Fatalf("all five joiners must count above the cap: got %q", f.Description)
					}
				}
			}
		})
	}
}
